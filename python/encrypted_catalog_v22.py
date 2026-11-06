"""Bounded authenticated local SQLite backups and key rotation (F229).

Cryptography is AES-256-GCM via the actual system OpenSSL libcrypto C API.
The Python stdlib alone is not a cryptographic backend.  If libcrypto is
unavailable or a trust/permission check fails, the operation fails closed.

Only ordinary-table SQLite catalogs in a private local directory are supported;
no arbitrary triggers, virtual tables, plugins or attached databases.  A
consistent SQLite backup goes into RAM; only *encrypted* bytes are written to
the archive path.  Restore writes plaintext only to the explicitly requested
new destination database.  No claim of full-disk/SQLCipher protection, secure
erasure of old SSD blocks, or whole-machine secret isolation is made.
"""

import argparse
from contextlib import closing
import ctypes
import ctypes.util
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import sys
import tempfile
from urllib.parse import quote


MAGIC = b"RPH-AES256-GCM-SQLITE-v1\x00"
NONCE_BYTES = 12
TAG_BYTES = 16
KEY_BYTES = 32
MAX_DUMP_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = MAX_DUMP_BYTES + 256
EVP_CTRL_GCM_GET_TAG = 0x10
EVP_CTRL_GCM_SET_TAG = 0x11


def _platform_adapter():
    embedded = globals().get("_RPH_PLATFORM_PRIVACY")
    if embedded is not None:
        return embedded
    sibling = Path(__file__).resolve().parent / "platform_privacy_v028.py"
    spec = importlib.util.spec_from_file_location("rph_crypto_platform_privacy", sibling)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


platform_privacy = _platform_adapter()


def _resolve_libcrypto():
    """Windows loads only interpreter-bundled crypto, never PATH or CWD."""
    if os.name != "nt":
        return ctypes.util.find_library("crypto")
    base = Path(sys.base_prefix)
    if not base.is_absolute():
        return None
    folder = base / "DLLs"
    for name in ("libcrypto-3.dll", "libcrypto-3-x64.dll", "libcrypto-1_1-x64.dll"):
        path = folder / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISREG(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400
                and path.resolve().parent == folder.resolve()):
            return str(path.resolve())
    return None


def _libcrypto():
    """Load fixed OpenSSL EVP symbols and verify real AES-256-GCM support."""
    name = _resolve_libcrypto()
    if not name:
        raise RuntimeError("cryptographic_backend_unavailable")
    try:
        lib = (ctypes.CDLL(name, winmode=0x00000100 | 0x00000800)
               if os.name == "nt" else ctypes.CDLL(name))
        specs = {
            "OpenSSL_version": (ctypes.c_char_p, [ctypes.c_int]),
            "EVP_CIPHER_CTX_new": (ctypes.c_void_p, []),
            "EVP_CIPHER_CTX_free": (None, [ctypes.c_void_p]),
            "EVP_aes_256_gcm": (ctypes.c_void_p, []),
            "EVP_EncryptInit_ex": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p,
                                                  ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]),
            "EVP_EncryptUpdate": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p,
                                                 ctypes.POINTER(ctypes.c_int), ctypes.c_void_p,
                                                 ctypes.c_int]),
            "EVP_EncryptFinal_ex": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p,
                                                   ctypes.POINTER(ctypes.c_int)]),
            "EVP_DecryptInit_ex": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p,
                                                  ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]),
            "EVP_DecryptUpdate": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p,
                                                 ctypes.POINTER(ctypes.c_int), ctypes.c_void_p,
                                                 ctypes.c_int]),
            "EVP_DecryptFinal_ex": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p,
                                                   ctypes.POINTER(ctypes.c_int)]),
            "EVP_CIPHER_CTX_ctrl": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_int,
                                                   ctypes.c_int, ctypes.c_void_p]),
        }
        for symbol, (result, arguments) in specs.items():
            method = getattr(lib, symbol)
            method.restype = result
            method.argtypes = arguments
        if not lib.EVP_aes_256_gcm():
            raise ValueError("cipher_unavailable")
    except (AttributeError, OSError, ValueError) as problem:
        raise RuntimeError("cryptographic_backend_unavailable") from problem
    return lib


def backend_capabilities():
    """Report backend availability without claiming OS-wide encryption."""
    try:
        lib = _libcrypto()
        available = True
        library_name = Path(str(lib._name)).name
        version = lib.OpenSSL_version(0).decode("ascii", errors="replace")[:160]
    except RuntimeError:
        available = False
        library_name = version = None
    return {"status": "OPENSSL_AES_256_GCM_AVAILABLE" if available
            else "NOT_SUPPORTED_MISSING_CRYPTO_BACKEND",
            "authenticated_encryption": available,
            "algorithm": "AES-256-GCM" if available else None,
            "backend_library_name": library_name,
            "backend_version": version,
            "backend_scope": "explicit interpreter OpenSSL EVP runtime compatibility only",
            "backend_publisher_authentication_verified": False,
            "production_sqlcipher": False,
            "backup_plaintext_tempfile_created": False,
            "arbitrary_sqlite_schema_supported": False}


def _ctx(lib):
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("cryptographic_context_unavailable")
    return ctx


def encrypt_bytes(plaintext, key, nonce=None):
    """Authenticated envelope with a fresh random nonce; never reusable by API."""
    if type(plaintext) is not bytes or len(plaintext) > MAX_DUMP_BYTES:
        raise ValueError("plaintext_invalid_or_oversized")
    if type(key) is not bytes or len(key) != KEY_BYTES:
        raise ValueError("key_must_be_exactly_32_bytes")
    if nonce is not None:
        raise ValueError("caller_supplied_gcm_nonces_forbidden")
    iv = secrets.token_bytes(NONCE_BYTES)
    header = MAGIC + iv
    lib = _libcrypto()
    ctx = _ctx(lib)
    try:
        key_buf = ctypes.create_string_buffer(key)
        nonce_buf = ctypes.create_string_buffer(iv)
        aad_buf = ctypes.create_string_buffer(header)
        input_buf = ctypes.create_string_buffer(plaintext)
        output = ctypes.create_string_buffer(len(plaintext) + 16)
        count = ctypes.c_int()
        final = ctypes.c_int()
        tag = ctypes.create_string_buffer(TAG_BYTES)
        if lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, key_buf, nonce_buf) != 1:
            raise RuntimeError("encryption_initialization_failed")
        if lib.EVP_EncryptUpdate(ctx, None, ctypes.byref(count), aad_buf, len(header)) != 1:
            raise RuntimeError("encryption_aad_failed")
        if lib.EVP_EncryptUpdate(ctx, output, ctypes.byref(count), input_buf, len(plaintext)) != 1:
            raise RuntimeError("encryption_failed")
        used = count.value
        destination = ctypes.c_void_p(ctypes.addressof(output) + used)
        if lib.EVP_EncryptFinal_ex(ctx, destination, ctypes.byref(final)) != 1:
            raise RuntimeError("encryption_final_failed")
        if lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_BYTES, tag) != 1:
            raise RuntimeError("authentication_tag_unavailable")
        return header + output.raw[:used + final.value] + tag.raw[:TAG_BYTES]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def decrypt_bytes(envelope, key):
    """AEAD verifies the header, nonce, ciphertext and tag before returning data."""
    if type(key) is not bytes or len(key) != KEY_BYTES:
        raise ValueError("key_must_be_exactly_32_bytes")
    header_length = len(MAGIC) + NONCE_BYTES
    if (type(envelope) is not bytes or len(envelope) < header_length + TAG_BYTES
            or len(envelope) > MAX_ARCHIVE_BYTES or not envelope.startswith(MAGIC)):
        raise ValueError("encrypted_envelope_invalid")
    header = envelope[:header_length]
    nonce = header[len(MAGIC):]
    encrypted = envelope[header_length:-TAG_BYTES]
    tag_data = envelope[-TAG_BYTES:]
    lib = _libcrypto()
    ctx = _ctx(lib)
    try:
        key_buf = ctypes.create_string_buffer(key)
        nonce_buf = ctypes.create_string_buffer(nonce)
        aad_buf = ctypes.create_string_buffer(header)
        input_buf = ctypes.create_string_buffer(encrypted)
        output = ctypes.create_string_buffer(len(encrypted) + 16)
        count = ctypes.c_int()
        final = ctypes.c_int()
        tag = ctypes.create_string_buffer(tag_data)
        if lib.EVP_DecryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, key_buf, nonce_buf) != 1:
            raise RuntimeError("decryption_initialization_failed")
        if lib.EVP_DecryptUpdate(ctx, None, ctypes.byref(count), aad_buf, len(header)) != 1:
            raise RuntimeError("decryption_aad_failed")
        if lib.EVP_DecryptUpdate(ctx, output, ctypes.byref(count), input_buf, len(encrypted)) != 1:
            raise RuntimeError("decryption_failed")
        used = count.value
        if lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_BYTES, tag) != 1:
            raise RuntimeError("authentication_tag_unavailable")
        destination = ctypes.c_void_p(ctypes.addressof(output) + used)
        if lib.EVP_DecryptFinal_ex(ctx, destination, ctypes.byref(final)) != 1:
            raise ValueError("authentication_failed")
        return output.raw[:used + final.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def _private_directory(path):
    folder = Path(path)
    info = folder.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("private_owner_only_directory_required")
    if os.name == "nt":
        platform_privacy.private_directory(folder, "private_owner_only_directory_required")
    elif info.st_mode & 0o077 or info.st_uid != os.getuid():
        raise ValueError("private_owner_only_directory_required")
    return folder


def _regular_private(path, limit, label):
    path = Path(path)
    _private_directory(path.parent)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_size > limit or (os.name != "nt" and
            (before.st_mode & 0o077 or before.st_uid != os.getuid()))):
        raise ValueError("unsafe_private_" + label)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(str(path), flags)
    with os.fdopen(fd, "rb") as stream:
        after = os.fstat(stream.fileno())
        if os.name == "nt":
            platform_privacy.private_descriptor(stream.fileno(), "unsafe_private_" + label)
        if not stat.S_ISREG(after.st_mode) or after.st_nlink != 1 or after.st_size > limit:
            raise ValueError("unsafe_private_" + label)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("file_changed_during_open")
        data = stream.read(limit + 1)
        last = os.fstat(stream.fileno())
        if (last.st_ino, last.st_size, last.st_mtime_ns) != (
                before.st_ino, before.st_size, before.st_mtime_ns):
            raise ValueError("file_changed_during_read")
    if len(data) > limit:
        raise ValueError("file_exceeds_quota")
    return data, before


def create_key(path):
    """Create 256-bit operator key only in an owner-private existing folder."""
    path = Path(path)
    _private_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "wb") as output:
        if os.name == "nt":
            platform_privacy.private_descriptor(output.fileno(), "unsafe_private_key")
        output.write(secrets.token_bytes(KEY_BYTES))
        output.flush()
        os.fsync(output.fileno())
    return {"status": "PRIVATE_KEY_CREATED", "key_bytes": KEY_BYTES}


def _read_key(path):
    key, _ = _regular_private(path, KEY_BYTES, "key")
    if len(key) != KEY_BYTES:
        raise ValueError("key_must_be_exactly_32_bytes")
    return key


def _new_private_file(path, payload):
    path = Path(path)
    _private_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            if os.name == "nt":
                platform_privacy.private_descriptor(output.fileno(), "unsafe_private_created_archive")
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink()
        raise


def _bounded_dump(source):
    """Consistent SQLite backup in RAM, then bounded SQL dump in RAM."""
    path = Path(source)
    _, before = _regular_private(path, MAX_DUMP_BYTES, "source_database")
    uri = "file:{}?mode=ro".format(quote(str(path.resolve()), safe="/"))
    with closing(sqlite3.connect(uri, uri=True)) as original:
        with closing(sqlite3.connect(":memory:")) as snapshot:
            original.backup(snapshot)
            if snapshot.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("source_database_integrity_failed")
            schema = snapshot.execute("SELECT type,sql FROM sqlite_master ")
            rows = schema.fetchall()
            if len(rows) > 128 or any(
                    kind not in ("table", "index") or
                    (ddl is not None and ("VIRTUAL TABLE" in ddl.upper()
                                          or "LOAD_EXTENSION" in ddl.upper()))
                    for kind, ddl in rows):
                raise ValueError("unsupported_or_unsafe_sqlite_schema")
            fragments = []
            total = 0
            for statement in snapshot.iterdump():
                raw = (statement + "\n").encode("utf-8")
                total += len(raw)
                if total > MAX_DUMP_BYTES:
                    raise ValueError("source_database_dump_quota")
                fragments.append(raw)
    after = path.lstat()
    if (before.st_ino, before.st_dev) != (after.st_ino, after.st_dev):
        raise ValueError("source_database_replaced")
    return b"".join(fragments)


def backup_database(database, encrypted_archive, key_file):
    """Create an encrypted, exclusive archive without a plaintext scratch file."""
    key = _read_key(key_file)
    plain = _bounded_dump(database)
    envelope = encrypt_bytes(plain, key)
    _new_private_file(encrypted_archive, envelope)
    return {"status": "AUTHENTICATED_ENCRYPTED_SQLITE_BACKUP",
            "archive_sha256": hashlib.sha256(envelope).hexdigest(),
            "plaintext_temporary_files_created": 0,
            "archive_contains_sqlite_plaintext": False,
            "source_database_mutated": False,
            "authenticated_encryption": "AES-256-GCM"}


def _restore_to_memory(envelope, key):
    plain = decrypt_bytes(envelope, key)
    try:
        script = plain.decode("utf-8")
    except UnicodeDecodeError as problem:
        raise ValueError("decrypted_sqlite_dump_invalid") from problem
    memory = sqlite3.connect(":memory:")
    try:
        # Restrict schema effects even after authentication. No attaches,
        # virtual tables, triggers, views, arbitrary loadable functions.
        denied = {sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH,
                  sqlite3.SQLITE_CREATE_TRIGGER, sqlite3.SQLITE_CREATE_VIEW,
                  sqlite3.SQLITE_CREATE_VTABLE, sqlite3.SQLITE_DROP_TRIGGER,
                  sqlite3.SQLITE_DROP_VIEW, sqlite3.SQLITE_DROP_VTABLE}

        def authorizer(action, first, second, database, trigger):
            if action in denied or (action == sqlite3.SQLITE_FUNCTION
                                     and str(second or first).lower() == "load_extension"):
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        memory.set_authorizer(authorizer)
        memory.executescript(script)
        # CPython 3.9/3.10's sqlite3.set_authorizer(None) can leave an
        # always-deny callback installed.  Install an explicit allow-only
        # callback after the untrusted, authenticated SQL script is done.
        memory.set_authorizer(lambda *_ignored: sqlite3.SQLITE_OK)
        if memory.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("decrypted_database_integrity_failed")
        return memory
    except BaseException:
        memory.close()
        raise


def restore_database(encrypted_archive, destination_database, key_file):
    """Decrypt in RAM; create only the caller's explicit new plaintext target."""
    key = _read_key(key_file)
    envelope, _ = _regular_private(encrypted_archive, MAX_ARCHIVE_BYTES, "encrypted_archive")
    memory = _restore_to_memory(envelope, key)
    destination = Path(destination_database)
    _private_directory(destination.parent)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(destination), flags, 0o600)
    except BaseException:
        memory.close()
        raise
    try:
        if os.name == "nt":
            platform_privacy.private_descriptor(fd, "unsafe_private_created_restore")
    finally:
        os.close(fd)
    try:
        with closing(sqlite3.connect(str(destination))) as written:
            memory.backup(written)
            if written.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("restored_database_integrity_failed")
    except BaseException:
        destination.unlink()
        raise
    finally:
        memory.close()
    return {"status": "AUTHENTICATED_SQLITE_RESTORE",
            "plaintext_temporary_files_created": 0,
            "explicit_plaintext_target_created": True}


def rotate_key(encrypted_archive, old_key_file, new_key_file):
    """Atomically replace live ciphertext with a new independently nonced key."""
    archive = Path(encrypted_archive)
    old_key = _read_key(old_key_file)
    new_key = _read_key(new_key_file)
    if old_key == new_key:
        raise ValueError("key_rotation_requires_distinct_key")
    envelope, before = _regular_private(archive, MAX_ARCHIVE_BYTES, "encrypted_archive")
    original = decrypt_bytes(envelope, old_key)
    updated = encrypt_bytes(original, new_key)
    temporary = archive.with_name(".{}.{}.rotation".format(archive.name, secrets.token_hex(8)))
    _new_private_file(temporary, updated)
    try:
        current = archive.lstat()
        if (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) != (
                current.st_ino, current.st_dev, current.st_size, current.st_mtime_ns):
            raise ValueError("archive_changed_before_atomic_swap")
        platform_privacy.replace_file(temporary, archive)
        durability = platform_privacy.sync_directory_scope(archive.parent)
    finally:
        if temporary.exists():
            temporary.unlink()
    return {"status": "AUTHENTICATED_KEY_ROTATION_CURRENT_ARCHIVE",
            "new_archive_sha256": hashlib.sha256(updated).hexdigest(),
            "old_key_fails_on_current_archive": True,
            "durability_scope": durability,
            "historical_deleted_blocks_cryptographically_erased": False}


def trusted_selftest():
    """Real local AES-GCM/SQLite lifecycle on a fixed temporary safe fixture."""
    if not backend_capabilities()["authenticated_encryption"]:
        return {"status": "NOT_SUPPORTED_MISSING_CRYPTO_BACKEND"}
    with tempfile.TemporaryDirectory(prefix="rph-v22-db-crypto-") as folder:
        base = Path(folder)
        database = base / "source.sqlite"
        old_key = base / "old.key"
        new_key = base / "new.key"
        archive = base / "backup.aes"
        restored = base / "restored.sqlite"
        with closing(sqlite3.connect(str(database))) as db:
            db.execute("CREATE TABLE facts(id INTEGER PRIMARY KEY, value TEXT)")
            db.execute("INSERT INTO facts VALUES (1, 'trusted-fixture')")
            db.commit()
        database.chmod(0o600)
        create_key(old_key)
        create_key(new_key)
        backup = backup_database(database, archive, old_key)
        rotated = rotate_key(archive, old_key, new_key)
        restore = restore_database(archive, restored, new_key)
        with closing(sqlite3.connect(str(restored))) as db:
            recovered = db.execute("SELECT value FROM facts WHERE id=1").fetchone()[0]
        if recovered != "trusted-fixture":
            raise ValueError("trusted_encrypted_database_roundtrip_failed")
        return {"status": "TRUSTED_LOCAL_AES256_GCM_ROTATION_AND_RESTORE_PASS",
                "real_sqlite_rows_restored": 1,
                "real_backend": "OpenSSL EVP AES-256-GCM",
                "archive_sha256_changes_on_rotation": backup["archive_sha256"] != rotated[
                    "new_archive_sha256"],
                "plaintext_temporary_files_created": restore[
                    "plaintext_temporary_files_created"],
                "unknown_project_code_executed": False,
                "whole_disk_sqlcipher_attested": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "trusted-selftest"),
                        default="capabilities")
    args = parser.parse_args(argv)
    try:
        result = (trusted_selftest() if args.mode == "trusted-selftest"
                  else backend_capabilities())
    except (OSError, ValueError, RuntimeError, sqlite3.Error):
        result = {"status": "NO_PASS_ENCRYPTED_CATALOG_PROBE_FAILED",
                  "unknown_project_code_executed": False}
        print(json.dumps(result, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") != "NOT_SUPPORTED_MISSING_CRYPTO_BACKEND" else 2


if __name__ == "__main__":
    raise SystemExit(main())
