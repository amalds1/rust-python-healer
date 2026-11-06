"""Actual authenticated SQLite backup/restore/rotation, negative fixtures."""

from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import windows_privacy_fixtures as privacy_fixtures
SCRIPT = ROOT / "python" / "encrypted_catalog_v22.py"
spec = importlib.util.spec_from_file_location("encrypted_catalog_v22", SCRIPT)
crypto = importlib.util.module_from_spec(spec)
spec.loader.exec_module(crypto)


class AuthenticatedCatalogTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="rph-v22-crypto-")
        self.addCleanup(self.folder.cleanup)
        self.base = Path(self.folder.name)
        if os.name == "nt":
            privacy_fixtures.set_private_acl(self.base)
        self.source = self.base / "source.sqlite"
        self.archive = self.base / "backup.aes"
        self.restored = self.base / "restored.sqlite"
        self.old_key = self.base / "old.key"
        self.new_key = self.base / "new.key"
        with closing(sqlite3.connect(str(self.source))) as db:
            db.execute("CREATE TABLE knowledge(k TEXT PRIMARY KEY, v TEXT)")
            db.execute("INSERT INTO knowledge VALUES (?,?)",
                       ("version", "private-fixture-3.9-to-3.15"))
            db.commit()
        self.source.chmod(0o600)
        crypto.create_key(self.old_key)
        crypto.create_key(self.new_key)

    def backup(self):
        return crypto.backup_database(self.source, self.archive, self.old_key)

    def test_backend_is_actual_openssl_aes_gcm_not_homegrown_cipher(self):
        report = crypto.backend_capabilities()
        self.assertEqual(report["status"], "OPENSSL_AES_256_GCM_AVAILABLE")
        self.assertTrue(report["authenticated_encryption"])
        self.assertFalse(report["production_sqlcipher"])

    def test_missing_crypto_backend_fails_closed_without_weak_fallback(self):
        with mock.patch.object(crypto, "_resolve_libcrypto", return_value=None):
            self.assertEqual(crypto.backend_capabilities()["status"],
                             "NOT_SUPPORTED_MISSING_CRYPTO_BACKEND")
            with self.assertRaisesRegex(RuntimeError, "cryptographic_backend_unavailable"):
                crypto.encrypt_bytes(b"private", self.old_key.read_bytes())

    def test_key_generation_creates_unique_secret_32_byte_keys(self):
        a = self.old_key.read_bytes()
        b = self.new_key.read_bytes()
        self.assertEqual(len(a), 32)
        self.assertEqual(len(b), 32)
        self.assertNotEqual(a, b)
        if os.name == "nt":
            privacy_fixtures.privacy.assert_private_file(self.old_key)
        else:
            self.assertEqual(self.old_key.stat().st_mode & 0o777, 0o600)

    def test_creating_existing_key_is_refused_without_overwrite(self):
        before = self.old_key.read_bytes()
        with self.assertRaises(FileExistsError):
            crypto.create_key(self.old_key)
        self.assertEqual(before, self.old_key.read_bytes())

    def test_real_aes_gcm_raw_bytes_roundtrip(self):
        plain = b"valuable-secret" * 10
        key = self.old_key.read_bytes()
        encrypted = crypto.encrypt_bytes(plain, key)
        self.assertEqual(crypto.decrypt_bytes(encrypted, key), plain)

    def test_random_nonce_changes_same_plaintext(self):
        key = self.old_key.read_bytes()
        first = crypto.encrypt_bytes(b"identical", key)
        second = crypto.encrypt_bytes(b"identical", key)
        self.assertNotEqual(first, second)
        self.assertNotEqual(first[len(crypto.MAGIC):len(crypto.MAGIC)+12],
                            second[len(crypto.MAGIC):len(crypto.MAGIC)+12])

    def test_raw_ciphertext_does_not_embed_secret(self):
        secret = b"extremely-private-words-long-string"
        encrypted = crypto.encrypt_bytes(secret, self.old_key.read_bytes())
        self.assertNotIn(secret, encrypted)
        self.assertTrue(encrypted.startswith(crypto.MAGIC))

    def test_caller_supplied_nonce_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "nonce"):
            crypto.encrypt_bytes(b"v", self.old_key.read_bytes(), nonce=b"x" * 12)

    def test_wrong_length_secret_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "32_bytes"):
            crypto.encrypt_bytes(b"v", b"k" * 31)
        with self.assertRaisesRegex(ValueError, "32_bytes"):
            crypto.decrypt_bytes(b"v", b"k" * 33)

    def test_raw_wrong_key_rejected_with_authentication_error(self):
        sealed = crypto.encrypt_bytes(b"secret", self.old_key.read_bytes())
        with self.assertRaisesRegex(ValueError, "authentication_failed"):
            crypto.decrypt_bytes(sealed, self.new_key.read_bytes())

    def test_raw_header_tampering_fails_closed(self):
        sealed = bytearray(crypto.encrypt_bytes(b"secret", self.old_key.read_bytes()))
        sealed[0] ^= 1
        with self.assertRaisesRegex(ValueError, "encrypted_envelope_invalid"):
            crypto.decrypt_bytes(bytes(sealed), self.old_key.read_bytes())

    def test_raw_nonce_tampering_fails_tag_validation(self):
        sealed = bytearray(crypto.encrypt_bytes(b"secret", self.old_key.read_bytes()))
        sealed[len(crypto.MAGIC)] ^= 1
        with self.assertRaisesRegex(ValueError, "authentication_failed"):
            crypto.decrypt_bytes(bytes(sealed), self.old_key.read_bytes())

    def test_raw_ciphertext_tampering_fails_tag_validation(self):
        sealed = bytearray(crypto.encrypt_bytes(b"secret", self.old_key.read_bytes()))
        sealed[len(crypto.MAGIC) + 12] ^= 1
        with self.assertRaisesRegex(ValueError, "authentication_failed"):
            crypto.decrypt_bytes(bytes(sealed), self.old_key.read_bytes())

    def test_raw_tag_tampering_fails_tag_validation(self):
        sealed = bytearray(crypto.encrypt_bytes(b"secret", self.old_key.read_bytes()))
        sealed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "authentication_failed"):
            crypto.decrypt_bytes(bytes(sealed), self.old_key.read_bytes())

    def test_truncated_envelope_is_rejected(self):
        sealed = crypto.encrypt_bytes(b"secret", self.old_key.read_bytes())
        with self.assertRaises(ValueError):
            crypto.decrypt_bytes(sealed[:15], self.old_key.read_bytes())

    def test_sqlite_backup_real_file_and_sha(self):
        report = self.backup()
        self.assertEqual(report["status"], "AUTHENTICATED_ENCRYPTED_SQLITE_BACKUP")
        self.assertEqual(report["archive_sha256"],
                         hashlib.sha256(self.archive.read_bytes()).hexdigest())
        if os.name == "nt":
            privacy_fixtures.privacy.assert_private_file(self.archive)
        else:
            self.assertEqual(self.archive.stat().st_mode & 0o777, 0o600)

    def test_backup_never_writes_plaintext_dump(self):
        self.backup()
        self.assertNotIn(b"private-fixture", self.archive.read_bytes())
        names = {item.name for item in self.base.iterdir()}
        self.assertEqual(names, {"source.sqlite", "backup.aes", "old.key", "new.key"})

    def test_source_db_is_not_modified_by_backup(self):
        before = hashlib.sha256(self.source.read_bytes()).hexdigest()
        report = self.backup()
        self.assertFalse(report["source_database_mutated"])
        self.assertEqual(before, hashlib.sha256(self.source.read_bytes()).hexdigest())

    def test_real_sqlite_restore_preserves_row_and_schema(self):
        self.backup()
        report = crypto.restore_database(self.archive, self.restored, self.old_key)
        self.assertEqual(report["status"], "AUTHENTICATED_SQLITE_RESTORE")
        with closing(sqlite3.connect(str(self.restored))) as db:
            self.assertEqual(db.execute("SELECT v FROM knowledge WHERE k='version'").fetchone()[0],
                             "private-fixture-3.9-to-3.15")
        if os.name == "nt":
            privacy_fixtures.privacy.assert_private_file(self.restored)
        else:
            self.assertEqual(self.restored.stat().st_mode & 0o777, 0o600)

    def test_wrong_key_never_creates_restored_plaintext_file(self):
        self.backup()
        with self.assertRaisesRegex(ValueError, "authentication_failed"):
            crypto.restore_database(self.archive, self.restored, self.new_key)
        self.assertFalse(self.restored.exists())

    def test_corrupted_encrypted_archive_rejected_before_destination(self):
        self.backup()
        mutated = bytearray(self.archive.read_bytes())
        mutated[-1] ^= 2
        self.archive.write_bytes(bytes(mutated))
        with self.assertRaisesRegex(ValueError, "authentication_failed"):
            crypto.restore_database(self.archive, self.restored, self.old_key)
        self.assertFalse(self.restored.exists())

    def test_restore_never_overwrites_existing_plaintext_database(self):
        self.backup()
        self.restored.write_text("existing-private-application-content", encoding="utf-8")
        self.restored.chmod(0o600)
        with self.assertRaises(FileExistsError):
            crypto.restore_database(self.archive, self.restored, self.old_key)
        self.assertEqual(self.restored.read_text(encoding="utf-8"),
                         "existing-private-application-content")

    def test_real_key_rotation_invalidates_old_key_on_current_file(self):
        self.backup()
        original = self.archive.read_bytes()
        report = crypto.rotate_key(self.archive, self.old_key, self.new_key)
        self.assertEqual(report["status"], "AUTHENTICATED_KEY_ROTATION_CURRENT_ARCHIVE")
        self.assertNotEqual(self.archive.read_bytes(), original)
        with self.assertRaisesRegex(ValueError, "authentication_failed"):
            crypto.restore_database(self.archive, self.restored, self.old_key)
        self.assertFalse(self.restored.exists())
        crypto.restore_database(self.archive, self.restored, self.new_key)
        with closing(sqlite3.connect(str(self.restored))) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM knowledge").fetchone()[0], 1)

    def test_key_rotation_wrong_old_key_does_not_modify_current(self):
        self.backup()
        before = self.archive.read_bytes()
        with self.assertRaisesRegex(ValueError, "authentication_failed"):
            crypto.rotate_key(self.archive, self.new_key, self.old_key)
        self.assertEqual(before, self.archive.read_bytes())

    def test_key_rotation_rejects_same_key_without_touch(self):
        self.backup()
        before = self.archive.read_bytes()
        with self.assertRaisesRegex(ValueError, "distinct_key"):
            crypto.rotate_key(self.archive, self.old_key, self.old_key)
        self.assertEqual(before, self.archive.read_bytes())

    def test_atomic_swap_failure_keeps_old_authenticated_archive(self):
        self.backup()
        original = self.archive.read_bytes()
        with mock.patch.object(crypto.platform_privacy, "replace_file", side_effect=OSError("fixture swap failure")):
            with self.assertRaisesRegex(OSError, "fixture swap failure"):
                crypto.rotate_key(self.archive, self.old_key, self.new_key)
        self.assertEqual(original, self.archive.read_bytes())
        self.assertFalse(any(p.name.endswith(".rotation") for p in self.base.iterdir()))

    def test_windows_backend_resolver_uses_only_absolute_interpreter_dll_directory(self):
        if os.name == "nt":
            with mock.patch.object(crypto.ctypes.util, "find_library", side_effect=AssertionError("PATH lookup forbidden")):
                resolved = Path(crypto._resolve_libcrypto())
            self.assertTrue(resolved.is_absolute())
            self.assertEqual(resolved.parent, (Path(sys.base_prefix) / "DLLs").resolve())
            self.assertIn(resolved.name, ("libcrypto-3.dll", "libcrypto-3-x64.dll", "libcrypto-1_1-x64.dll"))

    def test_windows_missing_interpreter_crypto_does_not_search_other_locations(self):
        if os.name == "nt":
            folder = self.base / "empty-python-prefix"; folder.mkdir()
            with mock.patch.object(crypto.sys, "base_prefix", str(folder)), \
                    mock.patch.object(crypto.ctypes.util, "find_library", side_effect=AssertionError("fallback forbidden")):
                self.assertIsNone(crypto._resolve_libcrypto())
                self.assertFalse(crypto.backend_capabilities()["authenticated_encryption"])

    def test_selected_backend_identity_is_explicit_without_publisher_approval(self):
        report = crypto.backend_capabilities()
        self.assertTrue(report["backend_library_name"])
        self.assertIn("OpenSSL", report["backend_version"])
        self.assertFalse(report["backend_publisher_authentication_verified"])

    def test_public_keyfile_is_rejected(self):
        if os.name == "nt":
            privacy_fixtures.set_public_read_acl(self.old_key)
        else:
            self.old_key.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "unsafe_private_key"):
            self.backup()
        self.assertFalse(self.archive.exists())

    def test_keyfile_symlink_is_rejected(self):
        self.old_key.unlink()
        self.old_key.symlink_to(self.new_key)
        with self.assertRaises((ValueError, OSError)):
            self.backup()

    def test_keyfile_hardlink_is_rejected(self):
        os.link(self.old_key, self.base / "copy-key")
        with self.assertRaisesRegex(ValueError, "unsafe_private_key"):
            self.backup()

    def test_archive_symlink_is_not_followed_on_restore(self):
        self.backup()
        self.archive.unlink()
        self.archive.symlink_to(self.old_key)
        with self.assertRaises((OSError, ValueError)):
            crypto.restore_database(self.archive, self.restored, self.old_key)
        self.assertFalse(self.restored.exists())

    def test_archive_hardlink_is_rejected_on_rotation(self):
        self.backup()
        os.link(self.archive, self.base / "other-link")
        with self.assertRaisesRegex(ValueError, "unsafe_private_encrypted_archive"):
            crypto.rotate_key(self.archive, self.old_key, self.new_key)

    def test_source_symlink_is_not_followed(self):
        source = self.base / "original.sqlite"
        self.source.rename(source)
        self.source.symlink_to(source)
        with self.assertRaises((OSError, ValueError)):
            self.backup()
        self.assertFalse(self.archive.exists())

    def test_source_hardlink_is_not_read(self):
        os.link(self.source, self.base / "source-clone.sqlite")
        with self.assertRaisesRegex(ValueError, "unsafe_private_source_database"):
            self.backup()

    def test_public_directory_fails_closed(self):
        if os.name == "nt":
            privacy_fixtures.set_public_read_acl(self.base)
        else:
            self.base.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private_owner_only_directory"):
            self.backup()

    def test_unsafe_trigger_schema_rejected_before_backup(self):
        with closing(sqlite3.connect(str(self.source))) as db:
            db.execute("CREATE TRIGGER newer AFTER INSERT ON knowledge BEGIN DELETE FROM knowledge; END")
            db.commit()
        with self.assertRaisesRegex(ValueError, "unsupported_or_unsafe_sqlite_schema"):
            self.backup()

    def test_authenticated_but_disallowed_schema_restore_rejected(self):
        dump = (b"CREATE TABLE t(x);\n"
                b"CREATE TRIGGER unsafe AFTER INSERT ON t BEGIN DELETE FROM t; END;\n")
        self.archive.write_bytes(crypto.encrypt_bytes(dump, self.old_key.read_bytes()))
        self.archive.chmod(0o600)
        with self.assertRaises(sqlite3.DatabaseError):
            crypto.restore_database(self.archive, self.restored, self.old_key)
        self.assertFalse(self.restored.exists())

    def test_oversize_source_is_rejected_before_parse(self):
        with self.source.open("r+b") as stream:
            stream.truncate(crypto.MAX_DUMP_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "unsafe_private_source_database"):
            self.backup()

    def test_archive_rejects_oversize_input_without_plaintext(self):
        self.archive.touch(mode=0o600)
        with self.archive.open("r+b") as stream:
            stream.truncate(crypto.MAX_ARCHIVE_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "unsafe_private_encrypted_archive"):
            crypto.restore_database(self.archive, self.restored, self.old_key)

    def test_trusted_cli_selftest_runs_actual_sqlite_and_crypto(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "trusted-selftest"], capture_output=True,
                             text=True, timeout=8, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        result = json.loads(run.stdout)
        self.assertEqual(result["status"],
                         "TRUSTED_LOCAL_AES256_GCM_ROTATION_AND_RESTORE_PASS")
        self.assertEqual(result["real_sqlite_rows_restored"], 1)
        self.assertFalse(result["unknown_project_code_executed"])

    def test_capabilities_cli_never_prints_keys_or_unknown_source(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "capabilities"], capture_output=True,
                             text=True, timeout=8, check=False)
        self.assertEqual(run.returncode, 0)
        result = json.loads(run.stdout)
        self.assertEqual(result["algorithm"], "AES-256-GCM")
        self.assertFalse(result["production_sqlcipher"])
        self.assertNotIn("private-fixture", run.stdout)

    def test_independent_cryptography_aesgcm_oracle_when_installed(self):
        if importlib.util.find_spec("cryptography") is None:
            self.assertTrue(crypto.backend_capabilities()["authenticated_encryption"])
            return
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = self.old_key.read_bytes()
        plain = b"independent PyCA oracle plaintext"
        enveloped = crypto.encrypt_bytes(plain, key)
        marker = len(crypto.MAGIC)
        nonce = enveloped[marker:marker+12]
        header = enveloped[:marker+12]
        other_decrypt = AESGCM(key).decrypt(nonce, enveloped[marker+12:], header)
        self.assertEqual(other_decrypt, plain)
        other_envelope = header + AESGCM(key).encrypt(nonce, plain, header)
        self.assertEqual(crypto.decrypt_bytes(other_envelope, key), plain)


if __name__ == "__main__":
    unittest.main()
