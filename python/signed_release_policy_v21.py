"""Offline Ed25519 signature gate, pinned publisher channel and local swap.

This checks *locally configured trust pins*, not an independently authenticated
real-world publisher. It never executes downloaded binaries, imports plugins,
starts an updater, installs dependencies or contacts a network service.
Disposable-directory pointer swap tests are not production rollout proof.
"""

import argparse
from contextlib import contextmanager, ExitStack
import ctypes
from ctypes import wintypes
from functools import lru_cache
import importlib.util
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
from pathlib import Path

MAX_ARTIFACT = 32 * 1024 * 1024
MAX_METADATA = 32_768
MAX_KEY_PEM = 8_192
MAX_LEDGER = 8 * 1024 * 1024
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
VERSION = re.compile(r"(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\Z")
PY_MINOR = re.compile(r"3\.(0|[1-9][0-9]{0,2})\Z")
KINDS = frozenset(("binary", "plugin", "updater"))
CHANNELS = frozenset(("stable", "preview", "nightly"))
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
VERSION_POINTER = re.compile(r"versions/[0-9]+_[0-9]+_[0-9]+-[a-f0-9]{64}\.bin\Z")
WINDOWS_OPENSSL_PROFILE = Path("C:/Program Files/Git/mingw64/bin/openssl.exe")
WINDOWS_OPENSSL_LOCAL_SHA256 = "822034da8a01558c17cbe53f42f33985a6eaf7c89e21273779f9c6560d8c4d78"
WINDOWS_OPENSSL_LOCAL_VERSION = "OpenSSL 3.5.7 9 Jun 2026 (Library: OpenSSL 3.5.7 9 Jun 2026)"


@lru_cache(maxsize=2)
def _windows_helper(kind):
    injected, filename = {"privacy": ("_RPH_WINDOWS_PRIVACY", "windows_private_paths.py"),
        "source": ("_RPH_WINDOWS_SECURITY", "windows_descriptor_security_v029.py")}[kind]
    module = globals().get(injected)
    if module is None:
        spec = importlib.util.spec_from_file_location("rph_signed_release_" + kind, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(spec)
        if kind == "source": module._RPH_WINDOWS_PRIVACY = _windows_helper("privacy")
        spec.loader.exec_module(module)
    return module


def _openssl_environment(executable):
    if os.name != "nt": return None
    kernel, _ = _windows_helper("privacy")._libraries()
    kernel.GetWindowsDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    kernel.GetWindowsDirectoryW.restype = wintypes.UINT
    value = ctypes.create_unicode_buffer(32768)
    length = kernel.GetWindowsDirectoryW(value, len(value))
    if not 0 < length < len(value): raise ValueError("windows_system_directory_unavailable")
    return {"SystemRoot": value.value, "WINDIR": value.value,
        "PATH": str(Path(executable).parent) + os.pathsep + str(Path(value.value) / "System32"),
        "OPENSSL_CONF": os.devnull}


def canonical(payload):
    return json.dumps(payload, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(payload):
    return hashlib.sha256(canonical(payload)).hexdigest()


def version_parts(value):
    if not isinstance(value, str):
        raise TypeError("invalid_release_version")
    match = VERSION.fullmatch(value)
    if not match:
        raise ValueError("invalid_release_version")
    return tuple(int(part) for part in match.groups())


def checked_regular(path, maximum):
    """Bounded no-follow unique regular file snapshot, never execute file."""
    target = Path(path)
    if target.is_symlink():
        raise ValueError("signed_input_symlink_refused")
    if os.name == "nt":
        if type(maximum) is not int or not 0 < maximum <= MAX_ARTIFACT:
            raise ValueError("signed_input_not_unique_bounded_file")
        security = _windows_helper("source")
        opened = security.Root(target.absolute().parent)
        try:
            handle = security._open(opened.handles[0], target.name, False)
            opened.handles.append(handle)
            try:
                return opened.read(handle, maximum)
            except ValueError as error:
                raise ValueError("signed_input_not_unique_bounded_file") from error
        finally:
            opened.close()
    fd = os.open(str(target), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise ValueError("signed_input_not_unique_bounded_file")
        content = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if (len(content) > maximum or
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise ValueError("signed_input_modified_or_oversized")
    return content


def strict_json(content):
    def unique_pairs(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("duplicate_signed_json_key")
            result[name] = value
        return result
    return json.loads(content.decode("utf-8"), object_pairs_hook=unique_pairs,
                      parse_constant=lambda _:
                      (_ for _ in ()).throw(ValueError("nonfinite_signed_json_number")))


def validate_manifest(manifest):
    if not isinstance(manifest, dict) or set(manifest) != {
            "schema_version", "publisher_id", "channel", "kind", "version",
            "artifact_name", "artifact_sha256", "artifact_bytes",
            "python_minors", "signature_algorithm"}:
        raise ValueError("invalid_signed_manifest_fields")
    if manifest["schema_version"] != 1 or manifest["signature_algorithm"] != "Ed25519":
        raise ValueError("unsigned_or_unsupported_manifest_algorithm")
    if (not isinstance(manifest["publisher_id"], str) or
            not IDENT.fullmatch(manifest["publisher_id"]) or
            not isinstance(manifest["artifact_name"], str) or
            not IDENT.fullmatch(manifest["artifact_name"])):
        raise ValueError("invalid_manifest_identity")
    if manifest["kind"] not in KINDS or manifest["channel"] not in CHANNELS:
        raise ValueError("invalid_manifest_channel_or_kind")
    version_parts(manifest["version"])
    if not isinstance(manifest["artifact_sha256"], str) or not HEX64.fullmatch(manifest["artifact_sha256"]):
        raise ValueError("invalid_manifest_artifact_hash")
    size = manifest["artifact_bytes"]
    if type(size) is not int or not 0 < size <= MAX_ARTIFACT:
        raise ValueError("invalid_manifest_artifact_size")
    minors = manifest["python_minors"]
    if (not isinstance(minors, list) or not 1 <= len(minors) <= 64 or
            any(not isinstance(x, str) or not PY_MINOR.fullmatch(x) for x in minors) or
            minors != sorted(set(minors), key=lambda minor: int(minor.split(".")[1]))):
        raise ValueError("invalid_manifest_python_coverage")
    return manifest


def validate_policy(policy):
    if not isinstance(policy, dict) or set(policy) != {"schema_version", "channels"} or policy["schema_version"] != 1:
        raise ValueError("invalid_publisher_policy")
    channels = policy["channels"]
    if not isinstance(channels, dict) or not 1 <= len(channels) <= 3 or not set(channels) <= CHANNELS:
        raise ValueError("invalid_channel_allowlist")
    for entry in channels.values():
        if not isinstance(entry, dict) or set(entry) != {
                "publisher_id", "public_key_der_sha256", "allowed_kinds", "minimum_version"}:
            raise ValueError("invalid_channel_policy")
        if not isinstance(entry["publisher_id"], str) or not IDENT.fullmatch(entry["publisher_id"]):
            raise ValueError("invalid_pinned_publisher")
        if (not isinstance(entry["public_key_der_sha256"], str) or
                not HEX64.fullmatch(entry["public_key_der_sha256"])):
            raise ValueError("invalid_pinned_publisher_key_hash")
        kinds = entry["allowed_kinds"]
        if (not isinstance(kinds, list) or not kinds or len(kinds) != len(set(kinds)) or
                not set(kinds) <= KINDS):
            raise ValueError("invalid_channel_kind_allowlist")
        version_parts(entry["minimum_version"])
    return channels


def open_ssl(binary):
    executable = binary or shutil.which("openssl")
    if not executable or not Path(executable).is_absolute() or not Path(executable).is_file():
        raise ValueError("trusted_openssl_executable_required")
    if os.name == "nt":
        if os.path.normcase(os.path.abspath(executable)) != os.path.normcase(str(WINDOWS_OPENSSL_PROFILE)):
            raise ValueError("installed_operator_openssl_profile_required")
        if hashlib.sha256(checked_regular(executable, MAX_ARTIFACT)).hexdigest() != WINDOWS_OPENSSL_LOCAL_SHA256:
            raise ValueError("installed_operator_openssl_hash_changed")
        observed = subprocess.run([executable, "version"], capture_output=True, timeout=5,
                                  env=_openssl_environment(executable), check=False)
        if observed.returncode != 0 or observed.stdout.decode("ascii").strip() != WINDOWS_OPENSSL_LOCAL_VERSION:
            raise ValueError("installed_operator_openssl_version_changed")
    return executable


def checked_public_key_der(pem_bytes, executable):
    if not isinstance(pem_bytes, bytes) or not 0 < len(pem_bytes) <= MAX_KEY_PEM:
        raise ValueError("invalid_public_key_bytes")
    try:
        process = subprocess.run(
            [executable, "pkey", "-pubin", "-inform", "PEM", "-outform", "DER"],
            input=pem_bytes, capture_output=True, check=False, timeout=5,
            env=_openssl_environment(executable))
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("openssl_public_key_conversion_failed")
    if process.returncode != 0 or not process.stdout.startswith(ED25519_SPKI_PREFIX) or len(process.stdout) != 44:
        raise ValueError("ed25519_public_key_required")
    return process.stdout


def verify_signed(policy, manifest_bytes, signature_bytes, artifact_bytes, pem_bytes,
                  openssl_bin=None):
    """Check actual Ed25519 detached signature and exact artifact SHA256."""
    if any(not isinstance(value, bytes) for value in (
            manifest_bytes, signature_bytes, artifact_bytes, pem_bytes)):
        raise ValueError("invalid_signed_input_type")
    if len(manifest_bytes) > MAX_METADATA or len(signature_bytes) != 64 or len(artifact_bytes) > MAX_ARTIFACT:
        raise ValueError("signed_input_quota_exceeded")
    manifest = validate_manifest(strict_json(manifest_bytes))
    if canonical(manifest) != manifest_bytes:
        raise ValueError("manifest_must_use_canonical_signed_encoding")
    policy_channels = validate_policy(policy)
    channel = policy_channels.get(manifest["channel"])
    if channel is None or manifest["kind"] not in channel["allowed_kinds"]:
        raise ValueError("publisher_channel_or_kind_not_allowlisted")
    if manifest["publisher_id"] != channel["publisher_id"]:
        raise ValueError("publisher_id_not_pinned")
    if version_parts(manifest["version"]) < version_parts(channel["minimum_version"]):
        raise ValueError("release_below_pinned_minimum_version")
    if len(artifact_bytes) != manifest["artifact_bytes"] or hashlib.sha256(artifact_bytes).hexdigest() != manifest["artifact_sha256"]:
        raise ValueError("artifact_size_or_sha256_mismatch")
    executable = open_ssl(openssl_bin)
    spki = checked_public_key_der(pem_bytes, executable)
    if hashlib.sha256(spki).hexdigest() != channel["public_key_der_sha256"]:
        raise ValueError("publisher_public_key_pin_mismatch")
    try:
        with tempfile.TemporaryDirectory(prefix="rph-ed25519-verify-") as folder:
            temporary = Path(folder)
            pub, manifest_file, sig_file = (temporary / "public.pem", temporary / "manifest.json",
                                            temporary / "manifest.sig")
            pub.write_bytes(pem_bytes)
            manifest_file.write_bytes(manifest_bytes)
            sig_file.write_bytes(signature_bytes)
            with ExitStack() as pinned:
                if os.name == "nt":
                    pinned.enter_context(_windows_directory_lease(temporary, "openssl_verifier_temp_not_private"))
                    privacy = _windows_helper("privacy")
                    for path, expected in ((pub, pem_bytes), (manifest_file, manifest_bytes), (sig_file, signature_bytes)):
                        descriptor = privacy.open_private_readonly(path)
                        pinned.callback(os.close, descriptor)
                        with os.fdopen(descriptor, "rb", closefd=False) as snapshot:
                            if snapshot.read(len(expected) + 1) != expected:
                                raise ValueError("openssl_verifier_input_snapshot_changed")
                process = subprocess.run(
                    [executable, "pkeyutl", "-verify", "-pubin", "-rawin",
                     "-inkey", str(pub), "-sigfile", str(sig_file), "-in", str(manifest_file)],
                    capture_output=True, check=False, timeout=5,
                    env=_openssl_environment(executable))
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("openssl_signature_verifier_unavailable")
    if process.returncode != 0:
        raise ValueError("ed25519_manifest_signature_invalid")
    return {"schema_version": 1, "status": "LOCAL_PINNED_ED25519_SIGNATURE_VERIFIED",
            "publisher_id": manifest["publisher_id"], "channel": manifest["channel"],
            "kind": manifest["kind"], "version": manifest["version"],
            "artifact_sha256": manifest["artifact_sha256"],
            "artifact_bytes": manifest["artifact_bytes"],
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "public_key_der_sha256": hashlib.sha256(spki).hexdigest(),
            "policy_sha256": digest(policy),
            "python_minors_declared_not_qualified": manifest["python_minors"],
            "ed25519_signature_verified": True,
            "publisher_matched_operator_pin": True,
            "external_publisher_identity_verified": False,
            "binary_executed": False, "release_health_verified": False,
            "network_used": False, "source_executed": False,
            "note": "Real Ed25519 signature for a locally pinned key; the pin's publisher identity is operator-controlled"}


@contextmanager
def _windows_ledger_lease(target):
    security, privacy = _windows_helper("source"), _windows_helper("privacy")
    opened, handle = security.Root(target.absolute().parent), None
    try:
        security._name(target.name)
        privacy._inspect_private_handle(opened.handles[0], True, *privacy._libraries())
        handle = opened.kernel.CreateFileW(str(target.absolute()), 0xC0000000, 3, None, 4, 0x00200000, None)
        if not handle or handle == ctypes.c_void_p(-1).value:
            raise ValueError("release_channel_ledger_native_open_refused")
        privacy._inspect_private_handle(handle, False, *privacy._libraries())
        before = opened.blob._information(handle, False, MAX_LEDGER)
        yield
        privacy._inspect_private_handle(handle, False, *privacy._libraries())
        after = opened.blob._information(handle, False, MAX_LEDGER)
        if before[:3] != after[:3]: raise ValueError("release_channel_ledger_identity_changed")
        privacy._inspect_private_handle(opened.handles[0], True, *privacy._libraries())
    finally:
        if handle and handle != ctypes.c_void_p(-1).value: opened.kernel.CloseHandle(handle)
        opened.close()


class _WindowsLedgerConnection(sqlite3.Connection):
    def close(self):
        try:
            super().close()
        finally:
            lease = getattr(self, "_windows_lease", None)
            self._windows_lease = None
            if lease is not None: lease.__exit__(None, None, None)

    def __del__(self):
        try: self.close()
        except Exception: pass  # Explicit record_channel.close still propagates validation failure.


def open_ledger(path):
    target = Path(path)
    if target.is_symlink() or (target.exists() and (
            not target.is_file() or target.stat().st_nlink != 1 or
            target.stat().st_size > MAX_LEDGER)):
        raise ValueError("release_channel_ledger_refused")
    if not target.exists() and (not target.parent.is_dir() or target.parent.is_symlink()):
        raise ValueError("release_channel_ledger_parent_refused")
    lease = _windows_ledger_lease(target) if os.name == "nt" else None
    if lease is not None: lease.__enter__()
    try:
        connection = sqlite3.connect(str(target), isolation_level=None, timeout=5,
            factory=_WindowsLedgerConnection if os.name == "nt" else sqlite3.Connection)
        if lease is not None: connection._windows_lease = lease
    except BaseException:
        if lease is not None: lease.__exit__(*__import__("sys").exc_info())
        raise
    try:
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA busy_timeout=5000")
    except BaseException:
        connection.close()
        raise
    return connection


def record_channel(ledger_path, policy, manifest_bytes, signature_bytes,
                   artifact_bytes, pem_bytes, openssl_bin=None):
    """Always re-verify actual signed bytes; never trust a supplied verdict."""
    verified = verify_signed(policy, manifest_bytes, signature_bytes, artifact_bytes,
                             pem_bytes, openssl_bin)
    connection = open_ledger(ledger_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("""CREATE TABLE IF NOT EXISTS channel_state (
          channel TEXT NOT NULL, kind TEXT NOT NULL, version TEXT NOT NULL,
          manifest_sha256 TEXT NOT NULL, artifact_sha256 TEXT NOT NULL,
          PRIMARY KEY(channel,kind))""")
        connection.execute("""CREATE TABLE IF NOT EXISTS channel_history (
          seq INTEGER PRIMARY KEY AUTOINCREMENT, channel TEXT NOT NULL,
          kind TEXT NOT NULL, version TEXT NOT NULL, manifest_sha256 TEXT NOT NULL,
          artifact_sha256 TEXT NOT NULL, recorded_at INTEGER NOT NULL)""")
        row = connection.execute("SELECT version,manifest_sha256 FROM channel_state "
                                 "WHERE channel=? AND kind=?",
                                 (verified["channel"], verified["kind"])).fetchone()
        if row is not None:
            if row[0] == verified["version"] and row[1] == verified["manifest_sha256"]:
                connection.execute("ROLLBACK")
                return {"status": "ALREADY_RECORDED_NO_NEW_RELEASE", "release_recorded": False,
                        "source_executed": False, "binary_executed": False,
                        "verified_release": verified}
            if version_parts(verified["version"]) <= version_parts(row[0]):
                raise ValueError("release_downgrade_or_same_version_content_change_refused")
        connection.execute("INSERT INTO channel_state VALUES (?,?,?,?,?) ON CONFLICT(channel,kind) DO UPDATE SET "
                           "version=excluded.version,manifest_sha256=excluded.manifest_sha256,"
                           "artifact_sha256=excluded.artifact_sha256",
                           (verified["channel"], verified["kind"], verified["version"],
                            verified["manifest_sha256"], verified["artifact_sha256"]))
        connection.execute("INSERT INTO channel_history(channel,kind,version,manifest_sha256,artifact_sha256,recorded_at) "
                           "VALUES (?,?,?,?,?,?)",
                           (verified["channel"], verified["kind"], verified["version"],
                            verified["manifest_sha256"], verified["artifact_sha256"], int(time.time())))
        connection.execute("COMMIT")
        return {"status": "PINNED_SIGNED_VERSION_RECORDED_NOT_DEPLOYED", "release_recorded": True,
                "channel": verified["channel"], "kind": verified["kind"],
                "version": verified["version"], "source_executed": False,
                "binary_executed": False, "verified_release": verified}
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def checked_private_root(root):
    """Allow only caller-owned private local directories for staged pointer swaps."""
    path = Path(root)
    if path.is_symlink() or not path.is_dir():
        raise ValueError("release_swap_private_root_required")
    if os.name == "nt":
        privacy = _windows_helper("privacy")
        try: privacy.assert_private_directory(path)
        except (OSError, ValueError) as error:
            raise ValueError("release_swap_root_must_be_private") from error
        versions = path / "versions"
        if versions.is_symlink(): raise ValueError("release_versions_symlink_refused")
        if not versions.exists(): versions.mkdir()
        try: privacy.assert_private_directory(versions)
        except (OSError, ValueError) as error:
            raise ValueError("release_versions_not_private_directory") from error
        return path, versions
    info = path.stat()
    if info.st_mode & 0o077 or info.st_uid != getattr(os, "getuid", lambda: info.st_uid)():
        raise ValueError("release_swap_root_must_be_private")
    versions = path / "versions"
    if versions.is_symlink():
        raise ValueError("release_versions_symlink_refused")
    if not versions.exists():
        versions.mkdir(mode=0o700)
    if not versions.is_dir() or versions.stat().st_mode & 0o077:
        raise ValueError("release_versions_not_private_directory")
    return path, versions


@contextmanager
def _windows_directory_lease(path, reason):
    security, privacy = _windows_helper("source"), _windows_helper("privacy")
    blob = security._blob()
    _, kernel, _ = blob._libraries()
    value = privacy._local_absolute_path(path)
    # Mutating a child needs directory write sharing, but DELETE sharing remains
    # absent: this same directory cannot be renamed/replaced during the call.
    # GENERIC_READ includes FILE_LIST_DIRECTORY. Metadata-only handles do not
    # reliably participate in Windows delete-sharing checks for empty dirs.
    handle = kernel.CreateFileW(value, 0x80100000, 3, None, 3, 0x02200000, None)
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise ValueError(reason)
    try:
        try: privacy._inspect_private_handle(handle, True, *privacy._libraries())
        except (OSError, ValueError) as error:
            raise ValueError(reason) from error
        before = blob._information(handle, True, MAX_ARTIFACT)
        final = ctypes.create_unicode_buffer(32768)
        length = kernel.GetFinalPathNameByHandleW(handle, final, len(final), 0)
        normalized = final.value[4:] if final.value.startswith("\\\\?\\") else final.value
        if (not 0 < length < len(final) or os.path.normcase(os.path.normpath(normalized)) != os.path.normcase(os.path.normpath(value))):
            raise ValueError("release_swap_directory_ancestor_alias_refused")
        yield handle
        privacy._inspect_private_handle(handle, True, *privacy._libraries())
        if before[:3] != blob._information(handle, True, MAX_ARTIFACT)[:3]:
            raise ValueError("release_versions_directory_changed")
    finally:
        kernel.CloseHandle(handle)


@contextmanager
def _windows_swap_lease(root):
    with _windows_directory_lease(root, "release_swap_root_must_be_private"):
        private, versions = checked_private_root(root)
        with _windows_directory_lease(versions, "release_versions_not_private_directory"):
            yield private, versions


def local_stage_and_swap(root, policy, manifest_bytes, signature_bytes, artifact_bytes,
                         pem_bytes, openssl_bin=None, force_post_switch_failure_for_test=False):
    """Swap a *pointer* atomically, never run an executable; rollback on failure.

    A signed, preverified artifact is copied to a private immutable-name file.
    os.replace() changes one symlink atomically. No whole-system atomicity,
    executable health-check, crash-consistent fsync proof or canary deploy.
    """
    verified = verify_signed(policy, manifest_bytes, signature_bytes, artifact_bytes,
                             pem_bytes, openssl_bin)
    if os.name == "nt":
        with _windows_swap_lease(root) as (private, versions):
            return _stage_verified_pointer(verified, private, versions, artifact_bytes, force_post_switch_failure_for_test)
    private, versions = checked_private_root(root)
    return _stage_verified_pointer(verified, private, versions, artifact_bytes, force_post_switch_failure_for_test)


def _stage_verified_pointer(verified, private, versions, artifact_bytes, force_post_switch_failure_for_test):
    filename = verified["version"].replace(".", "_") + "-" + verified["artifact_sha256"] + ".bin"
    stage = versions / filename
    if stage.is_symlink():
        raise ValueError("release_stage_symlink_refused")
    if stage.exists():
        if checked_regular(stage, MAX_ARTIFACT) != artifact_bytes:
            raise ValueError("release_stage_content_mismatch")
    else:
        descriptor = os.open(str(stage), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as output:
            if os.name == "nt": _windows_helper("privacy").assert_private_file_descriptor(output.fileno())
            output.write(artifact_bytes)
            output.flush()
            os.fsync(output.fileno())
            if os.name == "nt": _windows_helper("privacy").assert_private_file_descriptor(output.fileno())
    current = private / "current"
    old = None
    if current.is_symlink():
        old = _read_pointer(current)
        previous_stage = private / old
        if (not VERSION_POINTER.fullmatch(old) or previous_stage.is_symlink() or
                not previous_stage.is_file()):
            raise ValueError("previous_release_pointer_untrusted")
        previous_content = checked_regular(previous_stage, MAX_ARTIFACT)
        previous_digest = old.rsplit("-", 1)[1].removesuffix(".bin")
        if hashlib.sha256(previous_content).hexdigest() != previous_digest:
            raise ValueError("previous_release_stage_content_changed")
    elif current.exists():
        raise ValueError("refuse_to_overwrite_existing_current_regular_file")
    new = "versions/" + filename
    if old is not None:
        old_version = old.split("/", 1)[1].split("-", 1)[0].replace("_", ".")
        if version_parts(verified["version"]) < version_parts(old_version):
            raise ValueError("signed_release_pointer_downgrade_refused")
        if version_parts(verified["version"]) == version_parts(old_version) and old != new:
            raise ValueError("signed_same_version_artifact_change_refused")
    if old == new:
        return {"status": "SIGNED_POINTER_ALREADY_ACTIVE_NOT_EXECUTED",
                "atomic_pointer_switch": False, "binary_executed": False,
                "release_health_verified": False, "source_executed": False}
    pending = private / (".pending-" + secrets.token_hex(8))
    _create_pointer(new, pending)
    switched = False
    try:
        os.replace(pending, current)
        switched = True
        if force_post_switch_failure_for_test:
            raise ValueError("injected_post_switch_failure_for_test")
        if _read_pointer(current) != new or checked_regular(stage, MAX_ARTIFACT) != artifact_bytes:
            raise ValueError("post_switch_content_check_failed")
        return {"status": "SIGNED_LOCAL_POINTER_SWITCHED_NOT_EXECUTION_QUALIFIED",
                "atomic_pointer_switch": True,
                "artifact_sha256": verified["artifact_sha256"],
                "manifest_sha256": verified["manifest_sha256"],
                "previous_pointer_present": old is not None,
                "binary_executed": False,
                "release_health_verified": False,
                "content_health_check": "SIGNED_SHA256_ONLY",
                "external_publisher_identity_verified": False,
                "source_executed": False}
    except (OSError, ValueError):
        if switched:
            if old is None:
                current.unlink()
            else:
                rollback = private / (".rollback-" + secrets.token_hex(8))
                _create_pointer(old, rollback)
                os.replace(rollback, current)
            if (_read_pointer(current) if current.is_symlink() else None) != old:
                raise ValueError("local_pointer_rollback_unverified")
        return {"status": ("LOCAL_POINTER_ROLLED_BACK_AFTER_POST_SWITCH_FAILURE" if switched
                           else "LOCAL_POINTER_SWITCH_FAILED_NO_CHANGE"),
                "atomic_pointer_switch": switched,
                "rollback_pointer_restored": switched,
                "binary_executed": False,
                "release_health_verified": False,
                "source_executed": False,
                "note": "Rollback of the local symlink only; no executable/OS service health proof"}
    finally:
        if pending.is_symlink():
            pending.unlink()


def _read_pointer(path):
    target = os.readlink(path)
    return target.replace("\\", "/") if os.name == "nt" else target


def _create_pointer(target, path):
    if not VERSION_POINTER.fullmatch(target):
        raise ValueError("previous_release_pointer_untrusted")
    # NTFS relative symlink reparse targets need native separators; the policy
    # representation remains the original canonical versions/name format.
    os.symlink(target.replace("/", "\\") if os.name == "nt" else target, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--openssl")
    parser.add_argument("--record-ledger", type=Path)
    args = parser.parse_args()
    policy = strict_json(checked_regular(args.policy, MAX_METADATA))
    manifest = checked_regular(args.manifest, MAX_METADATA)
    signature = checked_regular(args.signature, 128)
    artifact = checked_regular(args.artifact, MAX_ARTIFACT)
    public_key = checked_regular(args.public_key, MAX_KEY_PEM)
    if args.record_ledger:
        report = record_channel(args.record_ledger, policy, manifest, signature,
                                artifact, public_key, args.openssl)
    else:
        report = verify_signed(policy, manifest, signature, artifact,
                               public_key, args.openssl)
    print(json.dumps(report))


if __name__ == "__main__":
    main()
