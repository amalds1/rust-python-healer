"""Opt-in, local canary state promotion with real subprocess health and rollback.

Never executes release contents. Production signed binary swaps, off-host
recovery and adversarial concurrent filesystem owners are NOT_VERIFIED.
"""

import argparse
import hashlib
import importlib.util
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


MAX_RELEASE_BYTES = 131072
MAX_AUDIT_BYTES = 200000
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,59}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")


def _platform_adapter():
    embedded = globals().get("_RPH_PLATFORM_PRIVACY")
    if embedded is not None:
        return embedded
    path = Path(__file__).resolve().parent / "platform_privacy_v028.py"
    spec = importlib.util.spec_from_file_location("rph_canary_platform_privacy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


platform_privacy = _platform_adapter()
TRUSTED_HEALTH_PROBE = r'''
import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1]); data=p.read_bytes()
if hashlib.sha256(data).hexdigest()!=sys.argv[2]: sys.exit(2)
try: payload=json.loads(data)
except (ValueError,UnicodeError): sys.exit(3)
if type(payload) is not dict or payload.get("health")!="ready" or payload.get("release")!=sys.argv[3]: sys.exit(4)
print(json.dumps({"status":"CANARY_HEALTH_PASS","sha256":sys.argv[2],"source_executed":False}))
'''


def _digest(content):
    return hashlib.sha256(content).hexdigest()


def _bounded_file(path, maximum):
    path = Path(path)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
            before.st_size > maximum or before.st_size < 1):
        raise ValueError("unsafe_or_unbounded_release_file")
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        if os.name == "nt":
            platform_privacy.private_descriptor(stream.fileno(), "canary_file_must_be_private")
        opened = os.fstat(stream.fileno())
        content = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
            (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) or
            (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or
            len(content) > maximum):
        raise ValueError("release_source_changed")
    return content


def _directory(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("canary_directory_must_be_private")
    if os.name == "nt":
        platform_privacy.private_directory(path, "canary_directory_must_be_private")
    elif stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("canary_directory_must_be_private")
    return path


def canary_signature(manifest, key):
    if not isinstance(manifest, dict) or not isinstance(key, bytes) or len(key) < 16:
        raise ValueError("canary_manifest_key_invalid")
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    return hmac.new(key, raw, hashlib.sha256).hexdigest()


def _write_unique(directory, label, content):
    fd, raw = tempfile.mkstemp(prefix=label, dir=str(directory))
    try:
        try:
            # Keep descriptor ownership here even if fdopen construction fails.
            with os.fdopen(fd, "wb", closefd=False) as stream:
                if os.name == "nt":
                    platform_privacy.private_descriptor(stream.fileno(), "canary_staged_file_must_be_private")
                else:
                    os.fchmod(stream.fileno(), 0o600)
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
        return Path(raw)
    except BaseException:
        Path(raw).unlink(missing_ok=True)
        raise


def _sync_directory(folder):
    return platform_privacy.sync_directory_scope(folder)


def _health_check(active, expect_sha, release, python):
    try:
        result = subprocess.run([str(python), "-I", "-S", "-B", "-c",
                                 TRUSTED_HEALTH_PROBE, str(active), expect_sha, release],
                                capture_output=True, check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode or result.stderr or len(result.stdout) > 1000:
        return False
    try:
        data = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        return False
    return data.get("status") == "CANARY_HEALTH_PASS" and data.get("source_executed") is False


def local_canary(active, candidate, manifest, signature, key, *, python=sys.executable,
                 inject_health_failure=False):
    """Compare signed local snapshots, canary-swap, probe, and restore on FAIL."""
    if not isinstance(manifest, dict) or set(manifest) != {
            "schema", "operation", "old_sha256", "candidate_sha256", "release", "actor"}:
        raise ValueError("unsupported_canary_manifest")
    if (manifest["schema"] != 1 or manifest["operation"] != "local_canary" or
            not isinstance(manifest["release"], str) or not LABEL.fullmatch(manifest["release"]) or
            not isinstance(manifest["actor"], str) or not LABEL.fullmatch(manifest["actor"]) or
            any(not isinstance(manifest[name], str) or not HEX.fullmatch(manifest[name])
                for name in ("old_sha256", "candidate_sha256"))):
        raise ValueError("invalid_canary_identity")
    if not isinstance(signature, str) or not HEX.fullmatch(signature) or not hmac.compare_digest(
            canary_signature(manifest, key), signature):
        raise ValueError("canary_approval_not_verified")
    active = Path(active)
    folder = _directory(active.parent)
    candidate = Path(candidate)
    if candidate.parent != folder or candidate == active:
        raise ValueError("canary_candidate_must_be_private_and_distinct")
    original = _bounded_file(active, MAX_RELEASE_BYTES)
    proposed = _bounded_file(candidate, MAX_RELEASE_BYTES)
    if _digest(original) != manifest["old_sha256"] or _digest(proposed) != manifest["candidate_sha256"]:
        raise ValueError("stale_or_corrupted_canary_snapshot")
    lock = folder / ".canary-active.lock"
    lock_descriptor = os.open(str(lock), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                              getattr(os, "O_NOFOLLOW", 0), 0o600)
    backup = None
    staged = None
    result = "NOT_RUN"
    try:
        try:
            if os.name == "nt":
                platform_privacy.private_descriptor(lock_descriptor, "canary_lock_must_be_private")
        finally:
            os.close(lock_descriptor)
        # No execution of untrusted candidate: health checks only canonical JSON.
        backup = _write_unique(folder, ".canary-backup-", original)
        staged = _write_unique(folder, ".canary-stage-", proposed)
        if _digest(_bounded_file(active, MAX_RELEASE_BYTES)) != manifest["old_sha256"]:
            raise ValueError("active_changed_before_swap")
        platform_privacy.replace_file(staged, active)
        staged = None
        durability = _sync_directory(folder)
        healthy = not inject_health_failure and _health_check(
            active, manifest["candidate_sha256"], manifest["release"], python)
        if healthy:
            result = "CANARY_HEALTH_PASS_LOCAL_ONLY"
        else:
            # The original bytes are atomically restored on the same filesystem.
            platform_privacy.replace_file(backup, active)
            backup = None
            durability = _sync_directory(folder)
            if _digest(_bounded_file(active, MAX_RELEASE_BYTES)) != manifest["old_sha256"]:
                raise ValueError("rollback_integrity_failed")
            result = "CANARY_FAILED_ROLLED_BACK"
        return {"status": result, "old_sha256": manifest["old_sha256"],
                "candidate_sha256": manifest["candidate_sha256"],
                "active_sha256": _digest(_bounded_file(active, MAX_RELEASE_BYTES)),
                "approval_verified": True, "canary_promoted": healthy,
                "automatic_rollback_verified": not healthy,
                "health_subprocess_invoked": not inject_health_failure,
                "unknown_release_executed": False,
                "production_binary_self_update_verified": False,
                "durability_scope": durability,
                "off_host_recovery_verified": False}
    finally:
        for artifact in (backup, staged):
            if artifact is not None and artifact.exists():
                artifact.unlink()
        lock.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--active", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--inject-health-failure", action="store_true")
    args = parser.parse_args()
    key_info = Path(args.key_file).lstat()
    if os.name != "nt" and stat.S_IMODE(key_info.st_mode) & 0o077:
        parser.error("review_key_file_must_be_private")
    key = _bounded_file(args.key_file, 128)
    envelope = json.loads(_bounded_file(args.approval, 20000))
    report = local_canary(args.active, args.candidate, envelope["manifest"],
                          envelope["signature"], key, python=args.python,
                          inject_health_failure=args.inject_health_failure)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
