"""Operator-approved local Rust binary rollout with a real canary and rollback.

Only execute an *out-of-band SHA256 allowlisted* binary signed by an explicitly
pinned local Ed25519 key. This is not an unattended remote self-updater, publisher
identity attestation, multi-process rollout, or Windows/macOS release mechanism.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from pathlib import Path

# Legacy CPython 3.9 zipimport can leave __package__ unset when a pure-Python
# helper wheel is mounted directly on sys.path; preserve package-relative
# imports using the already fully qualified module name.
if not __package__ and "." in __name__:
    __package__ = __name__.rpartition(".")[0]

if __package__:
    from .signed_release_policy_v21 import (
        HEX64,
        MAX_ARTIFACT,
        VERSION_POINTER,
        checked_private_root,
        checked_regular,
        strict_json,
        verify_signed,
        version_parts,
    )
else:
    from signed_release_policy_v21 import (
        HEX64,
        MAX_ARTIFACT,
        VERSION_POINTER,
        checked_private_root,
        checked_regular,
        strict_json,
        verify_signed,
        version_parts,
    )

CANARY_OUTPUT = re.compile(r"rust-python-healer ([0-9]+\.[0-9]+\.[0-9]+)\Z")


def _sync_dir(directory):
    descriptor = os.open(str(directory), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _run_canary(artifact, expected_version):
    """Only called after detached Ed25519 AND an independent SHA256 allowlist."""
    try:
        result = subprocess.run([str(artifact), "--version"], capture_output=True,
                                timeout=4, check=False, cwd=str(artifact.parent),
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0 or len(result.stdout) > 256 or result.stderr:
        return False
    try:
        output = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError:
        return False
    match = CANARY_OUTPUT.fullmatch(output)
    return match is not None and match.group(1) == expected_version


def _previous_pointer(root, current):
    if not current.is_symlink():
        if current.exists():
            raise ValueError("binary_current_must_be_managed_symlink")
        return None
    old = os.readlink(current)
    if not VERSION_POINTER.fullmatch(old):
        raise ValueError("binary_old_pointer_not_trusted")
    prior = root / old
    if prior.is_symlink():
        raise ValueError("binary_old_artifact_is_symlink")
    content = checked_regular(prior, MAX_ARTIFACT)
    recorded = old.rsplit("-", 1)[1].removesuffix(".bin")
    if hashlib.sha256(content).hexdigest() != recorded:
        raise ValueError("binary_old_artifact_modified")
    return old


def rollout(root, policy, manifest_bytes, signature_bytes, artifact_bytes,
            pem_bytes, approved_binary_sha256, openssl_bin=None,
            inject_post_switch_failure=False):
    """Preflight, stage, canary, atomic pointer commit, and automatic rollback.

    `approved_binary_sha256` MUST arrive from independent operator configuration,
    NEVER from the signed manifest or supplied artifact itself. Mutable external
    release activation is intentionally not provided by this offline helper.
    """
    if not isinstance(approved_binary_sha256, str) or not HEX64.fullmatch(approved_binary_sha256):
        raise ValueError("independent_approved_binary_sha256_required")
    actual_hash = hashlib.sha256(artifact_bytes).hexdigest()
    if actual_hash != approved_binary_sha256:
        raise ValueError("binary_not_in_out_of_band_sha256_allowlist")
    verified = verify_signed(policy, manifest_bytes, signature_bytes, artifact_bytes,
                             pem_bytes, openssl_bin)
    if verified["kind"] != "binary":
        raise ValueError("signed_artifact_is_not_binary")
    private, versions = checked_private_root(root)
    version = verified["version"]
    filename = version.replace(".", "_") + "-" + actual_hash + ".bin"
    stage = versions / filename
    if stage.is_symlink():
        raise ValueError("binary_stage_symlink_refused")
    if stage.exists():
        if checked_regular(stage, MAX_ARTIFACT) != artifact_bytes:
            raise ValueError("binary_stage_modified")
    else:
        descriptor = os.open(str(stage), os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                             getattr(os, "O_NOFOLLOW", 0), 0o500)
        with os.fdopen(descriptor, "wb") as output:
            output.write(artifact_bytes)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(stage, stat.S_IRUSR | stat.S_IXUSR, follow_symlinks=False)
        _sync_dir(versions)
    if not stage.stat().st_mode & stat.S_IXUSR:
        raise ValueError("binary_stage_is_not_executable")
    current = private / "current"
    old = _previous_pointer(private, current)
    new = "versions/" + filename
    if old is not None:
        old_version = old.split("/", 1)[1].split("-", 1)[0].replace("_", ".")
        if version_parts(version) < version_parts(old_version):
            raise ValueError("binary_rollout_downgrade_refused")
        if version_parts(version) == version_parts(old_version) and old != new:
            raise ValueError("binary_rollout_same_version_hash_conflict")
    if not _run_canary(stage, version):
        return {"status": "BINARY_CANARY_REFUSED_NO_MUTATION", "changed": False,
                "canary_passed": False, "rollback_required": False}
    if old == new:
        return {"status": "APPROVED_SIGNED_BINARY_ALREADY_ACTIVE", "changed": False,
                "canary_passed": True, "rollback_required": False}
    pending = private / (".binary-pending-" + secrets.token_hex(12))
    os.symlink(new, pending)
    switched = False
    try:
        os.replace(pending, current)
        switched = True
        _sync_dir(private)
        if inject_post_switch_failure:
            raise ValueError("injected_binary_canary_failure")
        if (os.readlink(current) != new or
                checked_regular(stage, MAX_ARTIFACT) != artifact_bytes or
                not _run_canary(stage, version)):
            raise ValueError("post_commit_binary_canary_failed")
        return {"status": "APPROVED_SIGNED_BINARY_CANARY_ACTIVE", "changed": True,
                "canary_passed": True, "previous_version_preserved": old is not None,
                "rollback_required": False, "binary_executed": True,
                "independent_publisher_verified": False,
                "artifact_sha256": actual_hash, "version": version}
    except (ValueError, OSError):
        if switched:
            if old is None:
                current.unlink()
            else:
                rollback = private / (".binary-rollback-" + secrets.token_hex(12))
                os.symlink(old, rollback)
                os.replace(rollback, current)
            _sync_dir(private)
            if (os.readlink(current) if current.is_symlink() else None) != old:
                raise ValueError("binary_automatic_rollback_not_verified")
        return {"status": "BINARY_POST_COMMIT_ROLLED_BACK" if switched else
                "BINARY_COMMIT_FAILED_UNCHANGED", "changed": False,
                "canary_passed": True, "rollback_required": switched,
                "previous_pointer_restored": switched}
    finally:
        if pending.is_symlink():
            pending.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--approved-sha256", required=True)
    parser.add_argument("--openssl")
    args = parser.parse_args()
    policy = strict_json(checked_regular(args.policy, 32_768))
    report = rollout(args.root, policy, checked_regular(args.manifest, 32_768),
                     checked_regular(args.signature, 128),
                     checked_regular(args.artifact, MAX_ARTIFACT),
                     checked_regular(args.public_key, 8192),
                     args.approved_sha256, args.openssl)
    print(json.dumps(report, sort_keys=True))
    if not report.get("canary_passed"):
        sys.exit(2)


if __name__ == "__main__":
    main()
