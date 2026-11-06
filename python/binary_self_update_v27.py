"""Explicitly approved, offline, Linux Rust ELF self-update in a private directory.

An operator must separately pin the Ed25519 publisher/channel and approve an
exact manifest digest, artifact digest, target root, version transition and
currently active digest.  Preview is read-only; ``--apply`` is opt-in.  This is
not a remote updater or proof of a production publisher, rollout, or fleet.

The advisory lock excludes cooperating update processes, not malicious code
already running with the same OS credentials.  Only the managed ``current``
symlink is atomically switched.  An already running process is not replaced.
"""

import argparse
try:
    import fcntl
except ImportError:  # Native Windows has no POSIX flock.
    fcntl = None
import hashlib
import json
import os
import platform
import re
import stat
import sys
from pathlib import Path

# CPython 3.9's legacy zipimport loader may leave __package__ empty while
# importing rust_python_healer_helpers.* from a directly mounted wheel.
# Recover only the package already encoded in the fully qualified module name.
if not __package__ and "." in __name__:
    __package__ = __name__.rpartition(".")[0]

if __package__:
    from .binary_recovery_v23 import rollout
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
    from binary_recovery_v23 import rollout
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

APPROVAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{7,95}\Z")
OPERATION = "apply_local_signed_rust_binary"
FIELDS = frozenset(("schema_version", "operation", "root", "channel",
                    "approval_id", "manifest_sha256", "candidate_sha256",
                    "candidate_version", "current_sha256", "current_version",
                    "openssl_sha256"))


def _verify_crypto_verifier_pin(intent, executable):
    """Pin the verification tool *before* invoking it on untrusted metadata."""
    if not isinstance(intent, dict) or set(intent) != FIELDS:
        raise ValueError("explicit_operator_intent_fields_required")
    expected = intent["openssl_sha256"]
    if not isinstance(expected, str) or not HEX64.fullmatch(expected):
        raise ValueError("operator_openssl_binary_pin_required")
    if executable is None or not Path(executable).is_absolute():
        raise ValueError("explicit_absolute_openssl_executable_required")
    if hashlib.sha256(checked_regular(executable, 32 * 1024 * 1024)).hexdigest() != expected:
        raise ValueError("openssl_verifier_sha256_pin_mismatch")


def _root_check(root):
    target = Path(root)
    if not target.is_absolute() or target.is_symlink() or not target.is_dir():
        raise ValueError("private_absolute_root_required")
    if target.resolve() != target:
        raise ValueError("symlinked_root_ancestor_refused")
    info = target.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or
            info.st_uid != os.getuid()):
        raise ValueError("private_owned_root_required")
    # Check even in read-only preview: an intermediate `versions` symlink
    # would otherwise redirect a previously managed `current` lookup.
    versions = target / "versions"
    if os.path.lexists(str(versions)):
        details = versions.lstat()
        if (not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid() or
                details.st_mode & 0o077):
            raise ValueError("private_regular_versions_directory_required")
    return target


def _active(root):
    """Validate managed active symlink, exact bytes and embedded version hash."""
    current = root / "current"
    if not current.is_symlink():
        if os.path.lexists(str(current)):
            raise ValueError("unmanaged_current_target_refused")
        return None, None, None
    pointer = os.readlink(str(current))
    if not VERSION_POINTER.fullmatch(pointer):
        raise ValueError("unsafe_current_pointer_refused")
    artifact = root / pointer
    content = checked_regular(artifact, MAX_ARTIFACT)
    digest = hashlib.sha256(content).hexdigest()
    declared = pointer.rsplit("-", 1)[1][:-4]
    if digest != declared:
        raise ValueError("current_artifact_hash_not_verified")
    version = pointer.split("/", 1)[1].split("-", 1)[0].replace("_", ".")
    version_parts(version)
    return pointer, digest, version


def _validate_intent(root, intent, verified, manifest_bytes, current_digest,
                     current_version):
    if not isinstance(intent, dict) or set(intent) != FIELDS:
        raise ValueError("explicit_operator_intent_fields_required")
    if type(intent["schema_version"]) is not int or intent["schema_version"] != 1:
        raise ValueError("unsupported_operator_intent")
    if intent["operation"] != OPERATION or intent["root"] != str(root):
        raise ValueError("operator_intent_target_or_operation_mismatch")
    if not isinstance(intent["approval_id"], str) or not APPROVAL_ID.fullmatch(intent["approval_id"]):
        raise ValueError("operator_approval_id_invalid")
    if not isinstance(intent["manifest_sha256"], str) or not HEX64.fullmatch(intent["manifest_sha256"]):
        raise ValueError("operator_manifest_digest_required")
    if intent["manifest_sha256"] != hashlib.sha256(manifest_bytes).hexdigest():
        raise ValueError("operator_manifest_digest_mismatch")
    if not isinstance(intent["candidate_sha256"], str) or not HEX64.fullmatch(intent["candidate_sha256"]):
        raise ValueError("independent_approved_candidate_sha256_required")
    if intent["candidate_sha256"] != verified["artifact_sha256"]:
        raise ValueError("independent_candidate_hash_mismatch")
    if intent["channel"] != verified["channel"] or intent["candidate_version"] != verified["version"]:
        raise ValueError("operator_channel_or_version_mismatch")
    if (intent["current_sha256"] is not None and
            (not isinstance(intent["current_sha256"], str) or
             not HEX64.fullmatch(intent["current_sha256"]))):
        raise ValueError("invalid_expected_current_hash")
    if intent["current_version"] is not None:
        version_parts(intent["current_version"])
    if intent["current_sha256"] != current_digest or intent["current_version"] != current_version:
        raise ValueError("active_binary_changed_since_operator_approval")
    if current_version is not None and version_parts(verified["version"]) <= version_parts(current_version):
        raise ValueError("no_replay_same_version_or_rollback_allowed")


def _require_native_rust_elf(artifact_bytes):
    """Linux-only executable architecture preflight; runtime identity is canaried."""
    architecture = {"x86_64": 62, "amd64": 62, "aarch64": 183,
                    "arm64": 183}.get(platform.machine().lower())
    if (sys.platform != "linux" or architecture is None or len(artifact_bytes) < 64 or
            artifact_bytes[:6] != b"\x7fELF\x02\x01" or
            int.from_bytes(artifact_bytes[18:20], "little") != architecture or
            int.from_bytes(artifact_bytes[16:18], "little") not in (2, 3)):
        raise ValueError("compatible_linux_elf_binary_required")


def _lock(root):
    """Nonblocking per-root, owner-only cooperative lock; caller closes fd."""
    if fcntl is None or sys.platform != "linux":
        raise ValueError("linux_elf_updater_lock_not_available_on_windows")
    path = root / ".binary-self-update-v27.lock"
    descriptor = os.open(str(path), os.O_CREAT | os.O_RDWR |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ValueError("unsafe_update_lock_file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("concurrent_binary_update_locked") from exc
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def offline_self_update(root, policy, manifest_bytes, signature_bytes,
                        artifact_bytes, pem_bytes, operator_intent, *,
                        openssl_bin=None, apply=False,
                        inject_post_switch_failure_for_test=False):
    """Preview or atomically activate an approved, real signed Rust ELF.

    ``operator_intent`` is an independent trusted input, not copied from the
    untrusted signed manifest.  All required checks precede any binary run.
    """
    if type(apply) is not bool:
        raise ValueError("explicit_boolean_apply_required")
    # This path uses ELF, POSIX flock and an atomic Unix symlink switch.
    # A Windows PE32+ binary must NEVER be passed through that release path.
    # In particular, fail before parsing untrusted manifests or creating files.
    if sys.platform != "linux" or fcntl is None:
        raise ValueError("linux_elf_updater_unavailable_on_windows_no_mutation")
    _verify_crypto_verifier_pin(operator_intent, openssl_bin)
    verified = verify_signed(policy, manifest_bytes, signature_bytes,
                             artifact_bytes, pem_bytes, openssl_bin)
    if verified["kind"] != "binary":
        raise ValueError("signed_artifact_must_be_binary")
    _require_native_rust_elf(artifact_bytes)
    private = _root_check(root)
    if not apply:
        pointer, current_digest, current_version = _active(private)
        _validate_intent(private, operator_intent, verified, manifest_bytes,
                         current_digest, current_version)
        return {"status": "VERIFIED_OFFLINE_UPDATE_PREVIEW_NO_MUTATION",
                "changed": False, "binary_executed": False, "network_used": False,
                "candidate_sha256": verified["artifact_sha256"],
                "from_version": current_version, "to_version": verified["version"],
                "independent_publisher_identity_verified": False,
                "external_release_rollout_qualified": False}

    # Fail without touching even the update-lock file when the intent is
    # invalid; repeat the CAS check *after* acquiring the exclusive lock.
    _preview_pointer, preview_digest, preview_version = _active(private)
    _validate_intent(private, operator_intent, verified, manifest_bytes,
                     preview_digest, preview_version)
    lock_fd = _lock(private)
    try:
        # The current pointer is compared under the same cooperative lock
        # used by every v27 updater, immediately before the delegated swap.
        pointer, current_digest, current_version = _active(private)
        _validate_intent(private, operator_intent, verified, manifest_bytes,
                         current_digest, current_version)
        private, _versions = checked_private_root(private)
        result = rollout(private, policy, manifest_bytes, signature_bytes,
                         artifact_bytes, pem_bytes,
                         operator_intent["candidate_sha256"], openssl_bin,
                         inject_post_switch_failure=inject_post_switch_failure_for_test)
        status = result["status"]
        if status == "APPROVED_SIGNED_BINARY_CANARY_ACTIVE":
            actual_pointer, actual_hash, actual_version = _active(private)
            if (not actual_pointer or actual_hash != operator_intent["candidate_sha256"] or
                    actual_version != operator_intent["candidate_version"]):
                raise ValueError("post_commit_active_digest_mismatch_requires_manual_recovery")
        elif status == "BINARY_POST_COMMIT_ROLLED_BACK":
            restored, digest, version = _active(private)
            if (restored != pointer or digest != current_digest or
                    version != current_version):
                raise ValueError("post_rollback_expected_pointer_not_restored")
        else:
            if _active(private) != (pointer, current_digest, current_version):
                raise ValueError("declined_canary_must_not_change_active_binary")
        return {**result, "operator_intent_verified": True,
                "exclusive_update_lock_used": True,
                "atomic_managed_pointer_only": True,
                "network_used": False, "independent_publisher_identity_verified": False,
                "external_release_rollout_qualified": False}
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--operator-intent", type=Path, required=True)
    parser.add_argument("--openssl")
    parser.add_argument("--apply", action="store_true", help="Explicit opt-in to local change")
    args = parser.parse_args()
    report = offline_self_update(
        args.root, strict_json(checked_regular(args.policy, 32_768)),
        checked_regular(args.manifest, 32_768),
        checked_regular(args.signature, 128),
        checked_regular(args.artifact, MAX_ARTIFACT),
        checked_regular(args.public_key, 8192),
        strict_json(checked_regular(args.operator_intent, 32_768)),
        openssl_bin=args.openssl, apply=args.apply)
    print(json.dumps(report, sort_keys=True))
    if args.apply and report.get("status") != "APPROVED_SIGNED_BINARY_CANARY_ACTIVE":
        sys.exit(2)


if __name__ == "__main__":
    main()
