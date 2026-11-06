"""Fail-closed offline publisher-pinned, operator-intent Rust ELF update tests."""

import copy
try:
    import fcntl
except ImportError:
    fcntl = None
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from binary_self_update_v27 import OPERATION, offline_self_update
from signed_release_policy_v21 import canonical, version_parts

OPENSSL = shutil.which("openssl")
BINARY = ROOT / "target" / "release" / ("rust-python-healer.exe" if sys.platform == "win32" else "rust-python-healer")
PRIOR_BINARY = ROOT / "dist" / "prior-v0.22" / "rust-python-healer"


@unittest.skipUnless(sys.platform == "linux" and fcntl is not None and
                     OPENSSL and BINARY.is_file() and PRIOR_BINARY.is_file(),
                     "Linux-only real Rust ELF release pair or openssl unavailable")
class OfflineBinarySelfUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="rph-self-update-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.private = self.base / "release"
        self.private.mkdir(mode=0o700)
        self.key = self.base / "private-key.pem"
        self.public = self.base / "public-key.pem"
        subprocess.run([OPENSSL, "genpkey", "-algorithm", "ED25519", "-out",
                        str(self.key)], check=True, capture_output=True)
        subprocess.run([OPENSSL, "pkey", "-in", str(self.key), "-pubout",
                        "-out", str(self.public)], check=True, capture_output=True)
        der = subprocess.run([OPENSSL, "pkey", "-pubin", "-in", str(self.public),
                              "-outform", "DER"], capture_output=True, check=True).stdout
        self.pem = self.public.read_bytes()
        self.openssl_sha = hashlib.sha256(Path(OPENSSL).read_bytes()).hexdigest()
        self.policy = {"schema_version": 1, "channels": {"stable": {
            "publisher_id": "offline-test-publisher", "allowed_kinds": ["binary"],
            "minimum_version": "0.1.0",
            "public_key_der_sha256": hashlib.sha256(der).hexdigest()}}}
        self.artifact = BINARY.read_bytes()
        self.previous_artifact = PRIOR_BINARY.read_bytes()
        self.sha = hashlib.sha256(self.artifact).hexdigest()
        self.previous_sha = hashlib.sha256(self.previous_artifact).hexdigest()
        self.version = subprocess.check_output([str(BINARY), "--version"],
                                               timeout=4).decode().strip().split(" ", 1)[1]
        self.previous_version = subprocess.check_output([str(PRIOR_BINARY), "--version"],
                                                        timeout=4).decode().strip().split(" ", 1)[1]
        self.assertLess(version_parts(self.previous_version), version_parts(self.version))

    def signed(self, *, version=None, artifact=None, kind="binary", channel="stable"):
        version = version or self.version
        artifact = self.artifact if artifact is None else artifact
        metadata = {"schema_version": 1, "publisher_id": "offline-test-publisher",
                    "channel": channel, "kind": kind, "version": version,
                    "artifact_name": "rust-python-healer", "artifact_sha256":
                    hashlib.sha256(artifact).hexdigest(), "artifact_bytes": len(artifact),
                    "signature_algorithm": "Ed25519", "python_minors": [
                        "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15"]}
        manifest = canonical(metadata)
        source = self.base / "manifest.json"
        signature = self.base / "manifest.sig"
        source.write_bytes(manifest)
        subprocess.run([OPENSSL, "pkeyutl", "-sign", "-rawin", "-inkey",
                        str(self.key), "-in", str(source), "-out", str(signature)],
                       capture_output=True, check=True)
        return manifest, signature.read_bytes(), artifact

    def intent(self, fixture, *, current_sha=None, current_version=None):
        manifest, _signature, artifact = fixture
        version = json.loads(manifest)["version"]
        return {"schema_version": 1, "operation": OPERATION,
                "root": str(self.private), "channel": "stable",
                "approval_id": "OPERATOR-TEST-00000001",
                "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                "candidate_sha256": hashlib.sha256(artifact).hexdigest(),
                "candidate_version": version, "current_sha256": current_sha,
                "current_version": current_version,
                "openssl_sha256": self.openssl_sha}

    def update(self, *, fixture=None, intent=None, apply=True, policy=None, pem=None,
               root=None, **kwargs):
        fixture = fixture or self.signed()
        intent = intent if intent is not None else self.intent(fixture)
        return offline_self_update(
            self.private if root is None else root,
            self.policy if policy is None else policy, *fixture,
            self.pem if pem is None else pem, intent,
            openssl_bin=OPENSSL, apply=apply, **kwargs)

    def cli(self, *, apply=False, intent_symlink=False):
        manifest, signature, artifact = self.signed()
        files = {"policy.json": canonical(self.policy), "manifest.json": manifest,
                 "manifest.sig": signature, "artifact.bin": artifact,
                 "public.pem": self.pem,
                 "intent.json": canonical(self.intent((manifest, signature, artifact)))}
        for name, content in files.items():
            (self.base / name).write_bytes(content)
        approval = self.base / "intent.json"
        if intent_symlink:
            approval = self.base / "intent-link.json"
            approval.symlink_to(self.base / "intent.json")
        options = [sys.executable, str(ROOT / "python" / "binary_self_update_v27.py"),
                   "--root", str(self.private), "--policy", str(self.base / "policy.json"),
                   "--manifest", str(self.base / "manifest.json"),
                   "--signature", str(self.base / "manifest.sig"),
                   "--artifact", str(self.base / "artifact.bin"),
                   "--public-key", str(self.base / "public.pem"),
                   "--operator-intent", str(approval), "--openssl", OPENSSL]
        if apply:
            options.append("--apply")
        return subprocess.run(options, check=False, capture_output=True,
                              text=True, timeout=9)

    def install_previous(self):
        fixture = self.signed(version=self.previous_version,
                              artifact=self.previous_artifact)
        result = self.update(fixture=fixture)
        self.assertTrue(result["changed"])
        return os.readlink(str(self.private / "current"))

    def test_signed_operator_approved_real_rust_elf_activates(self):
        report = self.update()
        self.assertTrue(report["operator_intent_verified"])
        self.assertTrue(report["exclusive_update_lock_used"])
        self.assertTrue(report["changed"])
        self.assertTrue(report["binary_executed"])
        self.assertFalse(report["network_used"])
        self.assertFalse(report["independent_publisher_identity_verified"])
        self.assertFalse(report["external_release_rollout_qualified"])
        current = self.private / "current"
        self.assertTrue(current.is_symlink())
        self.assertEqual(hashlib.sha256(current.read_bytes()).hexdigest(), self.sha)
        self.assertEqual(subprocess.check_output([str(current), "--version"],
                                                 timeout=4).decode().strip(),
                         "rust-python-healer " + self.version)

    def test_default_readonly_preview_does_not_stage_or_execute(self):
        report = self.update(apply=False)
        self.assertEqual(report["status"], "VERIFIED_OFFLINE_UPDATE_PREVIEW_NO_MUTATION")
        self.assertFalse(report["binary_executed"])
        self.assertFalse((self.private / "versions").exists())
        self.assertFalse((self.private / ".binary-self-update-v27.lock").exists())
        self.assertFalse(os.path.lexists(str(self.private / "current")))

    def test_cli_explicit_apply_required_and_real_signed_elf_commits(self):
        preview = self.cli()
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertFalse(json.loads(preview.stdout)["changed"])
        self.assertFalse((self.private / "versions").exists())
        approved = self.cli(apply=True)
        self.assertEqual(approved.returncode, 0, approved.stderr)
        self.assertTrue(json.loads(approved.stdout)["changed"])
        self.assertEqual(hashlib.sha256((self.private / "current").read_bytes()).hexdigest(),
                         self.sha)

    def test_cli_rejects_symlinked_operator_approval(self):
        process = self.cli(apply=True, intent_symlink=True)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("signed_input_symlink_refused", process.stderr)
        self.assertFalse(os.path.lexists(str(self.private / "current")))

    def test_missing_explicit_operator_intent_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "intent_fields_required"):
            self.update(intent={})
        self.assertFalse(os.path.lexists(str(self.private / "current")))
        self.assertFalse((self.private / ".binary-self-update-v27.lock").exists())

    def test_approval_target_root_mismatch_blocks_update(self):
        fixture = self.signed()
        approval = self.intent(fixture)
        approval["root"] = "/tmp/not-the-approved-release-root"
        with self.assertRaisesRegex(ValueError, "target_or_operation_mismatch"):
            self.update(fixture=fixture, intent=approval)
        self.assertFalse((self.private / ".binary-self-update-v27.lock").exists())

    def test_approval_signed_manifest_digest_mismatch_blocks_update(self):
        fixture = self.signed()
        approval = self.intent(fixture)
        approval["manifest_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "manifest_digest_mismatch"):
            self.update(fixture=fixture, intent=approval)

    def test_approval_candidate_digest_mismatch_blocks_update(self):
        fixture = self.signed()
        approval = self.intent(fixture)
        approval["candidate_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "candidate_hash_mismatch"):
            self.update(fixture=fixture, intent=approval)

    def test_openssl_verifier_binary_must_match_independent_pin(self):
        fixture = self.signed()
        approval = self.intent(fixture)
        approval["openssl_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "openssl_verifier_sha256_pin_mismatch"):
            self.update(fixture=fixture, intent=approval)

    def test_openssl_path_must_be_explicit_even_for_preview(self):
        fixture = self.signed()
        approval = self.intent(fixture)
        with self.assertRaisesRegex(ValueError, "explicit_absolute_openssl_executable_required"):
            offline_self_update(self.private, self.policy, *fixture, self.pem,
                                approval, apply=False)

    def test_approval_expected_version_mismatch_blocks_update(self):
        fixture = self.signed()
        approval = self.intent(fixture)
        approval["candidate_version"] = "9.99.9"
        with self.assertRaisesRegex(ValueError, "channel_or_version_mismatch"):
            self.update(fixture=fixture, intent=approval)

    def test_changed_signed_artifact_is_refused(self):
        manifest, signature, artifact = self.signed()
        with self.assertRaisesRegex(ValueError, "artifact_size_or_sha256_mismatch"):
            self.update(fixture=(manifest, signature, artifact[:-1] + b"!"))

    def test_changed_detached_ed25519_signature_is_refused(self):
        manifest, _signature, artifact = self.signed()
        with self.assertRaisesRegex(ValueError, "ed25519_manifest_signature_invalid"):
            self.update(fixture=(manifest, b"!" * 64, artifact))

    def test_wrong_publisher_pin_blocks_all_execution(self):
        policy = copy.deepcopy(self.policy)
        policy["channels"]["stable"]["public_key_der_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "publisher_public_key_pin_mismatch"):
            self.update(policy=policy)
        self.assertFalse(os.path.lexists(str(self.private / "current")))

    def test_non_binary_signed_artifact_is_never_executed(self):
        policy = copy.deepcopy(self.policy)
        policy["channels"]["stable"]["allowed_kinds"] = ["plugin"]
        fixture = self.signed(kind="plugin")
        with self.assertRaisesRegex(ValueError, "signed_artifact_must_be_binary"):
            self.update(fixture=fixture, policy=policy)

    def test_signed_non_elf_is_never_executed(self):
        fixture = self.signed(artifact=b"not an executable, merely signed data")
        with self.assertRaisesRegex(ValueError, "compatible_linux_elf_binary_required"):
            self.update(fixture=fixture)

    def test_wrong_elf_architecture_is_refused(self):
        other = bytearray(self.artifact)
        other[18:20] = (0).to_bytes(2, "little")
        fixture = self.signed(artifact=bytes(other))
        with self.assertRaisesRegex(ValueError, "compatible_linux_elf_binary_required"):
            self.update(fixture=fixture)

    def test_signed_wrong_runtime_version_cannot_activate(self):
        fixture = self.signed(version="9.99.9")
        result = self.update(fixture=fixture)
        self.assertEqual(result["status"], "BINARY_CANARY_REFUSED_NO_MUTATION")
        self.assertFalse(result["changed"])
        self.assertFalse(os.path.lexists(str(self.private / "current")))

    def test_real_two_release_upgrade_exact_expected_previous_sha(self):
        old = self.install_previous()
        fixture = self.signed()
        approval = self.intent(fixture, current_sha=self.previous_sha,
                               current_version=self.previous_version)
        report = self.update(fixture=fixture, intent=approval)
        self.assertTrue(report["changed"])
        self.assertNotEqual(os.readlink(str(self.private / "current")), old)
        self.assertEqual(hashlib.sha256((self.private / "current").read_bytes()).hexdigest(),
                         self.sha)

    def test_stale_operator_expected_previous_sha_blocks_swap(self):
        old = self.install_previous()
        fixture = self.signed()
        approval = self.intent(fixture)
        with self.assertRaisesRegex(ValueError, "active_binary_changed_since_operator_approval"):
            self.update(fixture=fixture, intent=approval)
        self.assertEqual(os.readlink(str(self.private / "current")), old)

    def test_replayed_same_version_approval_is_rejected(self):
        self.update()
        with self.assertRaisesRegex(ValueError, "active_binary_changed_since_operator_approval"):
            self.update()

    def test_signed_downgrade_blocked_with_correct_approval(self):
        self.update()
        old = os.readlink(str(self.private / "current"))
        fixture = self.signed(version=self.previous_version,
                              artifact=self.previous_artifact)
        approval = self.intent(fixture, current_sha=self.sha,
                               current_version=self.version)
        with self.assertRaisesRegex(ValueError, "no_replay_same_version_or_rollback_allowed"):
            self.update(fixture=fixture, intent=approval)
        self.assertEqual(os.readlink(str(self.private / "current")), old)

    def test_forced_post_commit_failure_restores_exact_old_pointer(self):
        old = self.install_previous()
        fixture = self.signed()
        approval = self.intent(fixture, current_sha=self.previous_sha,
                               current_version=self.previous_version)
        report = self.update(fixture=fixture, intent=approval,
                             inject_post_switch_failure_for_test=True)
        self.assertEqual(report["status"], "BINARY_POST_COMMIT_ROLLED_BACK")
        self.assertTrue(report["previous_pointer_restored"])
        self.assertEqual(os.readlink(str(self.private / "current")), old)
        self.assertEqual(hashlib.sha256((self.private / "current").read_bytes()).hexdigest(),
                         self.previous_sha)

    def test_unmanaged_current_regular_file_is_not_overwritten(self):
        current = self.private / "current"
        current.write_bytes(b"operator-private-file")
        with self.assertRaisesRegex(ValueError, "unmanaged_current_target_refused"):
            self.update()
        self.assertEqual(current.read_bytes(), b"operator-private-file")

    def test_current_escape_symlink_is_refused(self):
        (self.private / "current").symlink_to("../../outside-private-root")
        with self.assertRaisesRegex(ValueError, "unsafe_current_pointer_refused"):
            self.update()

    def test_current_artifact_digest_tampering_is_refused(self):
        self.update()
        stage = (self.private / "current").resolve()
        stage.chmod(0o700)
        stage.write_bytes(b"tampered staged executable")
        with self.assertRaisesRegex(ValueError, "current_artifact_hash_not_verified"):
            self.update()

    def test_nonprivate_root_is_refused(self):
        self.private.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private_owned_root_required"):
            self.update()

    def test_symlinked_root_is_refused(self):
        alias = self.base / "linked-release"
        alias.symlink_to(self.private, target_is_directory=True)
        fixture = self.signed()
        approval = self.intent(fixture)
        approval["root"] = str(alias)
        with self.assertRaisesRegex(ValueError, "private_absolute_root_required"):
            self.update(root=alias, fixture=fixture, intent=approval)

    def test_symlinked_versions_directory_refused_even_in_preview(self):
        (self.private / "versions").symlink_to(self.base, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "private_regular_versions_directory_required"):
            self.update(apply=False)

    def test_hardlinked_managed_active_binary_refused(self):
        self.update()
        original = (self.private / "current").resolve()
        os.link(str(original), str(self.base / "hardlink-to-active"))
        with self.assertRaisesRegex(ValueError, "signed_input_not_unique_bounded_file"):
            self.update()

    def test_symlinked_lock_is_refused(self):
        lock = self.private / ".binary-self-update-v27.lock"
        lock.symlink_to(self.base / "target")
        with self.assertRaises(OSError):
            self.update()
        self.assertFalse(os.path.lexists(str(self.private / "current")))

    def test_hardlinked_lock_is_refused(self):
        lock = self.private / ".binary-self-update-v27.lock"
        lock.write_bytes(b"lock-file")
        os.link(str(lock), str(self.base / "second-lock-link"))
        with self.assertRaisesRegex(ValueError, "unsafe_update_lock_file"):
            self.update()

    def test_concurrent_update_lock_fails_closed(self):
        lock = self.private / ".binary-self-update-v27.lock"
        lock.touch(mode=0o600)
        with lock.open("r+b") as descriptor:
            fcntl.flock(descriptor.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, "concurrent_binary_update_locked"):
                self.update()
        self.assertFalse(os.path.lexists(str(self.private / "current")))


if __name__ == "__main__":
    unittest.main()
