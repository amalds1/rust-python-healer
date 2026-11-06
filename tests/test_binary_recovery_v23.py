"""Real pinned release executable canary, atomic activation and rollback."""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPENSSL = shutil.which("openssl")
BINARY = ROOT / "target" / "release" / ("rust-python-healer.exe" if sys.platform == "win32" else "rust-python-healer")
PRIOR_BINARY = ROOT / "dist" / "prior-v0.22" / "rust-python-healer"
SIGNED_SPEC = spec_from_file_location("signed_release_policy_v21", ROOT / "python" /
                                     "signed_release_policy_v21.py")
SIGNED = module_from_spec(SIGNED_SPEC)
SIGNED_SPEC.loader.exec_module(SIGNED)

sys.path.insert(0, str(ROOT / "python"))
from binary_recovery_v23 import rollout  # noqa: E402


@unittest.skipUnless(OPENSSL and BINARY.is_file() and PRIOR_BINARY.is_file(),
                     "real trusted two-release Rust binaries and openssl required")
class BinaryRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="rph-real-binary-")
        self.root = Path(self.tmp.name)
        self.private = self.root / "release"
        self.private.mkdir(mode=0o700)
        self.secret = self.root / "key.pem"
        self.public = self.root / "public.pem"
        subprocess.run([OPENSSL, "genpkey", "-algorithm", "ED25519", "-out",
                        str(self.secret)], check=True, capture_output=True)
        subprocess.run([OPENSSL, "pkey", "-in", str(self.secret), "-pubout",
                        "-out", str(self.public)], check=True, capture_output=True)
        der = subprocess.run([OPENSSL, "pkey", "-pubin", "-in", str(self.public),
                              "-outform", "DER"], capture_output=True, check=True).stdout
        self.policy = {"schema_version": 1, "channels": {"stable": {
            "publisher_id": "local-operator", "allowed_kinds": ["binary"],
            "minimum_version": "0.1.0", "public_key_der_sha256": hashlib.sha256(der).hexdigest()}}}
        self.artifact = BINARY.read_bytes()
        self.sha = hashlib.sha256(self.artifact).hexdigest()
        version_output = subprocess.run([str(BINARY), "--version"], capture_output=True,
                                        check=True, timeout=4).stdout.decode("ascii").strip()
        self.version = version_output.split(" ", 1)[1]
        self.previous_artifact = PRIOR_BINARY.read_bytes()
        self.previous_sha = hashlib.sha256(self.previous_artifact).hexdigest()
        older_version_output = subprocess.run([str(PRIOR_BINARY), "--version"],
                                              capture_output=True, check=True,
                                              timeout=4).stdout.decode("ascii").strip()
        self.previous_version = older_version_output.split(" ", 1)[1]
        self.assertLess(SIGNED.version_parts(self.previous_version),
                        SIGNED.version_parts(self.version))
        self.public_bytes = self.public.read_bytes()

    def tearDown(self):
        self.tmp.cleanup()

    def signed(self, version=None, artifact=None, kind="binary"):
        version = version or self.version
        artifact = artifact if artifact is not None else self.artifact
        manifest = {"schema_version": 1, "publisher_id": "local-operator",
                    "channel": "stable", "kind": kind, "version": version,
                    "artifact_name": "rust-python-healer", "artifact_sha256":
                    hashlib.sha256(artifact).hexdigest(), "artifact_bytes": len(artifact),
                    "signature_algorithm": "Ed25519",
                    "python_minors": ["3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15"]}
        encoded = SIGNED.canonical(manifest)
        msg = self.root / "message.json"
        sig = self.root / "message.sig"
        msg.write_bytes(encoded)
        subprocess.run([OPENSSL, "pkeyutl", "-sign", "-rawin", "-inkey",
                        str(self.secret), "-in", str(msg), "-out", str(sig)],
                       capture_output=True, check=True)
        return encoded, sig.read_bytes(), artifact

    def deploy(self, fixture=None, sha=None, **kwargs):
        return rollout(self.private, self.policy, *(fixture or self.signed()),
                       self.public_bytes, self.sha if sha is None else sha,
                       OPENSSL, **kwargs)

    def test_real_rust_canary_executes_then_atomically_activates(self):
        report = self.deploy()
        self.assertEqual(report["status"], "APPROVED_SIGNED_BINARY_CANARY_ACTIVE")
        self.assertTrue(report["binary_executed"])
        self.assertEqual(subprocess.check_output([str(self.private / "current"), "--version"],
                         timeout=4).decode().strip(), "rust-python-healer " + self.version)
        self.assertEqual((self.private / "current").stat().st_mode & 0o777, 0o500)

    def test_approved_same_release_idempotent(self):
        self.deploy()
        second = self.deploy()
        self.assertEqual(second["status"], "APPROVED_SIGNED_BINARY_ALREADY_ACTIVE")
        self.assertFalse(second["changed"])

    def test_sha256_out_of_band_gate_refuses_unapproved_binary(self):
        with self.assertRaisesRegex(ValueError, "out_of_band_sha256_allowlist"):
            self.deploy(sha="0" * 64)
        self.assertFalse((self.private / "current").exists())

    def test_wrong_ed25519_signature_prevents_binary_execution(self):
        manifest, _sig, artifact = self.signed()
        with self.assertRaisesRegex(ValueError, "ed25519_manifest_signature_invalid"):
            self.deploy((manifest, b"!" * 64, artifact))
        self.assertFalse((self.private / "current").exists())

    def test_forged_publisher_key_pin_fails_closed(self):
        self.policy["channels"]["stable"]["public_key_der_sha256"] = "a" * 64
        with self.assertRaisesRegex(ValueError, "publisher_public_key_pin_mismatch"):
            self.deploy()

    def test_wrong_signed_kind_refused(self):
        with self.assertRaisesRegex(ValueError, "channel_or_kind_not_allowlisted"):
            self.deploy(self.signed(kind="plugin"))

    def test_non_rust_signed_data_not_executed_even_if_hash_pinned(self):
        other = b"this file is signed data; not a binary"
        report = self.deploy(self.signed(artifact=other), hashlib.sha256(other).hexdigest())
        self.assertEqual(report["status"], "BINARY_CANARY_REFUSED_NO_MUTATION")
        self.assertFalse((self.private / "current").exists())

    def test_signed_wrong_runtime_version_fails_canary(self):
        report = self.deploy(self.signed(version="9.99.1"))
        self.assertEqual(report["status"], "BINARY_CANARY_REFUSED_NO_MUTATION")
        self.assertFalse((self.private / "current").exists())

    def test_real_post_commit_failure_restores_old_pointer(self):
        self.deploy(self.signed(version=self.previous_version,
                                artifact=self.previous_artifact), sha=self.previous_sha)
        old_pointer = os.readlink(self.private / "current")
        result = self.deploy(inject_post_switch_failure=True)
        self.assertEqual(result["status"], "BINARY_POST_COMMIT_ROLLED_BACK")
        self.assertTrue(result["previous_pointer_restored"])
        self.assertEqual(os.readlink(self.private / "current"), old_pointer)
        self.assertEqual(subprocess.check_output([str(self.private / "current"), "--version"],
                         timeout=4).decode().strip(),
                         "rust-python-healer " + self.previous_version)

    def test_real_second_release_commits_and_downgrade_refused(self):
        self.deploy(self.signed(version=self.previous_version,
                                artifact=self.previous_artifact), sha=self.previous_sha)
        report = self.deploy()
        self.assertEqual(report["status"], "APPROVED_SIGNED_BINARY_CANARY_ACTIVE")
        self.assertTrue(report["previous_version_preserved"])
        with self.assertRaisesRegex(ValueError, "binary_rollout_downgrade_refused"):
            self.deploy(self.signed(version=self.previous_version,
                                    artifact=self.previous_artifact), sha=self.previous_sha)

    def test_real_post_commit_injection_rolls_back_first_install(self):
        report = self.deploy(inject_post_switch_failure=True)
        self.assertEqual(report["status"], "BINARY_POST_COMMIT_ROLLED_BACK")
        self.assertTrue(report["previous_pointer_restored"])
        self.assertFalse((self.private / "current").is_symlink())

    def test_managed_private_root_required(self):
        self.private.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private"):
            self.deploy()

    def test_existing_current_regular_file_is_never_overwritten(self):
        (self.private / "current").write_bytes(b"private user file")
        with self.assertRaisesRegex(ValueError, "managed_symlink"):
            self.deploy()
        self.assertEqual((self.private / "current").read_bytes(), b"private user file")

    def test_repoint_to_unverified_relative_path_rejected(self):
        (self.private / "current").symlink_to("../../attacker")
        with self.assertRaisesRegex(ValueError, "old_pointer_not_trusted"):
            self.deploy()

    def test_existing_staged_binary_tamper_rejected(self):
        self.deploy()
        stage = (self.private / "current").resolve()
        stage.chmod(0o700)
        stage.write_bytes(b"tampered local executable")
        with self.assertRaisesRegex(ValueError, "binary_stage_modified"):
            self.deploy()

    def test_out_of_band_hash_must_be_valid_sha256(self):
        with self.assertRaisesRegex(ValueError, "independent_approved_binary_sha256_required"):
            self.deploy(sha="not-a-sha256")


if __name__ == "__main__":
    unittest.main()
