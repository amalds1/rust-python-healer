"""Actual OpenSSL Ed25519 fixtures, pinned local publisher and channel policy."""

import hashlib
import ctypes
from contextlib import closing
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("signed_release_v21", ROOT / "python" / "signed_release_policy_v21.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)
OPENSSL = (str(module.WINDOWS_OPENSSL_PROFILE) if os.name == "nt" and module.WINDOWS_OPENSSL_PROFILE.is_file()
           else shutil.which("openssl"))


@unittest.skipUnless(OPENSSL, "trusted OpenSSL CLI required for actual Ed25519 verification")
class SignedReleasePolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        if os.name == "nt":
            import windows_privacy_fixtures
            windows_privacy_fixtures.set_private_acl(self.root)
        self.secret = self.root / "trusted-ed25519-key.pem"
        self.public = self.root / "trusted-ed25519-pub.pem"
        self.ledger = self.root / "channel.sqlite"
        generated = subprocess.run([OPENSSL, "genpkey", "-algorithm", "ED25519",
                                    "-out", str(self.secret)], capture_output=True, check=False)
        self.assertEqual(generated.returncode, 0, generated.stderr)
        public = subprocess.run([OPENSSL, "pkey", "-in", str(self.secret), "-pubout",
                                 "-out", str(self.public)], capture_output=True, check=False)
        self.assertEqual(public.returncode, 0, public.stderr)
        fingerprint = subprocess.run([OPENSSL, "pkey", "-pubin", "-in", str(self.public),
                                      "-outform", "DER"], capture_output=True, check=False)
        self.assertEqual(fingerprint.returncode, 0, fingerprint.stderr)
        self.policy = {"schema_version": 1, "channels": {
            "stable": {"publisher_id": "trusted-fixture-publisher",
                       "public_key_der_sha256": hashlib.sha256(fingerprint.stdout).hexdigest(),
                       "allowed_kinds": ["binary", "plugin", "updater"],
                       "minimum_version": "0.21.0"}}}
        self.pem = self.public.read_bytes()

    def tearDown(self):
        self.tmp.cleanup()

    def signed(self, version="0.21.0", kind="binary", artifact=b"trusted-binary-content",
               channel="stable", publisher="trusted-fixture-publisher"):
        manifest = {"schema_version": 1, "publisher_id": publisher,
                    "channel": channel, "kind": kind, "version": version,
                    "artifact_name": "healer-artifact.bin", "artifact_sha256":
                    hashlib.sha256(artifact).hexdigest(), "artifact_bytes": len(artifact),
                    "python_minors": ["3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15"],
                    "signature_algorithm": "Ed25519"}
        canonical = module.canonical(manifest)
        input_file = self.root / "manifest.json"
        output_file = self.root / "manifest.sig"
        input_file.write_bytes(canonical)
        sign = subprocess.run([OPENSSL, "pkeyutl", "-sign", "-rawin",
                               "-inkey", str(self.secret), "-in", str(input_file),
                               "-out", str(output_file)], capture_output=True, check=False)
        self.assertEqual(sign.returncode, 0, sign.stderr)
        signature = output_file.read_bytes()
        self.assertEqual(len(signature), 64)
        return canonical, signature, artifact

    def verify(self, manifest, signature, artifact, policy=None, key=None):
        return module.verify_signed(policy if policy is not None else self.policy,
                                    manifest, signature, artifact,
                                    key if key is not None else self.pem, OPENSSL)

    def test_actual_detached_ed25519_signature_and_artifact_are_verified(self):
        manifest, signature, artifact = self.signed()
        report = self.verify(manifest, signature, artifact)
        self.assertEqual(report["status"], "LOCAL_PINNED_ED25519_SIGNATURE_VERIFIED")
        self.assertTrue(report["ed25519_signature_verified"])
        self.assertTrue(report["publisher_matched_operator_pin"])
        self.assertEqual(report["artifact_sha256"], hashlib.sha256(artifact).hexdigest())
        self.assertFalse(report["external_publisher_identity_verified"])
        self.assertFalse(report["binary_executed"])
        self.assertFalse(report["release_health_verified"])

    def test_openssl_independent_verifier_accepts_exact_signed_bytes(self):
        manifest, signature, artifact = self.signed()
        sigpath = self.root / "manifest.sig"
        msgpath = self.root / "manifest.json"
        # This check is performed by an independent OpenSSL process rather
        # than merely comparing our own SHA256 report values.
        verified = subprocess.run([OPENSSL, "pkeyutl", "-verify", "-pubin",
                                   "-rawin", "-inkey", str(self.public),
                                   "-sigfile", str(sigpath), "-in", str(msgpath)],
                                  capture_output=True, check=False)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(self.verify(manifest, signature, artifact)["kind"], "binary")

    def test_changed_manifest_bytes_including_version_are_not_authenticated(self):
        manifest, signature, artifact = self.signed()
        altered = json.loads(manifest)
        altered["version"] = "0.22.0"
        with self.assertRaisesRegex(ValueError, "ed25519_manifest_signature_invalid"):
            self.verify(module.canonical(altered), signature, artifact)

    def test_changed_artifact_bytes_cannot_pass_signed_sha256(self):
        manifest, signature, artifact = self.signed()
        with self.assertRaisesRegex(ValueError, "artifact_size_or_sha256_mismatch"):
            self.verify(manifest, signature, artifact + b"tamper")
        with self.assertRaisesRegex(ValueError, "artifact_size_or_sha256_mismatch"):
            self.verify(manifest, signature, b"t" * len(artifact))

    def test_wrong_ed25519_key_does_not_match_operator_pin(self):
        manifest, signature, artifact = self.signed()
        other_secret = self.root / "other-key.pem"
        other_public = self.root / "other-pub.pem"
        subprocess.run([OPENSSL, "genpkey", "-algorithm", "ED25519",
                        "-out", str(other_secret)], check=True, capture_output=True)
        subprocess.run([OPENSSL, "pkey", "-in", str(other_secret),
                        "-pubout", "-out", str(other_public)], check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, "publisher_public_key_pin_mismatch"):
            self.verify(manifest, signature, artifact, key=other_public.read_bytes())

    def test_valid_signature_by_different_key_fails_pinned_publisher(self):
        manifest, signature, artifact = self.signed()
        altered = dict(self.policy)
        altered["channels"] = {"stable": dict(self.policy["channels"]["stable"])}
        altered["channels"]["stable"]["public_key_der_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "publisher_public_key_pin_mismatch"):
            self.verify(manifest, signature, artifact, policy=altered)

    def test_channel_and_artifact_kind_are_operator_allowlisted(self):
        for changed in (dict(self.policy["channels"]["stable"], allowed_kinds=["binary"]),):
            manifest, signature, artifact = self.signed(kind="plugin")
            policy = {"schema_version": 1, "channels": {"stable": changed}}
            with self.assertRaisesRegex(ValueError, "publisher_channel_or_kind_not_allowlisted"):
                self.verify(manifest, signature, artifact, policy=policy)
        manifest, signature, artifact = self.signed(channel="preview")
        with self.assertRaisesRegex(ValueError, "publisher_channel_or_kind_not_allowlisted"):
            self.verify(manifest, signature, artifact)

    def test_signed_manifest_wrong_publisher_id_cannot_bypass_pin(self):
        manifest, signature, artifact = self.signed(publisher="attacker")
        with self.assertRaisesRegex(ValueError, "publisher_id_not_pinned"):
            self.verify(manifest, signature, artifact)

    def test_forged_rsa_key_is_not_accepted_as_ed25519(self):
        manifest, signature, artifact = self.signed()
        private = self.root / "rsa.key"
        public = self.root / "rsa.pub"
        subprocess.run([OPENSSL, "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:2048", "-out", str(private)], check=True, capture_output=True)
        subprocess.run([OPENSSL, "pkey", "-in", str(private), "-pubout",
                        "-out", str(public)], check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, "ed25519_public_key_required"):
            self.verify(manifest, signature, artifact, key=public.read_bytes())

    def test_signed_old_release_below_pinned_minimum_is_rejected(self):
        manifest, signature, artifact = self.signed(version="0.20.9")
        with self.assertRaisesRegex(ValueError, "release_below_pinned_minimum_version"):
            self.verify(manifest, signature, artifact)

    def test_channel_registers_valid_signed_binary_plugin_and_updater(self):
        for kind, version in (("binary", "0.21.0"), ("plugin", "0.21.0"),
                              ("updater", "0.21.0")):
            manifest, signature, artifact = self.signed(version=version, kind=kind)
            result = module.record_channel(self.ledger, self.policy, manifest,
                                           signature, artifact, self.pem, OPENSSL)
            self.assertTrue(result["release_recorded"])
            self.assertEqual(result["verified_release"]["kind"], kind)
        with closing(sqlite3.connect(str(self.ledger))) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM channel_state").fetchone()[0], 3)

    def test_rollback_or_same_version_different_contents_rejected(self):
        first = self.signed(version="0.21.0")
        module.record_channel(self.ledger, self.policy, *first, self.pem, OPENSSL)
        newer = self.signed(version="0.22.0")
        module.record_channel(self.ledger, self.policy, *newer, self.pem, OPENSSL)
        with self.assertRaisesRegex(ValueError, "release_downgrade_or_same_version_content_change_refused"):
            module.record_channel(self.ledger, self.policy, *first, self.pem, OPENSSL)
        modified = self.signed(version="0.22.0", artifact=b"different content same version")
        with self.assertRaisesRegex(ValueError, "release_downgrade_or_same_version_content_change_refused"):
            module.record_channel(self.ledger, self.policy, *modified, self.pem, OPENSSL)
        with closing(sqlite3.connect(str(self.ledger))) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM channel_history").fetchone()[0], 2)

    def test_same_signed_release_idempotently_deduplicates(self):
        fixture = self.signed()
        first = module.record_channel(self.ledger, self.policy, *fixture, self.pem, OPENSSL)
        second = module.record_channel(self.ledger, self.policy, *fixture, self.pem, OPENSSL)
        self.assertTrue(first["release_recorded"])
        self.assertEqual(second["status"], "ALREADY_RECORDED_NO_NEW_RELEASE")
        with closing(sqlite3.connect(str(self.ledger))) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM channel_history").fetchone()[0], 1)

    def test_signature_must_pass_again_during_channel_recording(self):
        manifest, _signature, artifact = self.signed()
        with self.assertRaisesRegex(ValueError, "ed25519_manifest_signature_invalid"):
            module.record_channel(self.ledger, self.policy, manifest, b"0" * 64,
                                  artifact, self.pem, OPENSSL)
        self.assertFalse(self.ledger.exists())

    def test_noncanonical_manifest_json_and_duplicate_keys_rejected(self):
        manifest, signature, artifact = self.signed()
        with self.assertRaisesRegex(ValueError, "manifest_must_use_canonical_signed_encoding"):
            self.verify(manifest + b"\n", signature, artifact)
        with self.assertRaisesRegex(ValueError, "duplicate_signed_json_key"):
            module.strict_json(b'{"version":"0.21.0","version":"0.22.0"}')

    def test_symlink_hardlink_oversized_inputs_not_treated_as_signed(self):
        path = self.root / "artifact.bin"
        path.write_bytes(b"safe")
        link = self.root / "artifact-link.bin"
        link.symlink_to(path)
        with self.assertRaisesRegex(ValueError, "signed_input_symlink_refused"):
            module.checked_regular(link, module.MAX_ARTIFACT)
        other = self.root / "artifact-hard.bin"
        os.link(path, other)
        with self.assertRaisesRegex(ValueError, "signed_input_not_unique_bounded_file"):
            module.checked_regular(path, module.MAX_ARTIFACT)
        other.unlink()
        with self.assertRaisesRegex(ValueError, "signed_input_not_unique_bounded_file"):
            module.checked_regular(path, 2)

    def test_cli_is_read_only_without_record_and_no_binary_execution(self):
        _manifest, _signature, artifact = self.signed()
        policy_path = self.root / "policy.json"
        policy_path.write_bytes(module.canonical(self.policy))
        artifact_path = self.root / "artifact.bin"
        artifact_path.write_bytes(artifact)
        command = [sys.executable, "-I", "-S", "-B"] + (
            [str(ROOT / "python" / "signed_release_policy_v21.py")] if os.name == "nt" else
            ["-c", (ROOT / "python" / "signed_release_policy_v21.py").read_text()]) + [
                   "--policy", str(policy_path), "--public-key", str(self.public),
                   "--manifest", str(self.root / "manifest.json"),
                   "--signature", str(self.root / "manifest.sig"),
                   "--artifact", str(artifact_path), "--openssl", OPENSSL]
        proc = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertTrue(report["ed25519_signature_verified"])
        self.assertFalse(report["binary_executed"])
        self.assertFalse(report["external_publisher_identity_verified"])
        self.assertFalse(self.ledger.exists())

    def test_signed_local_atomic_pointer_switch_never_executes_artifact(self):
        manifest, signature, artifact = self.signed()
        private = self.root / "private-releases"
        private.mkdir(mode=0o700)
        report = module.local_stage_and_swap(
            private, self.policy, manifest, signature, artifact, self.pem, OPENSSL)
        self.assertEqual(report["status"], "SIGNED_LOCAL_POINTER_SWITCHED_NOT_EXECUTION_QUALIFIED")
        self.assertTrue((private / "current").is_symlink())
        self.assertEqual((private / "current").read_bytes(), artifact)
        self.assertFalse(report["binary_executed"])
        self.assertFalse(report["release_health_verified"])
        self.assertFalse(report["external_publisher_identity_verified"])

    def test_new_signed_version_switches_pointer_but_preserves_old_binary(self):
        private = self.root / "private-releases"
        private.mkdir(mode=0o700)
        first = self.signed("0.21.0")
        module.local_stage_and_swap(private, self.policy, *first, self.pem, OPENSSL)
        original = os.readlink(private / "current")
        later = self.signed("0.22.0", artifact=b"new verified fixture binary")
        switched = module.local_stage_and_swap(private, self.policy, *later, self.pem, OPENSSL)
        self.assertNotEqual(os.readlink(private / "current"), original)
        self.assertEqual((private / "current").read_bytes(), later[2])
        self.assertEqual((private / original).read_bytes(), first[2])
        self.assertTrue(switched["previous_pointer_present"])

    def test_failure_after_switch_rolls_back_existing_pointer_without_binary_execution(self):
        private = self.root / "private-releases"
        private.mkdir(mode=0o700)
        first = self.signed("0.21.0")
        module.local_stage_and_swap(private, self.policy, *first, self.pem, OPENSSL)
        old_target = os.readlink(private / "current")
        later = self.signed("0.22.0", artifact=b"unhealthy stage scenario")
        result = module.local_stage_and_swap(
            private, self.policy, *later, self.pem, OPENSSL,
            force_post_switch_failure_for_test=True)
        self.assertEqual(result["status"], "LOCAL_POINTER_ROLLED_BACK_AFTER_POST_SWITCH_FAILURE")
        self.assertTrue(result["rollback_pointer_restored"])
        self.assertEqual(os.readlink(private / "current"), old_target)
        self.assertEqual((private / "current").read_bytes(), first[2])
        self.assertFalse(result["binary_executed"])

    def test_failed_replace_before_pointer_switch_reports_no_rollback(self):
        private = self.root / "private-releases"
        private.mkdir(mode=0o700)
        first = self.signed("0.21.0")
        module.local_stage_and_swap(private, self.policy, *first, self.pem, OPENSSL)
        original_pointer = os.readlink(private / "current")
        later = self.signed("0.22.0", artifact=b"valid staged update")
        with mock.patch.object(module.os, "replace", side_effect=OSError("injected")):
            result = module.local_stage_and_swap(private, self.policy, *later, self.pem, OPENSSL)
        self.assertEqual(result["status"], "LOCAL_POINTER_SWITCH_FAILED_NO_CHANGE")
        self.assertFalse(result["rollback_pointer_restored"])
        self.assertFalse(result["atomic_pointer_switch"])
        self.assertEqual(os.readlink(private / "current"), original_pointer)
        self.assertEqual(list(private.glob(".pending-*")), [])

    def test_staged_previous_release_mutation_blocks_pointer_swap(self):
        private = self.root / "private-releases"
        private.mkdir(mode=0o700)
        initial = self.signed("0.21.0")
        module.local_stage_and_swap(private, self.policy, *initial, self.pem, OPENSSL)
        old_pointer = os.readlink(private / "current")
        (private / old_pointer).write_bytes(b"tampered after stage")
        newer = self.signed("0.22.0", artifact=b"good new bytes")
        with self.assertRaisesRegex(ValueError, "previous_release_stage_content_changed"):
            module.local_stage_and_swap(private, self.policy, *newer, self.pem, OPENSSL)
        self.assertEqual(os.readlink(private / "current"), old_pointer)

    def test_pointer_downgrade_and_same_version_changed_artifact_are_refused(self):
        private = self.root / "private-releases"
        private.mkdir(mode=0o700)
        latest = self.signed("0.22.0")
        module.local_stage_and_swap(private, self.policy, *latest, self.pem, OPENSSL)
        original = os.readlink(private / "current")
        with self.assertRaisesRegex(ValueError, "signed_release_pointer_downgrade_refused"):
            module.local_stage_and_swap(private, self.policy, *self.signed("0.21.0"),
                                        self.pem, OPENSSL)
        with self.assertRaisesRegex(ValueError, "signed_same_version_artifact_change_refused"):
            module.local_stage_and_swap(private, self.policy,
                                        *self.signed("0.22.0", artifact=b"new same-version bits"),
                                        self.pem, OPENSSL)
        self.assertEqual(os.readlink(private / "current"), original)

    def test_reused_signed_stage_is_idempotent_and_not_executed(self):
        private = self.root / "private-releases"
        private.mkdir(mode=0o700)
        fixture = self.signed()
        module.local_stage_and_swap(private, self.policy, *fixture, self.pem, OPENSSL)
        same = module.local_stage_and_swap(private, self.policy, *fixture, self.pem, OPENSSL)
        self.assertEqual(same["status"], "SIGNED_POINTER_ALREADY_ACTIVE_NOT_EXECUTED")
        self.assertFalse(same["atomic_pointer_switch"])

    def test_unsigned_stage_cannot_write_versions_or_current(self):
        private = self.root / "private-releases"
        private.mkdir(mode=0o700)
        manifest, _signature, artifact = self.signed()
        with self.assertRaisesRegex(ValueError, "ed25519_manifest_signature_invalid"):
            module.local_stage_and_swap(private, self.policy, manifest, b"0" * 64,
                                        artifact, self.pem, OPENSSL)
        self.assertFalse((private / "versions").exists())
        self.assertFalse((private / "current").exists())

    def test_nonprivate_release_root_cannot_be_modified(self):
        private = self.root / "public-releases"
        private.mkdir(mode=0o755)
        if os.name == "nt":
            import windows_privacy_fixtures
            windows_privacy_fixtures.set_public_read_acl(private)
        fixture = self.signed()
        with self.assertRaisesRegex(ValueError, "release_swap_root_must_be_private"):
            module.local_stage_and_swap(private, self.policy, *fixture, self.pem, OPENSSL)
        self.assertFalse((private / "versions").exists())

    def test_current_regular_file_is_not_overwritten(self):
        private = self.root / "private-releases"
        private.mkdir(mode=0o700)
        (private / "current").write_text("existing arbitrary file")
        fixture = self.signed()
        with self.assertRaisesRegex(ValueError, "refuse_to_overwrite_existing_current_regular_file"):
            module.local_stage_and_swap(private, self.policy, *fixture, self.pem, OPENSSL)
        self.assertEqual((private / "current").read_text(), "existing arbitrary file")

    def test_previous_pointer_outside_private_versions_is_refused(self):
        private = self.root / "private-releases"
        private.mkdir(mode=0o700)
        (private / "current").symlink_to(self.root / "trusted-ed25519-key.pem")
        fixture = self.signed()
        with self.assertRaisesRegex(ValueError, "previous_release_pointer_untrusted"):
            module.local_stage_and_swap(private, self.policy, *fixture, self.pem, OPENSSL)

    def test_version_directory_symlink_is_rejected(self):
        private = self.root / "private-releases"
        private.mkdir(mode=0o700)
        (private / "versions").symlink_to(self.root, target_is_directory=True)
        fixture = self.signed()
        with self.assertRaisesRegex(ValueError, "release_versions_symlink_refused"):
            module.local_stage_and_swap(private, self.policy, *fixture, self.pem, OPENSSL)

    @unittest.skipUnless(os.name == "nt", "Native Windows mutation-directory lease")
    def test_windows_root_versions_pinned_but_own_child_rename_allowed(self):
        private = self.root / "private-held"
        private.mkdir()
        with module._windows_swap_lease(private):
            versions = private / "versions"
            for path in (private, versions):
                before = path.stat()
                with self.subTest(path=path.name):
                    with self.assertRaises(OSError) as rejected:
                        os.rename(path, path.with_name("moved-" + path.name))
                    self.assertIn(rejected.exception.winerror, (5, 32))
                    after = path.stat()
                    self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
            pending = private / "own-data-pending"
            pending.write_bytes(b"fixed-non-executable-fixture")
            os.replace(pending, private / "own-data-current")
            self.assertEqual((private / "own-data-current").read_bytes(), b"fixed-non-executable-fixture")
        # Demonstrate that the refusal was the held native lease, not an ACL
        # fixture that would reject these owner operations even without it.
        for path in (private / "versions", private):
            moved = path.with_name("moved-" + path.name)
            os.rename(path, moved)
            os.rename(moved, path)

    @unittest.skipUnless(os.name == "nt", "Native Windows OpenSSL environment")
    def test_windows_tool_config_environment_cannot_load_caller_provider(self):
        manifest, signature, artifact = self.signed()
        config = self.root / "bad-caller-openssl.cnf"
        config.write_text("openssl_conf = absent_provider_configuration\n", encoding="ascii")
        real_run = subprocess.run
        observed = []
        blocked_writes = []
        def actual_openssl_run(*args, **kwargs):
            observed.append(kwargs.get("env"))
            command = args[0]
            if "-verify" in command:
                for flag in ("-inkey", "-in", "-sigfile"):
                    target = Path(command[command.index(flag) + 1])
                    kernel, _ = module._windows_helper("privacy")._libraries()
                    handle = kernel.CreateFileW(str(target), 0x40000000, 7, None, 3, 0x00200000, None)
                    error = ctypes.get_last_error()
                    if handle not in (None, ctypes.c_void_p(-1).value):
                        kernel.CloseHandle(handle)
                        self.fail("verifier input permitted a concurrent write handle")
                    self.assertEqual(error, 32)
                    blocked_writes.append(flag)
            return real_run(*args, **kwargs)
        with mock.patch.dict(os.environ, {"OPENSSL_CONF": str(config), "OPENSSL_MODULES": "C:/rph_absent_provider", "OPENSSL_ENGINES": "C:/rph_absent_engine", "RPH_SECRET": "fixed-marker"}), \
                mock.patch.object(module.subprocess, "run", side_effect=actual_openssl_run):
            result = self.verify(manifest, signature, artifact)
        self.assertTrue(result["ed25519_signature_verified"])
        self.assertGreaterEqual(len(observed), 3)
        self.assertEqual(set(blocked_writes), {"-inkey", "-in", "-sigfile"})
        for environment in observed:
            self.assertEqual(environment["OPENSSL_CONF"], os.devnull)
            self.assertNotIn("OPENSSL_MODULES", environment)
            self.assertNotIn("OPENSSL_ENGINES", environment)
            self.assertNotIn("RPH_SECRET", environment)

    @unittest.skipUnless(os.name == "nt", "Native Windows unique private ledger")
    def test_windows_ledger_handle_pins_leaf_and_rejects_hardlink(self):
        with closing(module.open_ledger(self.ledger)) as connection:
            connection.execute("CREATE TABLE fixed_probe(value INTEGER)")
            with self.assertRaises(OSError) as rejected:
                os.rename(self.ledger, self.root / "moved-ledger.sqlite")
            self.assertEqual(rejected.exception.winerror, 32)
        hardlink = self.root / "ledger-alias.sqlite"
        os.link(self.ledger, hardlink)
        with self.assertRaisesRegex(ValueError, "release_channel_ledger_refused"):
            module.open_ledger(self.ledger)
        hardlink.unlink()

    @unittest.skipUnless(os.name == "nt", "Installed operator OpenSSL profile pin")
    def test_windows_changed_or_foreign_openssl_profile_refused_before_execution(self):
        with self.assertRaisesRegex(ValueError, "installed_operator_openssl_profile_required"):
            module.open_ssl(str(self.secret))
        with mock.patch.object(module, "WINDOWS_OPENSSL_LOCAL_SHA256", "0" * 64), \
                mock.patch.object(module.subprocess, "run", side_effect=AssertionError("changed_tool_must_not_start")):
            with self.assertRaisesRegex(ValueError, "installed_operator_openssl_hash_changed"):
                module.open_ssl(OPENSSL)


if __name__ == "__main__":
    unittest.main()
