"""Cross-application safety checks on actual local Rust/CPython processes.

All five requested F-ID areas have positive and negative tests.  Local test
coverage does NOT turn partial global product requirements into a PASS.
"""

from contextlib import closing
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "python" / "security_integrations_v23.py"
spec = importlib.util.spec_from_file_location("security_integrations_v23", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RustCliBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.binary = ROOT / "target" / "release" / ("rust-python-healer.exe" if sys.platform == "win32" else "rust-python-healer")
        if not self.binary.is_file():
            self.fail("release Rust CLI unavailable: do not claim all-command verification")
        self.pin = hashlib.sha256(self.binary.read_bytes()).hexdigest()

    def test_every_real_top_level_rust_command_help_invoked_and_redacted(self):
        proof = module.probe_all_rust_cli_help(self.binary, self.pin)
        self.assertEqual(proof["status"], "TRUSTED_HELP_SURFACE_AUDITED_ONLY")
        self.assertEqual(proof["top_level_checked"], 21)
        self.assertTrue(proof["all_top_level_help_passed"])
        self.assertGreaterEqual(proof["lab_tools_enumerated_not_executed"], 24)
        self.assertFalse(proof["full_cli_secret_redaction_qualified"])
        for entry in proof["help_log_evidence"].values():
            self.assertFalse(entry["raw_strings_disclosed"])
            self.assertEqual(entry["returncode_class"], "ZERO")

    def test_unknown_or_tampered_rust_binary_is_refused(self):
        with self.assertRaisesRegex(module.CrossApplicationRejected, "PIN_MISMATCH"):
            module.probe_all_rust_cli_help(self.binary, "f" * 64)

    def test_symlinked_fake_cli_cannot_be_launched(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-cli-") as folder:
            fake = Path(folder) / "link"
            fake.symlink_to(self.binary)
            with self.assertRaisesRegex(module.CrossApplicationRejected, "UNSAFE"):
                module.probe_all_rust_cli_help(fake, self.pin)

    def test_actual_cli_non_approval_actions_fail_closed_in_gateway(self):
        for unsafe in ("repair", "update", "catalog", "lab"):
            with self.subTest(unsafe=unsafe):
                summary = module.classify_rust_cli_action([unsafe, "--help"])
                self.assertEqual(summary["status"], "RISKY_REQUIRES_HUMAN_APPROVAL")
                self.assertFalse(summary["allowed_to_execute"])
                self.assertFalse(summary["human_approval_enforced_in_original_binary"])

    def test_each_known_read_only_command_remains_not_executed(self):
        for name in module.EXPECTED_TOP_LEVEL - module.RISKY_TOP_LEVEL:
            with self.subTest(name=name):
                report = module.classify_rust_cli_action([name])
                self.assertFalse(report["allowed_to_execute"])
                self.assertEqual(report["command"], name)

    def test_new_command_requires_manual_policy_review(self):
        with self.assertRaisesRegex(module.CrossApplicationRejected, "UNREGISTERED"):
            module.classify_rust_cli_action(["new-secret-command", "--mutate"])

    def test_pinned_cli_output_disallows_opaque_attacker_fields(self):
        output = (b"Bearer SUPER_SECRET_TOKEN\nPrivate mail: me@example.invalid\n"
                  b"Traceback at /secret/path/file.py\nprivate source text")
        report = module.redact_process_result(output, b"PRIVATE_ERROR_MESSAGE", 1, "scan")
        encoded = json.dumps(report)
        for secret in ("SUPER_SECRET", "example.invalid", "/secret/path",
                       "private source text", "PRIVATE_ERROR_MESSAGE"):
            self.assertNotIn(secret, encoded)
        self.assertEqual(report["returncode_class"], "NONZERO")
        self.assertFalse(report["full_rust_cli_log_privacy_proven"])

    def test_missing_stdout_budget_or_unlisted_command_is_rejected(self):
        with self.assertRaises(module.CrossApplicationRejected):
            module.redact_process_result(b"x" * (module.MAX_OUTPUT_BYTES + 1), b"", 0,
                                         "scan")
        with self.assertRaises(module.CrossApplicationRejected):
            module.redact_process_result(b"secret", b"", 0, "sk-private-value")

    def test_cli_surface_mode_is_real_json_and_rejects_missing_pin(self):
        command = [sys.executable, "-I", "-S", "-B", str(SOURCE),
                   "--mode", "surface", "--binary", str(self.binary),
                   "--trusted-sha256", self.pin]
        result = subprocess.run(command, capture_output=True, check=False, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["top_level_checked"], 21)
        invalid = subprocess.run(command[:-2], capture_output=True,
                                 check=False, timeout=8)
        self.assertEqual(invalid.returncode, 2)
        self.assertEqual(json.loads(invalid.stdout)["status"], "NOT_VERIFIED")


class ToolAndModelBoundaryTests(unittest.TestCase):
    def test_actual_child_tool_injection_is_data_only_and_hashed(self):
        report = module.run_trusted_hostile_tool_probe(sys.executable)
        self.assertEqual(report["status"], "HOSTILE_TOOL_BYTES_QUARANTINED_DATA_ONLY")
        self.assertTrue(report["source_was_separate_real_subprocess"])
        self.assertFalse(report["proposed_tool_calls_executed"])
        self.assertFalse(report["raw_tool_text_emitted"])
        self.assertTrue(report["no_real_model_redteam_proven"])

    def test_real_tool_data_cannot_sign_operator_approval(self):
        tool = module.run_trusted_hostile_tool_probe(sys.executable)
        with self.assertRaises(module.CrossApplicationRejected):
            module.verify_operator_model_boundary(tool, "0" * 64, b"operator-secret-key-len-32-or-more")

    def test_distinct_key_and_sha_bound_readonly_review_only(self):
        tool = module.run_trusted_hostile_tool_probe(sys.executable)
        key = b"operator-secret-key-len-32-or-more"
        claim = {"action": "READ_ONLY_REVIEW", "source_sha256": tool["source_sha256"]}
        signature = hmac.new(key, module._canonical(claim), hashlib.sha256).hexdigest()
        report = module.verify_operator_model_boundary(tool, signature, key)
        self.assertEqual(report["status"], "INDEPENDENT_OPERATOR_READ_ONLY_REVIEW_GRANTED")
        self.assertFalse(report["tool_execution_permitted"])
        self.assertFalse(report["release_permitted"])
        self.assertFalse(report["external_llm_verified"])

    def test_forged_tool_claim_cannot_grant_review(self):
        tool = module.run_trusted_hostile_tool_probe(sys.executable)
        bad = dict(tool, status="TOOL_OUTPUT_DIRECTIVE_ACCEPTED")
        with self.assertRaises(module.CrossApplicationRejected):
            module.verify_operator_model_boundary(bad, "f" * 64,
                                                  b"operator-secret-key-len-32-or-more")

    def test_unknown_tool_action_is_denied_even_with_operator_key(self):
        key = b"operator-secret-key-len-32-or-more"
        with self.assertRaises(module.CrossApplicationRejected):
            module._verify_operator_policy("EXECUTE_SOURCE", "f" * 64, "0" * 64, key)

    def test_tool_boundary_cli_uses_isolated_python_without_execution_claim(self):
        completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE)],
                                   capture_output=True, check=False, timeout=8)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertFalse(report["proposed_tool_calls_executed"])


class HumanApprovalAndRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rph-v23-integrated-canary-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.active = self.folder / "active.json"
        self.candidate = self.folder / "candidate.json"
        self.before = json.dumps({"release": "old", "health": "ready"},
                                 sort_keys=True).encode("utf-8")
        self.after = json.dumps({"release": "new", "health": "ready"},
                                sort_keys=True).encode("utf-8")
        self.active.write_bytes(self.before)
        self.candidate.write_bytes(self.after)
        self.actor = "local-requester"
        self.key = b"0123456789abcdef0123456789abcdef"
        self.human_key = {"schema_version": 1, "key_hex": self.key.hex()}
        self.canary_key = b"private-local-canary-signature-key"
        self.manifest = {"schema": 1, "operation": "local_canary",
                         "actor": "fixture-reviewer", "release": "new",
                         "old_sha256": hashlib.sha256(self.before).hexdigest(),
                         "candidate_sha256": hashlib.sha256(self.after).hexdigest()}
        self.release_api = module._trusted_local_module("release_canary_v21")
        self.human_api = module._trusted_local_module("human_approval")
        self.canary_signature = self.release_api.canary_signature(self.manifest,
                                                                  self.canary_key)
        self.ledger = self.folder / "approvals.sqlite"
        self.moment = int(time.time())
        self.token = {"schema_version": 1, "policy_id": "human-v1",
                      "nonce": "c" * 32, "issued_at": self.moment - 5,
                      "expires_at": self.moment + 60,
                      "actor_id": self.actor, "approver_id": "independent-local-approver",
                      "action": "BINARY_RELEASE",
                      "artifact_sha256": self.manifest["candidate_sha256"],
                      "target_sha256": self.manifest["old_sha256"]}
        self.token["signature"] = self.human_api.sign_for_test(self.token, self.human_key)

    def invoke(self, **options):
        return module.authorized_local_canary(
            self.ledger, self.token, self.human_key, self.actor, self.active,
            self.candidate, self.manifest, self.canary_signature, self.canary_key,
            now=self.moment, **options)

    def test_actual_one_use_approved_canary_changes_only_private_fixture_state(self):
        report = self.invoke()
        self.assertEqual(report["status"], "APPROVAL_GATED_LOCAL_CANARY_REHEARSAL")
        self.assertTrue(report["approval_consumed"])
        self.assertEqual(self.active.read_bytes(), self.after)
        self.assertFalse(report["production_binary_mutation"])
        self.assertFalse(report["all_rust_mutation_paths_covered"])
        self.assertFalse(report["human_identity_independently_verified"])

    def test_unsigned_or_forged_human_intent_never_mutates_state(self):
        self.token["signature"] = "f" * 64
        with self.assertRaises(module.CrossApplicationRejected):
            self.invoke()
        self.assertEqual(self.active.read_bytes(), self.before)

    def test_actor_and_target_binding_prevent_cross_action_replay(self):
        with self.assertRaises(module.CrossApplicationRejected):
            module.authorized_local_canary(self.ledger, self.token, self.human_key,
                                           "intruding-actor", self.active, self.candidate,
                                           self.manifest, self.canary_signature,
                                           self.canary_key, now=self.moment)
        self.assertEqual(self.active.read_bytes(), self.before)

    def test_consumed_nonce_is_not_replayed_for_second_release(self):
        self.invoke()
        with self.assertRaises(module.CrossApplicationRejected):
            self.invoke()
        self.assertEqual(self.active.read_bytes(), self.after)

    def test_real_post_swap_health_failure_rolls_back_exact_bytes(self):
        report = self.invoke(inject_failure=True)
        self.assertEqual(report["canary_status"], "CANARY_FAILED_ROLLED_BACK")
        self.assertTrue(report["automatic_rollback_verified"])
        self.assertEqual(self.active.read_bytes(), self.before)

    def test_canary_manifest_hash_tamper_blocks_approved_mutation(self):
        self.candidate.write_text("tampered release candidate", encoding="utf-8")
        with self.assertRaises(module.CrossApplicationRejected):
            self.invoke()
        self.assertEqual(self.active.read_bytes(), self.before)

    def _database_and_backup(self):
        database = self.folder / "catalog.sqlite"
        with closing(sqlite3.connect(str(database))) as conn:
            conn.execute("CREATE TABLE entries(id INTEGER PRIMARY KEY, value TEXT)")
            conn.execute("INSERT INTO entries VALUES(1, 'committed-data')")
            conn.commit()
        archive = self.folder / "archives"
        archive.mkdir(mode=0o700)
        return database, archive

    def test_real_sqlite_snapshot_and_disposable_restore_verified(self):
        database, archive = self._database_and_backup()
        report = module.local_backup_upgrade_drill(database, archive, "v23-local-01")
        self.assertEqual(report["status"],
                         "LOCAL_DB_RESTORED_AND_HASH_VERIFIED_NOT_PRODUCTION")
        self.assertTrue(report["real_disposable_restore"])
        self.assertEqual(report["snapshots_verified"], 1)
        self.assertFalse(report["production_upgrade_executed"])

    def test_backup_archive_tampering_cannot_be_silently_accepted(self):
        database, archive = self._database_and_backup()
        module.local_backup_upgrade_drill(database, archive, "v23-local-01")
        backup = archive / "backup-v23-local-01.sqlite"
        with backup.open("ab") as stream:
            stream.write(b"TAMPER")
        with self.assertRaises(module.CrossApplicationRejected):
            module.local_backup_upgrade_drill(database, archive, "v23-local-02")

    def test_rehearsal_refuses_existing_snapshot_identifier_and_sentinel(self):
        database, archive = self._database_and_backup()
        module.local_backup_upgrade_drill(database, archive, "v23-local-01")
        with self.assertRaises(module.CrossApplicationRejected):
            module.local_backup_upgrade_drill(database, archive, "v23-local-01")


class SixAxisEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.axes = {name: "PASS" for name in module.SIX_AXES}
        self.pin = hashlib.sha256(b"separate-trusted-metrics").hexdigest()

    def test_all_six_local_axes_are_reported_but_do_not_authorize_release(self):
        report = module.local_six_axis_evidence_gate(self.axes, self.pin, "origin-A", "origin-B")
        self.assertEqual(report["status"], "SIX_LOCAL_AXES_RECORDED_NOT_EXTERNALLY_AUDITED")
        self.assertFalse(report["release_authorized"])
        self.assertFalse(report["external_auditors_attested"])

    def test_missing_axis_never_becomes_pass(self):
        self.axes.pop("FUTURE_READINESS")
        with self.assertRaises(module.CrossApplicationRejected):
            module.local_six_axis_evidence_gate(self.axes, self.pin, "origin-A", "origin-B")

    def test_any_failed_axis_is_no_winner(self):
        self.axes["SAFETY"] = "FAIL"
        report = module.local_six_axis_evidence_gate(self.axes, self.pin, "origin-A", "origin-B")
        self.assertEqual(report["status"], "NO_WINNER")
        self.assertFalse(report["six_axes_all_passed"])

    def test_replayed_or_same_origin_names_rejected(self):
        with self.assertRaises(module.CrossApplicationRejected):
            module.local_six_axis_evidence_gate(self.axes, self.pin, "origin-A", "origin-A")
        with self.assertRaises(module.CrossApplicationRejected):
            module.local_six_axis_evidence_gate(self.axes, "bad-sha", "origin-A", "origin-B")


if __name__ == "__main__":
    unittest.main()
