"""Signed append-only audit ledger; independently verify retained rows."""

import copy
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from test_qualification_policy import candidate, fixture_data, module as policy_engine


ROOT = Path(__file__).resolve().parents[1]
sys.modules["qualification_policy"] = policy_engine
spec = spec_from_file_location("decision_audit", ROOT / "python" / "decision_audit.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)
AUDIT_SECRET = {"schema_version": 1, "key_hex": "ab" * 32}


class DecisionAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)
        self.db = self.path / "decisions.sqlite"
        self.policy, self.trust, self.evidence = fixture_data()

    def tearDown(self):
        self.tmp.cleanup()

    def add(self, run="RUN-1", retest=False):
        return module.append_decision(self.db, self.policy, self.trust,
                                      self.evidence, AUDIT_SECRET, run, retest)

    def test_no_winner_is_durably_logged_and_verified(self):
        value = candidate(self.policy, self.trust)
        value["observations"] = []
        self.evidence["candidates"].append(value)
        report = self.add()
        self.assertEqual(report["status"], "AUDIT_RECORDED_AUTHENTICATED_NOT_WORM")
        self.assertEqual(report["decision"], "NO_WINNER")
        self.assertIsNone(report["primary_variant"])
        self.assertIsNone(report["reserve_variant"])
        checked = module.verify_database(self.db, AUDIT_SECRET)
        self.assertEqual(checked["status"], "AUDIT_CHAIN_VERIFIED_NOT_WORM")
        self.assertEqual(checked["events"], 1)
        self.assertEqual(checked["chain_tip_sha256"], report["chain_tip_sha256"])
        self.assertFalse(checked["release_authorized"])

    def test_primary_and_at_most_one_reserve_from_six_attested_gates(self):
        fast = candidate(self.policy, self.trust, "fast", speed=3)
        middle = candidate(self.policy, self.trust, "middle", speed=12)
        slow = candidate(self.policy, self.trust, "slow", speed=27)
        self.evidence["candidates"].extend([slow, middle, fast])
        report = self.add()
        self.assertEqual(report["primary_variant"], fast["variant_id"])
        self.assertEqual(report["reserve_variant"], middle["variant_id"])
        self.assertEqual(module.verify_database(self.db, AUDIT_SECRET)["events"], 1)
        self.assertFalse(report["release_authorized"])

    def test_idempotent_rerun_never_adds_fake_retest(self):
        self.evidence["candidates"].append(candidate(self.policy, self.trust))
        first = self.add()
        same = self.add()
        self.assertEqual(same["status"], "ALREADY_RECORDED_NO_NEW_MEASUREMENT")
        self.assertEqual(same["chain_tip_sha256"], first["chain_tip_sha256"])
        self.assertEqual(module.verify_database(self.db, AUDIT_SECRET)["events"], 1)
        with self.assertRaisesRegex(ValueError, "duplicate_evidence_new_run_id_refused"):
            self.add("NEW-RUN-ID")

    def test_new_measurement_same_variant_requires_explicit_retest(self):
        self.evidence["candidates"].append(candidate(self.policy, self.trust, "engine-a", speed=15))
        first = self.add()
        self.evidence["candidates"] = [candidate(self.policy, self.trust, "engine-a", speed=10)]
        with self.assertRaisesRegex(ValueError, "explicit_retest_required_or_unexpected"):
            self.add("RUN-2")
        repeated = self.add("RUN-2", retest=True)
        self.assertEqual(repeated["seq"], 2)
        self.assertNotEqual(first["chain_tip_sha256"], repeated["chain_tip_sha256"])
        self.assertEqual(module.verify_database(self.db, AUDIT_SECRET)["events"], 2)

    def test_unexpected_first_retest_is_rejected(self):
        self.evidence["candidates"].append(candidate(self.policy, self.trust))
        with self.assertRaisesRegex(ValueError, "explicit_retest_required_or_unexpected"):
            self.add(retest=True)
        with self.assertRaisesRegex(ValueError, "audit_schema_missing_or_modified"):
            module.verify_database(self.db, AUDIT_SECRET)
        first = self.add()
        self.assertEqual(first["seq"], 1)

    def test_ledger_triggers_reject_update_and_delete(self):
        self.evidence["candidates"].append(candidate(self.policy, self.trust))
        self.add()
        conn = sqlite3.connect(str(self.db))
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("DELETE FROM audit_events")
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE audit_events SET run_id='different'")
        finally:
            conn.close()
        self.assertEqual(module.verify_database(self.db, AUDIT_SECRET)["events"], 1)

    def test_tampering_with_row_or_signature_is_detected_even_after_trigger_drop(self):
        self.evidence["candidates"].append(candidate(self.policy, self.trust))
        self.add()
        conn = sqlite3.connect(str(self.db))
        try:
            conn.execute("DROP TRIGGER audit_no_update")
            conn.execute("UPDATE audit_events SET report_json='{}'")
            conn.commit()
        finally:
            conn.close()
        with self.assertRaisesRegex(ValueError, "audit_report_sha256_mismatch"):
            module.verify_database(self.db, AUDIT_SECRET)

    def test_recomputed_unkeyed_chain_hash_cannot_forge_audit_mac(self):
        self.evidence["candidates"].append(candidate(self.policy, self.trust))
        self.add()
        conn = sqlite3.connect(str(self.db))
        try:
            conn.execute("DROP TRIGGER audit_no_update")
            row = conn.execute("SELECT * FROM audit_events").fetchone()
            event = module.row_event(row)
            event["recorded_at_utc"] = "2099-01-01T00:00:00+00:00"
            new_chain = module.digest(module.event_body(event))
            conn.execute("UPDATE audit_events SET recorded_at_utc=?, chain_sha256=?",
                         (event["recorded_at_utc"], new_chain))
            conn.commit()
        finally:
            conn.close()
        with self.assertRaisesRegex(ValueError, "audit_hmac_invalid"):
            module.verify_database(self.db, AUDIT_SECRET)

    def test_a_different_operator_key_cannot_verify_prior_chain(self):
        self.evidence["candidates"].append(candidate(self.policy, self.trust))
        self.add()
        wrong = {"schema_version": 1, "key_hex": "cd" * 32}
        with self.assertRaisesRegex(ValueError, "audit_hmac_invalid"):
            module.verify_database(self.db, wrong)

    def test_missing_verify_database_is_not_created_or_claimed_pass(self):
        with self.assertRaisesRegex(ValueError, "audit_database_not_found"):
            module.verify_database(self.db, AUDIT_SECRET)
        self.assertFalse(self.db.exists())

    def test_symlink_database_rejected_before_sqlite_open(self):
        link = self.path / "linked.sqlite"
        self.evidence["candidates"].append(candidate(self.policy, self.trust))
        self.add()
        link.symlink_to(self.db)
        with self.assertRaisesRegex(ValueError, "audit_database_symlink_refused"):
            module.verify_database(link, AUDIT_SECRET)
        with self.assertRaisesRegex(ValueError, "audit_database_symlink_refused"):
            module.append_decision(link, self.policy, self.trust, self.evidence,
                                   AUDIT_SECRET, "RUN-NEW")

    def test_unsigned_or_edited_audit_evidence_rejected_before_write(self):
        value = candidate(self.policy, self.trust)
        value["observations"][0]["value"] = 10
        self.evidence["candidates"].append(value)
        with self.assertRaisesRegex(ValueError, "audit_signature_invalid"):
            self.add()
        self.assertFalse(self.db.exists())

    def test_report_claiming_release_approval_or_fake_winner_rejected(self):
        self.evidence["candidates"].append(candidate(self.policy, self.trust))
        report = policy_engine.qualify(self.policy, self.trust, self.evidence)
        invalid = copy.deepcopy(report)
        invalid["release_authorized"] = True
        with self.assertRaisesRegex(ValueError, "report_verification_claims_invalid"):
            module.checked_report(invalid)
        invalid = copy.deepcopy(report)
        invalid["reserve_variant"] = report["primary_variant"]
        with self.assertRaisesRegex(ValueError, "primary_and_reserve_must_differ"):
            module.checked_report(invalid)

    def test_cli_read_only_verify_and_append_without_exposing_operator_secret(self):
        self.evidence["candidates"].append(candidate(self.policy, self.trust))
        for name, value in (("policy", self.policy), ("trust", self.trust),
                            ("evidence", self.evidence), ("key", AUDIT_SECRET)):
            (self.path / (name + ".json")).write_text(json.dumps(value))
        prefix = ("import types,sys\n"
                  "_m=types.ModuleType('qualification_policy')\n"
                  "exec({!r},_m.__dict__)\n"
                  "sys.modules['qualification_policy']=_m\n".format(
                      (ROOT / "python" / "qualification_policy.py").read_text()))
        program = prefix + (ROOT / "python" / "decision_audit.py").read_text()
        base = [sys.executable, "-I", "-S", "-B", "-c", program,
                "--db", str(self.db), "--audit-key", str(self.path / "key.json")]
        appended = subprocess.run(base + ["--policy", str(self.path / "policy.json"),
                                         "--trust", str(self.path / "trust.json"),
                                         "--evidence", str(self.path / "evidence.json"),
                                         "--run-id", "RUN-1"],
                                 capture_output=True, text=True, check=False)
        self.assertEqual(appended.returncode, 0, appended.stderr)
        self.assertEqual(json.loads(appended.stdout)["status"],
                         "AUDIT_RECORDED_AUTHENTICATED_NOT_WORM")
        self.assertNotIn(AUDIT_SECRET["key_hex"], appended.stdout)
        verified = subprocess.run(base + ["--verify"], capture_output=True,
                                  text=True, check=False)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(json.loads(verified.stdout)["events"], 1)
        self.assertFalse(json.loads(verified.stdout)["release_authorized"])


if __name__ == "__main__":
    unittest.main()
