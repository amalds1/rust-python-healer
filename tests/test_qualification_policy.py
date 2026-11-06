"""Qualification gates are policy-only; no arbitrary candidate code runs."""

import copy
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("qualification_policy", ROOT / "python" / "qualification_policy.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


def fixture_data():
    policy = {"schema_version": 1, "policy_id": "P-seven-minors", "maximum_reserves": 1,
              "thresholds": {
                  "SAFETY": {"metric": "critical_findings", "comparison": "max", "limit": 0},
                  "CORRECTNESS": {"metric": "failing_oracle_checks", "comparison": "max", "limit": 0},
                  "SPEED": {"metric": "p95_millis", "comparison": "max", "limit": 50},
                  "RELIABILITY": {"metric": "passing_repetitions", "comparison": "min", "limit": 10},
                  "COMPATIBILITY": {"metric": "passing_python_minors", "comparison": "min", "limit": 7},
                  "FUTURE_READINESS": {"metric": "metadata_age_days", "comparison": "max", "limit": 30},
              }}
    trust = {"schema_version": 1, "auditors": {
        "auditor{}".format(i): {"key_hex": "{:02x}".format(i + 1) * 32, "axes": [axis]}
        for i, axis in enumerate(module.AXES)}}
    evidence = {"schema_version": 1, "candidates": []}
    return policy, trust, evidence


def candidate(policy, trust, engine="safe-ruff", speed=25, failed=None, missing=None,
              explicit_status=None):
    code_hash = hashlib.sha256((engine + "-code").encode()).hexdigest()
    config_hash = hashlib.sha256((engine + "-config").encode()).hexdigest()
    variant = {"variant_id": module.identity(engine, code_hash, config_hash),
               "engine": engine, "code_sha256": code_hash,
               "config_sha256": config_hash, "observations": []}
    metrics = {"SAFETY": 0, "CORRECTNESS": 0, "SPEED": speed,
               "RELIABILITY": 10, "COMPATIBILITY": 7, "FUTURE_READINESS": 1}
    if failed:
        metrics.update(failed)
    for i, axis in enumerate(module.AXES):
        if axis == missing:
            continue
        auditor = "auditor{}".format(i)
        row = {"axis": axis, "metric": module.METRICS[axis][0],
               "value": metrics[axis], "status": explicit_status.get(axis, "PASS")
               if explicit_status else "PASS",
               "auditor_id": auditor, "evidence_sha256": hashlib.sha256(
                   (engine + axis).encode()).hexdigest(),
               "run_id": "run-{}-{}".format(i, engine)}
        row["signature"] = module.sign_for_test(policy, variant, row,
                                                 trust["auditors"][auditor]["key_hex"])
        variant["observations"].append(row)
    return variant


class QualificationPolicyTests(unittest.TestCase):
    def test_missing_all_axes_fails_closed_without_winner(self):
        policy, trust, evidence = fixture_data()
        incomplete = candidate(policy, trust)
        incomplete["observations"] = []
        evidence["candidates"].append(incomplete)
        report = module.qualify(policy, trust, evidence)
        self.assertEqual(report["decision"], "NO_WINNER")
        self.assertIsNone(report["primary_variant"])
        self.assertIsNone(report["reserve_variant"])
        self.assertEqual(report["decision_log"][0]["gates_checked"], 0)
        self.assertEqual(len(report["decision_log"][0]["failed_gates"]), 6)
        self.assertFalse(report["independent_execution_verified"])

    def test_six_signed_gates_are_required_before_policy_qualification(self):
        policy, trust, evidence = fixture_data()
        good = candidate(policy, trust)
        evidence["candidates"].append(good)
        report = module.qualify(policy, trust, evidence)
        self.assertEqual(report["primary_variant"], good["variant_id"])
        self.assertEqual(report["qualified_variants"], 1)
        self.assertEqual(report["decision_log"][0]["gates_checked"], 6)
        self.assertFalse(report["release_authorized"])
        self.assertFalse(report["source_executed"])
        self.assertIn("NOT_BEHAVIORALLY_PROVEN", report["status"])

    def test_deterministic_ranking_primary_and_at_most_one_reserve(self):
        policy, trust, evidence = fixture_data()
        slow = candidate(policy, trust, "slow", speed=40)
        fast = candidate(policy, trust, "fast", speed=2)
        medium = candidate(policy, trust, "medium", speed=25)
        evidence["candidates"].extend([slow, medium, fast])
        report = module.qualify(policy, trust, evidence)
        self.assertEqual(report["primary_variant"], fast["variant_id"])
        self.assertEqual(report["reserve_variant"], medium["variant_id"])
        self.assertEqual(report["qualified_variants"], 3)
        self.assertEqual(report["maximum_reserves"], 1)
        evidence["candidates"].reverse()
        reversed_report = module.qualify(policy, trust, evidence)
        self.assertEqual(reversed_report["primary_variant"], fast["variant_id"])
        self.assertEqual(reversed_report["reserve_variant"], medium["variant_id"])

    def test_a_signed_pass_cannot_overrule_a_failing_numeric_gate(self):
        policy, trust, evidence = fixture_data()
        evidence["candidates"].append(candidate(policy, trust,
                                                failed={"CORRECTNESS": 1, "SPEED": 55}))
        report = module.qualify(policy, trust, evidence)
        self.assertEqual(report["decision"], "NO_WINNER")
        self.assertIn("CORRECTNESS_THRESHOLD_FAIL",
                      report["decision_log"][0]["failed_gates"])
        self.assertIn("SPEED_THRESHOLD_FAIL", report["decision_log"][0]["failed_gates"])

    def test_not_run_and_explicit_fail_never_become_green(self):
        policy, trust, evidence = fixture_data()
        evidence["candidates"].append(candidate(
            policy, trust, explicit_status={"SAFETY": "NOT_RUN", "SPEED": "FAIL"}))
        report = module.qualify(policy, trust, evidence)
        self.assertEqual(report["decision"], "NO_WINNER")
        self.assertEqual(report["decision_log"][0]["failed_gates"], [
            "SAFETY_NOT_PASS", "SPEED_NOT_PASS"])

    def test_replaying_a_signature_across_policies_is_rejected(self):
        policy, trust, evidence = fixture_data()
        evidence["candidates"].append(candidate(policy, trust))
        altered = copy.deepcopy(policy)
        altered["thresholds"]["SPEED"]["limit"] = 40
        with self.assertRaisesRegex(ValueError, "audit_signature_invalid"):
            module.qualify(altered, trust, evidence)

    def test_hmac_prevents_tampered_evidence_values_and_hashes(self):
        policy, trust, evidence = fixture_data()
        value = candidate(policy, trust)
        evidence["candidates"].append(value)
        value["observations"][2]["value"] = 1
        with self.assertRaisesRegex(ValueError, "audit_signature_invalid"):
            module.qualify(policy, trust, evidence)
        value["observations"][2]["value"] = 25
        value["observations"][2]["evidence_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "audit_signature_invalid"):
            module.qualify(policy, trust, evidence)

    def test_duplicate_variants_and_measurements_require_retest(self):
        policy, trust, evidence = fixture_data()
        evidence["candidates"].extend([candidate(policy, trust), candidate(policy, trust)])
        with self.assertRaisesRegex(ValueError, "duplicate_variant_requires_explicit_retest"):
            module.qualify(policy, trust, evidence)
        evidence["candidates"] = [candidate(policy, trust)]
        evidence["candidates"][0]["observations"].append(
            copy.deepcopy(evidence["candidates"][0]["observations"][0]))
        with self.assertRaisesRegex(ValueError, "invalid_observation_count"):
            module.qualify(policy, trust, evidence)

    def test_cross_variant_measurement_reuse_is_rejected_even_when_signed(self):
        policy, trust, evidence = fixture_data()
        first = candidate(policy, trust, "different-engine")
        second = candidate(policy, trust, "second-engine")
        second["observations"][0]["run_id"] = first["observations"][0]["run_id"]
        second["observations"][0]["signature"] = module.sign_for_test(
            policy, second, second["observations"][0],
            trust["auditors"]["auditor0"]["key_hex"])
        evidence["candidates"] = [first, second]
        with self.assertRaisesRegex(ValueError, "cross_variant_evidence_reused"):
            module.qualify(policy, trust, evidence)

    def test_identity_tied_to_code_and_configuration_hash(self):
        policy, trust, evidence = fixture_data()
        value = candidate(policy, trust)
        value["code_sha256"] = "0" * 64
        evidence["candidates"].append(value)
        with self.assertRaisesRegex(ValueError, "variant_identity_hash_mismatch"):
            module.qualify(policy, trust, evidence)

    def test_trust_roots_must_be_distinct_and_authorized(self):
        policy, trust, evidence = fixture_data()
        value = candidate(policy, trust)
        evidence["candidates"].append(value)
        altered = copy.deepcopy(trust)
        altered["auditors"]["auditor0"]["axes"] = ["CORRECTNESS"]
        with self.assertRaisesRegex(ValueError, "auditor_outside_authorized_scope"):
            module.qualify(policy, altered, evidence)
        altered = copy.deepcopy(trust)
        altered["auditors"].pop("auditor0")
        with self.assertRaisesRegex(ValueError, "six_distinct_auditors_required"):
            module.qualify(policy, altered, evidence)
        altered = copy.deepcopy(trust)
        altered["auditors"]["auditor1"]["key_hex"] = trust["auditors"]["auditor0"]["key_hex"]
        with self.assertRaisesRegex(ValueError, "auditors_must_have_distinct_signing_keys"):
            module.qualify(policy, altered, evidence)

    def test_policy_rejects_weaker_limits_and_missing_axes(self):
        policy, trust, evidence = fixture_data()
        evidence["candidates"].append(candidate(policy, trust))
        invalid = copy.deepcopy(policy)
        invalid["thresholds"]["SAFETY"]["limit"] = 1
        with self.assertRaisesRegex(ValueError, "critical_failures_must_be_zero"):
            module.qualify(invalid, trust, evidence)
        invalid = copy.deepcopy(policy)
        invalid["thresholds"]["RELIABILITY"]["limit"] = 9
        with self.assertRaisesRegex(ValueError, "threshold_weaker_than_policy_floor"):
            module.qualify(invalid, trust, evidence)
        invalid = copy.deepcopy(policy)
        invalid["thresholds"].pop("COMPATIBILITY")
        with self.assertRaisesRegex(ValueError, "six_thresholds_required"):
            module.qualify(invalid, trust, evidence)

    def test_nan_and_invalid_status_cannot_bypass_policy(self):
        policy, trust, evidence = fixture_data()
        value = candidate(policy, trust)
        evidence["candidates"].append(value)
        value["observations"][0]["value"] = float("nan")
        with self.assertRaisesRegex(ValueError, "nonfinite_axis_metric"):
            module.qualify(policy, trust, evidence)
        value["observations"][0]["value"] = 0
        value["observations"][0]["status"] = "UNVERIFIED_PASS"
        with self.assertRaisesRegex(ValueError, "invalid_axis_status"):
            module.qualify(policy, trust, evidence)

    def test_symlink_and_oversized_evidence_files_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            file = path / "input.json"
            file.write_text("{}")
            link = path / "linked.json"
            link.symlink_to(file)
            with self.assertRaisesRegex(ValueError, "symlink_policy_input_refused"):
                module.bounded_file(link)
            file.write_bytes(b"x" * (module.MAX_SIZE + 1))
            with self.assertRaisesRegex(ValueError, "policy_input_not_unique_bounded_file"):
                module.bounded_file(file)

    def test_duplicate_json_keys_are_rejected_before_policy_check(self):
        with tempfile.TemporaryDirectory() as root:
            file = Path(root) / "ambiguous.json"
            file.write_text('{"schema_version":1,"schema_version":2}')
            with self.assertRaisesRegex(ValueError, "duplicate_json_key"):
                module.bounded_file(file)

    def test_cli_reports_no_execution_and_omits_secrets(self):
        policy, trust, evidence = fixture_data()
        evidence["candidates"].append(candidate(policy, trust))
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            for name, content in (("policy", policy), ("trust", trust), ("evidence", evidence)):
                (path / (name + ".json")).write_text(json.dumps(content))
            proc = subprocess.run([
                sys.executable, "-I", "-S", "-B", "-c",
                (ROOT / "python" / "qualification_policy.py").read_text(),
                "--policy", str(path / "policy.json"),
                "--trust", str(path / "trust.json"),
                "--evidence", str(path / "evidence.json")],
                capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual(report["decision"], "POLICY_PRIMARY_EXISTS")
            self.assertNotIn(trust["auditors"]["auditor0"]["key_hex"], proc.stdout)
            self.assertFalse(report["source_executed"])
            self.assertFalse(report["release_authorized"])


if __name__ == "__main__":
    unittest.main()
