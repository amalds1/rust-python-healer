"""Pure evidence analysis; no project fixture or arbitrary input execution."""

from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("flaky_evidence", ROOT / "python" / "flaky_evidence.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


def rows(outcomes):
    return {"schema_version": 1, "runs": [
        {"candidate": "V-demo", "case": "test_example", "runtime": "3.9",
         "run_id": "R{}".format(i), "status": status, "duration_ms": 4.5,
         "retest": i > 0}
        for i, status in enumerate(outcomes)
    ]}


class FlakyEvidenceTests(unittest.TestCase):
    def test_three_repeat_passes_are_not_behavioral_proof(self):
        result = module.inspect(rows(["PASS", "PASS", "PASS"]))
        self.assertEqual(result["groups"][0]["state"], "REPEATABLE_PASS_NOT_VERIFIED")
        self.assertEqual(result["behavioral_correctness"], "NOT_VERIFIED")
        self.assertFalse(result["source_executed"])

    def test_mixed_outcomes_mark_candidate_flaky(self):
        result = module.inspect(rows(["PASS", "FAIL", "PASS"]))
        self.assertEqual(result["summary"]["FLAKY"], 1)
        self.assertEqual(result["groups"][0]["state"], "FLAKY")

    def test_missing_evidence_and_few_runs_do_not_get_pass(self):
        self.assertEqual(module.inspect(rows(["PASS"]))["groups"][0]["state"], "INSUFFICIENT")
        self.assertEqual(module.inspect(rows(["PASS", "PASS", "NOT_RUN"]))["groups"][0]["state"], "INCOMPLETE")
        self.assertEqual(module.inspect(rows(["FAIL", "FAIL", "FAIL"]))["groups"][0]["state"], "REPEATABLE_FAIL")

    def test_duplicate_or_implicit_retest_is_rejected(self):
        evidence = rows(["PASS", "PASS", "PASS"])
        evidence["runs"][1]["run_id"] = evidence["runs"][0]["run_id"]
        with self.assertRaisesRegex(ValueError, "duplicate_run_id"):
            module.inspect(evidence)
        evidence = rows(["PASS", "PASS", "PASS"])
        evidence["runs"][1]["retest"] = False
        with self.assertRaisesRegex(ValueError, "repeated_run_requires_retest"):
            module.inspect(evidence)

    def test_injected_status_and_invalid_numeric_values_are_rejected(self):
        evidence = rows(["PASS", "PASS", "PASS"])
        evidence["runs"][1]["case"] = "test; __import__('os').system('bad')"
        with self.assertRaisesRegex(ValueError, "invalid_run_identity"):
            module.inspect(evidence)
        evidence = rows(["PASS", "PASS", "PASS"])
        evidence["runs"][0]["duration_ms"] = float("nan")
        with self.assertRaisesRegex(ValueError, "invalid_run_duration"):
            module.inspect(evidence)
        evidence = rows(["PASS", "PASS", "PASS"])
        evidence["runs"][0]["status"] = []
        with self.assertRaisesRegex(ValueError, "invalid_run_status"):
            module.inspect(evidence)

    def test_file_sha256_and_symlink_quotas_are_enforced(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            report_path = root / "evidence.json"
            report_path.write_text(json.dumps(rows(["PASS", "FAIL", "PASS"])))
            result = module.inspect_file(report_path)
            self.assertEqual(len(result["input_sha256"]), 64)
            self.assertEqual(result["summary"]["FLAKY"], 1)
            alias = root / "alias.json"
            alias.symlink_to(report_path)
            with self.assertRaisesRegex(ValueError, "evidence_file_refused"):
                module.inspect_file(alias)
            report_path.write_bytes(b"Z" * (module.MAX_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "evidence_file_refused"):
                module.inspect_file(report_path)


if __name__ == "__main__":
    unittest.main()
