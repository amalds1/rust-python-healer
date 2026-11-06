"""Real and negative F050 partial qualification; no claimed global coverage."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "run_microversion_matrix_v25.py"
SPEC = importlib.util.spec_from_file_location("run_microversion_matrix_v25", SCRIPT)
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)
PATCH = ".".join(map(str, sys.version_info[:3]))


class MicroVersionMatrixTests(unittest.TestCase):
    def test_exact_patch_triplet_required(self):
        self.assertEqual(MATRIX.version_tuple("3.15.2"), (3, 15, 2))
        self.assertEqual(MATRIX.version_tuple("3.16.0"), (3, 16, 0))

    def test_invalid_or_non_patch_versions_rejected(self):
        for value in ("3.15", "3.15.0rc1", "3.015.2", "3.15.02", "3.8.25", "4.0.0",
                      "3.15.2;echo x", "3.15.2\n", "3.15.-2"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                MATRIX.version_tuple(value)

    def test_duplicate_and_undeclared_candidates_rejected(self):
        with self.assertRaises(ValueError):
            MATRIX.parse_mappings(["3.15.2=/bin/a", "3.15.2=/bin/b"],
                                  {"3.15.2"}, "interpreter")
        with self.assertRaises(ValueError):
            MATRIX.parse_mappings(["3.15.1=/bin/a"], {"3.15.2"}, "interpreter")

    def test_missing_interpreter_is_not_run(self):
        with mock.patch.object(MATRIX, "check_probe") as probe:
            rows = MATRIX.evaluate_versions({"3.15.2"}, {}, {}, 1, 10)
            probe.assert_not_called()
        self.assertEqual(rows[0]["status"], "NOT_RUN")
        self.assertEqual(rows[0]["tests_pass"], 0)

    def test_invalid_pin_blocks_before_any_interpreter_execution(self):
        with mock.patch.object(MATRIX, "check_probe") as probe:
            rows = MATRIX.evaluate_versions({PATCH}, {PATCH: sys.executable},
                                            {PATCH: "f" * 63}, 1, 10)
            probe.assert_not_called()
        self.assertEqual(rows[0]["reason"], "invalid_sha256_pin")

    def test_wrong_pin_blocks_before_any_interpreter_execution(self):
        with mock.patch.object(MATRIX, "check_probe") as probe:
            rows = MATRIX.evaluate_versions({PATCH}, {PATCH: sys.executable},
                                            {PATCH: "a" * 64}, 1, 10)
            probe.assert_not_called()
        self.assertEqual(rows[0]["status"], "BLOCKED")
        self.assertEqual(rows[0]["tests_executed"], 0)

    def test_real_versioned_100_case_suite(self):
        exe = Path(sys.executable).resolve()
        expected = MATRIX.pin_hash(exe)
        rows = MATRIX.evaluate_versions({PATCH}, {PATCH: str(exe)},
                                        {PATCH: expected}, 1, 40)
        self.assertEqual(rows[0]["status"], "PASS", rows)
        self.assertEqual(rows[0]["tests_pass"], 100)
        self.assertGreaterEqual(rows[0]["elapsed_ms"], 0)

    def test_real_identity_mismatch_fails_closed(self):
        exe = Path(sys.executable).resolve()
        target = "3.9.9" if PATCH != "3.9.9" else "3.10.2"
        rows = MATRIX.evaluate_versions({target}, {target: str(exe)},
                                        {target: MATRIX.pin_hash(exe)}, 1, 30)
        self.assertEqual(rows[0]["status"], "FAIL")
        self.assertIn("actual_cpython_patch_identity_mismatch", rows[0]["reason"])

    def test_explicit_run_budget_leaves_missing_versions_not_run(self):
        exe = Path(sys.executable).resolve()
        other = "3.9.25" if PATCH != "3.9.25" else "3.10.22"
        rows = MATRIX.evaluate_versions({PATCH, other}, {PATCH: str(exe)},
                                        {PATCH: MATRIX.pin_hash(exe)}, 1, 30)
        self.assertEqual(sum(row["status"] == "PASS" for row in rows), 1)
        self.assertEqual(sum(row["status"] == "NOT_RUN" for row in rows), 1)

    def test_zero_budget_rejected(self):
        with self.assertRaisesRegex(ValueError, "resource_budget"):
            MATRIX.evaluate_versions({PATCH}, {}, {}, 0, 30)

    def test_nonabsolute_path_is_not_executed(self):
        with mock.patch.object(MATRIX, "check_probe") as probe:
            rows = MATRIX.evaluate_versions({PATCH}, {PATCH: "python3"},
                                            {PATCH: "b" * 64}, 1, 30)
            probe.assert_not_called()
        self.assertEqual(rows[0]["reason"], "relative_interpreter_path_rejected")

    def test_changed_previous_binary_blocks_even_with_new_pin(self):
        exe = Path(sys.executable).resolve()
        pin = MATRIX.pin_hash(exe)
        with mock.patch.object(MATRIX, "check_probe") as probe:
            rows = MATRIX.evaluate_versions({PATCH}, {PATCH: str(exe)},
                                            {PATCH: pin}, 1, 30,
                                            {PATCH: "f" * 64})
            probe.assert_not_called()
        self.assertEqual(rows[0]["reason"], "previously_pinned_binary_changed")

    def test_downgrade_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            saved = Path(folder) / "before.json"
            saved.write_text(json.dumps({"schema_version": 1,
                                         "latest_stable": "3.16.0",
                                         "required_versions": ["3.15.2"],
                                         "results": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "downgrade"):
                MATRIX.read_previous(saved, {"3.15.2"}, "3.15.2")

    def test_prior_monitored_versions_cannot_silently_disappear(self):
        with tempfile.TemporaryDirectory() as folder:
            saved = Path(folder) / "before.json"
            saved.write_text(json.dumps({"schema_version": 1,
                                         "latest_stable": "3.15.2",
                                         "required_versions": ["3.9.25", "3.15.2"],
                                         "results": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "cannot_disappear"):
                MATRIX.read_previous(saved, {"3.15.2"}, "3.15.2")

    def test_duplicate_previous_result_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            saved = Path(folder) / "before.json"
            row = {"version": "3.15.2", "executable_sha256": "f" * 64}
            saved.write_text(json.dumps({"schema_version": 1,
                                         "latest_stable": "3.15.2",
                                         "required_versions": ["3.15.2"],
                                         "results": [row, row]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate_previous_result"):
                MATRIX.read_previous(saved, {"3.15.2"}, "3.15.2")

    def test_invalid_suite_oracle_does_not_pass(self):
        fake = {"python": PATCH, "implementation": "cpython", "status": "PASS",
                "cases": 100, "pass": 100, "fail": 0,
                "results": [{"id": "duplicate", "status": "PASS"}] * 100}
        process = subprocess.CompletedProcess([], 0, json.dumps(fake), "")
        with mock.patch.object(MATRIX.subprocess, "run", return_value=process):
            with self.assertRaisesRegex(ValueError, "not_qualified"):
                MATRIX.check_suite(Path(sys.executable), PATCH, 10)

    def test_cli_missing_latest_is_never_a_global_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            report = Path(folder) / "report.json"
            required, _ = MATRIX.read_release_manifest()
            run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                                  "--require-version", required,
                                  "--output", str(report)], capture_output=True,
                                 text=True, timeout=10, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            data = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(data["results"][0]["status"], "NOT_RUN")
            self.assertFalse(data["all_existing_microversions_qualified"])
            self.assertFalse(data["future_microversions_qualified"])
            self.assertEqual(data["actual_tests_pass"], 0)


if __name__ == "__main__":
    unittest.main()
