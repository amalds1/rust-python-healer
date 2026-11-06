"""Negative/positive evidence gates for genuine per-minor 100-case fixture."""

import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "qualify_curated.py"
SPEC = importlib.util.spec_from_file_location("qualify_curated_windows", SOURCE)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class CuratedQualificationTests(unittest.TestCase):
    def test_real_exactly_100_curated_checks_on_current_cpython(self):
        if sys.implementation.name != "cpython" or not 9 <= sys.version_info.minor <= 15:
            self.skipTest("real target CPython minor unavailable")
        current = "{}.{}".format(*sys.version_info[:2])
        result = module.qualify(current)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual((result["cases"], result["passed"], result["failed"]),
                         (100, 100, 0))
        self.assertEqual(len(set(row["id"] for row in result["case_results"])), 100)
        self.assertFalse(result["full_compatibility_proven"])

    def test_other_python_minor_is_never_synthetically_passed(self):
        other = "3.9" if sys.version_info.minor != 9 else "3.10"
        with mock.patch.object(module.subprocess, "run") as child:
            report = module.qualify(other)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["cases"], 0)
        child.assert_not_called()

    def test_invalid_versions_rejected_before_execution(self):
        for value in ("", "3.8", "3.16", "3.12;rm", None, 3.12):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.qualify(value)

    def test_child_failure_is_fail_not_pass(self):
        expected = "{}.{}".format(*sys.version_info[:2])
        completed = mock.Mock(returncode=4, stdout=b"secret", stderr=b"secret=password")
        with mock.patch.object(module.subprocess, "run", return_value=completed):
            result = module.qualify(expected)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["reason"], "bounded_curated_child_failed")
        self.assertNotIn("password", json.dumps(result))

    def test_duplicate_identifiers_are_rejected(self):
        expected = "{}.{}".format(*sys.version_info[:2])
        rows = [{"id": "same", "status": "PASS"} for _ in range(100)]
        value = {"python": expected + ".0", "implementation": "cpython",
                 "cases": 100, "pass": 100, "fail": 0, "status": "PASS",
                 "results": rows}
        completed = mock.Mock(returncode=0, stdout=json.dumps(value).encode(), stderr=b"")
        with mock.patch.object(module.subprocess, "run", return_value=completed):
            result = module.qualify(expected)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["reason"], "suite_result_inconsistent")

    def test_subprocess_timeout_stays_not_run(self):
        expected = "{}.{}".format(*sys.version_info[:2])
        with mock.patch.object(module.subprocess, "run", side_effect=OSError("private")):
            result = module.qualify(expected)
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertNotIn("private", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
