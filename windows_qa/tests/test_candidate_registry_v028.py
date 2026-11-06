"""No Windows runner or winner may be manufactured from historical fixtures."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class WindowsCandidateRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = json.loads((ROOT / "config" /
                                   "candidate_registry_windows_v028.json").read_text())

    def test_variants_have_distinct_id_and_no_phantom_native_runs(self):
        variants = self.registry["variants"]
        self.assertEqual(len(variants), 2)
        self.assertEqual(len(set(row["variant_id"] for row in variants)), 2)
        self.assertTrue(all(row["native_test_runs"] == 0 for row in variants))
        self.assertTrue(all(row["eligible_for_rank"] is False for row in variants))

    def test_six_quality_gates_and_no_winner(self):
        self.assertIsNone(self.registry["winner"])
        self.assertIsNone(self.registry["verified_reserve"])
        self.assertFalse(self.registry["independent_security_audit"])
        for row in self.registry["variants"]:
            self.assertEqual(len(row["quality_gates"]), 6)
            self.assertEqual(set(row["quality_gates"].values()), {"NOT_RUN"})

    def test_thresholds_include_real_python_and_speed(self):
        limits = self.registry["thresholds_defined_before_native_windows_trials"]
        self.assertEqual(limits["curated_tests_per_actual_cpython_minor"], 100)
        self.assertEqual(len(limits["required_python_minors"]), 7)
        self.assertEqual(limits["speed_fresh_runs_minimum"], 5)
        self.assertEqual(limits["speed_fts5_p95_max_ms"], 50)


if __name__ == "__main__":
    unittest.main()
