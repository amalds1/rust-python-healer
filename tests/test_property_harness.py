"""Seed-stable property generation and shrinking of a fixed trusted mutant."""

from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("property_harness", ROOT / "python/property_harness.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


class PropertyHarnessTests(unittest.TestCase):
    def test_trusted_roundtrip_property_is_seed_stable(self):
        result = module.run(42, 256, "roundtrip_nonnegative")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["cases_executed"], 256)
        self.assertIsNone(result["shrinking"])
        self.assertEqual(result["generator_sha256"], module.run(
            42, 256, "roundtrip_nonnegative")["generator_sha256"])

    def test_sha256_property_checks_all_generated_values(self):
        self.assertEqual(module.run(135, 211, "hex_digest_length")["status"], "PASS")

    def test_mutant_is_killed_with_minimal_shrunken_counterexample(self):
        result = module.run(93, 255, "mutant_double_equals_self")
        self.assertEqual(result["status"], "EXPECTED_MUTANT_KILLED")
        self.assertEqual(result["shrinking"]["minimal_witness"], 1)
        self.assertTrue(result["shrinking"]["immediate_predecessor_passes"])
        self.assertTrue(result["shrinking"]["witness_is_counterexample"])

    def test_shrinker_rejects_passing_initial_example(self):
        with self.assertRaises(ValueError):
            module.shrink_counterexample("mutant_double_equals_self", 0)

    def test_unknown_properties_are_rejected_without_eval(self):
        with self.assertRaisesRegex(ValueError, "property_not_allowlisted"):
            module.run(1, 5, "__import__('os').system('echo unsafe')")

    def test_seed_and_case_budget_fail_closed(self):
        for seed, cases in ((-1, 10), (2**32, 10), (True, 10), (1, 0),
                            (1, 1001), (1, 1.5), (1, True)):
            with self.assertRaises(ValueError):
                module.run(seed, cases, "roundtrip_nonnegative")

    def test_different_seeds_produce_distinct_generation_records(self):
        left = module.run(14, 100, "roundtrip_nonnegative")
        right = module.run(15, 100, "roundtrip_nonnegative")
        self.assertNotEqual(left["generator_sha256"], right["generator_sha256"])

    def test_cli_runs_isolated_fixed_properties(self):
        p = subprocess.run([sys.executable, "-I", "-S", "-B", "-c",
                            (ROOT / "python/property_harness.py").read_text(),
                            "--seed", "4", "--cases", "100", "--property",
                            "mutant_double_equals_self"], capture_output=True, text=True,
                           check=False)
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data["status"], "EXPECTED_MUTANT_KILLED")
        self.assertIs(data["user_source_executed"], False)


if __name__ == "__main__":
    unittest.main()
