"""Measured independent CPython process and real Rust/Ruff fixture tests."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("reliability_bench", ROOT / "python/reliability_bench.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReliabilityBenchTests(unittest.TestCase):
    def test_ten_real_independent_processes_same_predeclared_oracle(self):
        report = module.run_trusted_repetitions(sys.executable, 10)
        self.assertEqual(report["status"], "TRUSTED_TEN_REPEATS_MATCH")
        self.assertEqual(report["pass"], 10)
        self.assertEqual(report["fail"], 0)
        self.assertEqual(report["independent_processes_recorded"], 10)
        self.assertEqual(report["deterministic_result_sha256"],
                         module.KNOWN_TRUSTED_OBSERVATION_SHA256)
        self.assertEqual(len({item["run_id"] for item in report["observations"]}), 10)
        self.assertEqual(sum(item["retest"] for item in report["observations"]), 9)
        self.assertTrue(report["time_locale_random_filesystem_environment_controlled"])
        self.assertFalse(report["release_authorized"])

    def test_real_cli_ten_runs_and_json(self):
        proc = subprocess.run([sys.executable, "-I", "-S", "-B",
                               str(ROOT / "python/reliability_bench.py"),
                               "--mode", "trusted-repeat", "--python", sys.executable],
                              capture_output=True, check=False, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["pass"], 10)

    def test_real_cli_alternating_exit_is_flaky_never_pass(self):
        proc = subprocess.run([sys.executable, "-I", "-S", "-B",
                               str(ROOT / "python/reliability_bench.py"), "--mode", "trusted-repeat",
                               "--fixture-mode", "alternating-fail", "--python", sys.executable],
                              capture_output=True, check=False, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["status"], "FLAKY_DETECTED")
        self.assertEqual(report["independent_processes_recorded"], 10)

    def test_real_cli_latency_measurement_has_fixed_limits(self):
        proc = subprocess.run([sys.executable, "-I", "-S", "-B",
                               str(ROOT / "python/reliability_bench.py"), "--mode", "latency-measure",
                               "--latency-profile", "baseline", "--python", sys.executable],
                              capture_output=True, check=False, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["status"], "MEASURED_THRESHOLDS_PASS", report)
        self.assertEqual(report["predeclared_p95_limit_ms"], module.MAX_MEASURED_P95_MS)

    def test_deterministic_environment_explicit_time_locale_and_seed(self):
        with tempfile.TemporaryDirectory() as directory:
            env = module.trusted_environment(directory)
            self.assertEqual(env["LC_ALL"], "C")
            self.assertEqual(env["TZ"], "UTC")
            self.assertEqual(env["RPH_TRUSTED_FIXTURE"], "set-by-test-harness")
            self.assertEqual(env["TMPDIR"], directory)
            self.assertNotIn("PYTHONPATH", env)
            self.assertNotIn("HOME", env)
        self.assertIn("time.time = lambda: 1700000000.0", module.TRUSTED_PROGRAM)
        self.assertIn("random.seed(81473)", module.TRUSTED_PROGRAM)

    def test_cannot_claim_ten_retests_from_nine(self):
        with self.assertRaisesRegex(ValueError, "minimum_independent_runs_not_met"):
            module.run_trusted_repetitions(sys.executable, 9)

    def test_cannot_claim_five_pipeline_rounds_from_four(self):
        with self.assertRaisesRegex(ValueError, "minimum_independent_runs_not_met"):
            module.repair_pipeline_rounds("missing", "missing", sys.executable, 4)

    def test_quota_rejects_bad_or_fake_run_counts(self):
        for count in (-1, 0, 9, 31, True, 10.0, "10"):
            with self.subTest(count=count), self.assertRaises(ValueError):
                module.ensure_runs(count, module.MIN_REPEATS)

    def test_missing_interpreter_cannot_fabricate_success(self):
        report = module.run_trusted_repetitions("/definitely/missing/python", 10)
        self.assertEqual(report["status"], "INCOMPLETE_OR_DIVERGENT")
        self.assertEqual(report["not_run"], 10)
        self.assertEqual(report["pass"], 0)
        self.assertFalse(report["trusted_fixture_executed"])

    def test_real_ten_independent_flaky_odd_even_injection(self):
        report = module.run_trusted_repetitions(sys.executable, 10, "alternating-fail")
        self.assertEqual(report["status"], "FLAKY_DETECTED")
        self.assertEqual(report["pass"], 5)
        self.assertEqual(report["fail"], 5)
        self.assertEqual(report["not_run"], 0)
        self.assertEqual(report["measured_process_durations"], 10)
        self.assertEqual([row["status"] for row in report["observations"]],
                         ["PASS", "FAIL"] * 5)
        self.assertEqual({row["exit_code"] for row in report["observations"]
                          if row["status"] == "FAIL"}, {31})
        self.assertFalse(report["time_locale_random_filesystem_environment_controlled"])

    def test_real_ten_independent_fail_injection(self):
        report = module.run_trusted_repetitions(sys.executable, 10, "always-fail")
        self.assertEqual(report["status"], "FAIL_DETECTED")
        self.assertEqual((report["pass"], report["fail"], report["not_run"]), (0, 10, 0))
        self.assertEqual(report["measured_process_durations"], 10)
        self.assertFalse(report["trusted_fixture_passed"])

    def test_fake_unknown_injection_is_rejected_without_launch(self):
        with self.assertRaisesRegex(ValueError, "unknown_fixture_mode"):
            module.run_trusted_repetitions(sys.executable, 10, "skip-other-tests")

    def test_measured_real_ten_process_median_p95_baseline(self):
        report = module.measure_trusted_latency(sys.executable, 10)
        self.assertEqual(report["status"], "MEASURED_THRESHOLDS_PASS", report)
        self.assertEqual((report["passes"], report["fails"], report["not_run"]), (10, 0, 0))
        self.assertEqual(report["independent_processes_measured"], 10)
        self.assertGreater(report["median_ms"], 0)
        self.assertGreaterEqual(report["p95_ms"], report["median_ms"])
        self.assertFalse(report["production_performance_verified"])

    def test_measured_one_slow_child_triggers_p95_regression(self):
        report = module.measure_trusted_latency(sys.executable, 10, "p95-regression")
        self.assertEqual(report["status"], "MEASURED_REGRESSION", report)
        self.assertEqual(report["passes"], 10)
        self.assertEqual(report["not_run"], 0)
        self.assertGreater(report["p95_ms"], report["predeclared_p95_limit_ms"])
        self.assertEqual(sum(row["injected_delay_ms"] != 0 for row in report["observations"]), 1)

    def test_measured_six_slow_children_trigger_median_regression(self):
        report = module.measure_trusted_latency(sys.executable, 10, "median-regression")
        self.assertEqual(report["status"], "MEASURED_REGRESSION", report)
        self.assertEqual(report["passes"], 10)
        self.assertEqual(report["not_run"], 0)
        self.assertGreater(report["median_ms"], report["predeclared_median_limit_ms"])
        self.assertEqual(sum(row["injected_delay_ms"] != 0 for row in report["observations"]), 6)

    def test_missing_latency_interpreter_never_fakes_threshold_pass(self):
        report = module.measure_trusted_latency("/absent/python", 10, "baseline")
        self.assertEqual(report["status"], "INCOMPLETE_OR_FAILED_MEASUREMENT")
        self.assertEqual(report["independent_processes_measured"], 0)
        self.assertEqual(report["not_run"], 10)

    def test_latency_quota_and_profile_fail_closed(self):
        with self.assertRaises(ValueError):
            module.measure_trusted_latency(sys.executable, 9)
        with self.assertRaises(ValueError):
            module.measure_trusted_latency(sys.executable, 10, "user-defined-program")

    def test_missing_pipeline_tools_are_not_run(self):
        report = module.repair_pipeline_rounds("/nonexistent/rust", "/nonexistent/ruff",
                                               sys.executable, 5)
        self.assertEqual(report["status"], "NOT_RUN")
        self.assertFalse(report["untrusted_project_code_executed"])

    def test_p95_is_nearest_rank_not_interpolated(self):
        self.assertEqual(module.p95([1, 2, 3, 4, 5]), 5)
        self.assertEqual(module.p95([100, 1, 2, 3, 4]), 100)
        self.assertIsNone(module.p95([]))

    def test_pipeline_threshold_predeclared(self):
        self.assertEqual(module.MAX_LATENCY_P95_MS, 30000)
        self.assertEqual(module.MIN_PIPELINE_ROUNDS, 5)

    def test_pipeline_five_fresh_workdirs_real_rust_ruff_and_python(self):
        binary = ROOT / "target" / "release" / ("rust-python-healer.exe" if sys.platform == "win32" else "rust-python-healer")
        ruff = ROOT.parent / ".uv-bin/ruff"
        if not binary.is_file() or not ruff.is_file():
            self.skipTest("real Rust/Ruff binaries unavailable in this environment")
        report = module.repair_pipeline_rounds(binary, ruff, sys.executable, 5)
        self.assertEqual(report["status"], "TRUSTED_PIPELINE_MEETS_P95", report)
        self.assertEqual(report["passes"], 5)
        self.assertEqual(report["independent_workdirs"], 5)
        self.assertEqual({row["candidate_sha256"] for row in report["rounds"]},
                         {report["candidate_sha256"]})
        self.assertEqual(sum(row["retest"] for row in report["rounds"]), 4)
        self.assertFalse(report["source_executed"])
        self.assertFalse(report["release_authorized"])

    def test_rejects_fake_repair_json_even_if_successful_exit(self):
        binary = ROOT / "target" / "release" / ("rust-python-healer.exe" if sys.platform == "win32" else "rust-python-healer")
        ruff = ROOT.parent / ".uv-bin/ruff"
        if not binary.is_file() or not ruff.is_file():
            self.skipTest("selected executables not installed")
        fake = mock.Mock(returncode=0, stdout=b'{"status":"WINNER"}', stderr=b'')
        with mock.patch.object(module.subprocess, "run", return_value=fake):
            report = module.repair_pipeline_rounds(binary, ruff, sys.executable, 5)
        self.assertEqual(report["passes"], 0)
        self.assertNotEqual(report["status"], "TRUSTED_PIPELINE_MEETS_P95")

    def test_cli_rejects_insufficient_repeat_count(self):
        proc = subprocess.run([sys.executable, str(ROOT / "python/reliability_bench.py"),
                               "--mode", "trusted-repeat", "--python", sys.executable,
                               "--runs", "9"], capture_output=True, check=False, text=True, timeout=10)
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn('"status": "TRUSTED_TEN_REPEATS_MATCH"', proc.stdout)


if __name__ == "__main__":
    unittest.main()
