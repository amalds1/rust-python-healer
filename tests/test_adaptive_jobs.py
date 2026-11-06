"""Data-only bounded adaptive DAG simulation and imported variant comparison."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("adaptive_jobs", ROOT / "python/adaptive_jobs.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def jobs():
    return [{"id": "build", "duration_ms": 8, "memory_mb": 20, "deps": []},
            {"id": "lint", "duration_ms": 3, "memory_mb": 10, "deps": []},
            {"id": "compile", "duration_ms": 5, "memory_mb": 30, "deps": ["build"]},
            {"id": "pack", "duration_ms": 2, "memory_mb": 5, "deps": ["lint", "compile"]}]


class AdaptiveJobsTests(unittest.TestCase):
    def test_critical_path_and_real_decision_latency_recorded(self):
        report = module.schedule_trusted_fixture(jobs(), max_workers=3, memory_limit_mb=60)
        self.assertEqual(report["status"], "TRUSTED_DATA_ONLY_SIMULATION")
        self.assertEqual(report["simulated_serial_ms"], 18)
        self.assertEqual(report["simulated_makespan_ms"], 15)
        self.assertEqual(report["jobs_finished_at_ms"]["pack"], 15)
        self.assertTrue(report["real_scheduler_decision_latency_measured"])
        self.assertFalse(report["actual_parallel_runtime_measured"])
        self.assertFalse(report["fixture_costs_independently_measured"])
        self.assertFalse(report["untrusted_code_executed"])
        self.assertFalse(report["release_authorized"])

    def test_adaptive_worker_count_changes_with_pressure(self):
        report = module.schedule_trusted_fixture(jobs(), max_workers=3, memory_limit_mb=60)
        self.assertGreaterEqual(report["peak_workers"], 2)
        self.assertGreater(len(report["observed_worker_counts"]), 1)
        decisions = [event for event in report["events"] if event["event"] == "schedule"]
        self.assertTrue(all(event["wall_decision_ms"] >= 0 for event in decisions))
        self.assertTrue(any(event["queue_pressure_before"] > 0 for event in decisions))

    def test_critical_path_remaining_decreases_at_completion(self):
        report = module.schedule_trusted_fixture(jobs(), 2, 60)
        self.assertTrue(all(event["critical_path_delta_ms"] >= 0 for event in report["events"]))
        self.assertEqual(sum(event["critical_path_delta_ms"] for event in report["events"]), 15)
        completion_paths = [event["critical_path_remaining_ms"] for event in report["events"]
                            if event["event"] == "finished"]
        self.assertEqual(completion_paths[-1], 0)
        self.assertEqual(completion_paths, sorted(completion_paths, reverse=True))

    def test_memory_budget_prevents_overcommit(self):
        with self.assertRaisesRegex(ValueError, "job_exceeds_memory_limit"):
            module.schedule_trusted_fixture(jobs(), 4, 20)

    def test_one_worker_matches_serial_lower_bound(self):
        report = module.schedule_trusted_fixture(jobs(), 1, 100)
        self.assertEqual(report["simulated_makespan_ms"], 18)
        self.assertEqual(report["observed_worker_counts"], [1])

    def test_unknown_dependency_rejected(self):
        invalid = [{"id": "x", "duration_ms": 1, "memory_mb": 1, "deps": ["missing"]}]
        with self.assertRaisesRegex(ValueError, "unknown_dependency"):
            module.schedule_trusted_fixture(invalid)

    def test_indirect_cycle_rejected(self):
        invalid = [{"id": "x", "duration_ms": 1, "memory_mb": 1, "deps": ["y"]},
                   {"id": "y", "duration_ms": 1, "memory_mb": 1, "deps": ["x"]}]
        with self.assertRaisesRegex(ValueError, "cyclic_dependency"):
            module.schedule_trusted_fixture(invalid)

    def test_duplicate_job_and_edge_rejected(self):
        sample = jobs()
        with self.assertRaisesRegex(ValueError, "duplicate_job_id"):
            module.schedule_trusted_fixture(sample + [sample[0]])
        sample[3]["deps"] = ["lint", "lint"]
        with self.assertRaisesRegex(ValueError, "duplicate_dependencies"):
            module.schedule_trusted_fixture(sample)

    def test_quotas_reject_bool_negative_and_resource_exhaustion(self):
        for count in (0, -1, True, 100):
            with self.subTest(count=count), self.assertRaises(ValueError):
                module.schedule_trusted_fixture(jobs(), count, 100)
        for memory in (0, True, 1, 70_000):
            with self.subTest(memory=memory), self.assertRaises(ValueError):
                module.schedule_trusted_fixture(jobs(), 2, memory)

    def test_secure_fresh_variant_metadata_is_distinct(self):
        result = module.independently_initialize(b"trusted fixed example", quantity=8)
        self.assertEqual(result["status"], "INDEPENDENT_METADATA_ONLY")
        variants = result["variants"]
        self.assertEqual(len(variants), 8)
        self.assertEqual(len({row["variant_id"] for row in variants}), 8)
        self.assertEqual(len({row["independent_initialization_sha256"] for row in variants}), 8)
        self.assertEqual(len({row["config_sha256"] for row in variants}), 8)
        self.assertEqual(len({row["source_sha256"] for row in variants}), 1)
        self.assertFalse(result["repair_executed"])
        self.assertFalse(result["independence_of_actual_repair_models_proven"])

    def test_random_collision_fails_closed(self):
        with (mock.patch.object(module.secrets, "token_bytes", return_value=b"x" * 32),
              self.assertRaisesRegex(ValueError, "cryptographic_random_collision")):
            module.independently_initialize(b"fixed", quantity=2)

    def test_actual_untrusted_source_is_never_executed(self):
        marker = "__import__('subprocess').run(['false'])"
        result = module.independently_initialize(marker.encode(), quantity=2)
        self.assertTrue(all("source_sha256" in item for item in result["variants"]))
        self.assertFalse(result["repair_executed"])

    def test_rejects_unsupported_repair_engine(self):
        with self.assertRaisesRegex(ValueError, "unsupported_engine"):
            module.independently_initialize(b"trusted", engines=["imaginary-autonomous-ai"])

    def test_phi_identical_and_inverted_vectors(self):
        variants = [{"variant_id": "v1"}, {"variant_id": "v2"}, {"variant_id": "v3"}]
        baseline = {"a": "PASS", "b": "PASS", "c": "FAIL", "d": "FAIL"}
        inverted = {"a": "FAIL", "b": "FAIL", "c": "PASS", "d": "PASS"}
        report = module.correlate_imported_outcomes(variants,
                                                     {"v1": baseline, "v2": dict(baseline),
                                                      "v3": inverted})
        coefficients = {(item["left"], item["right"]): item["phi"] for item in report["pairs"]}
        self.assertEqual(coefficients[("v1", "v2")], 1.0)
        self.assertEqual(coefficients[("v1", "v3")], -1.0)
        self.assertEqual(coefficients[("v2", "v3")], -1.0)
        self.assertFalse(report["outcomes_independently_verified"])

    def test_constant_or_insufficient_vectors_have_undefined_phi(self):
        variants = [{"variant_id": "v1"}, {"variant_id": "v2"}]
        result = module.correlate_imported_outcomes(
            variants, {"v1": {"a": "PASS", "b": "PASS", "c": "PASS", "d": "PASS"},
                       "v2": {"a": "FAIL", "b": "PASS", "c": "FAIL", "d": "PASS"}})
        self.assertIsNone(result["pairs"][0]["phi"])
        self.assertEqual(result["pairs"][0]["interpretation"], "UNDEFINED_OR_INSUFFICIENT_DATA")

    def test_rejects_fake_outcome_and_duplicate_variant(self):
        variants = [{"variant_id": "v1"}, {"variant_id": "v2"}]
        with self.assertRaisesRegex(ValueError, "invalid_supplied_outcomes"):
            module.correlate_imported_outcomes(variants,
                                                {"v1": {"test": "UNKNOWN"},
                                                 "v2": {"test": "PASS"}})
        with self.assertRaisesRegex(ValueError, "duplicate_variant_id"):
            module.correlate_imported_outcomes([variants[0], variants[0]],
                                                {"v1": {"test": "PASS"}})

    def test_data_only_cli_json_trusted_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "jobs.json"
            target.write_text(json.dumps({"jobs": jobs()}), encoding="utf-8")
            proc = subprocess.run([sys.executable, "-I", "-S", "-B",
                                   str(ROOT / "python/adaptive_jobs.py"), "--mode", "schedule",
                                   "--input", str(target), "--workers", "3", "--memory-mb", "60"],
                                   capture_output=True, check=False, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["simulated_makespan_ms"], 15)

    def test_actual_concurrent_trusted_subprocesses_and_runtime_critical_path(self):
        report = module.live_trusted_subprocess_schedule(jobs(), sys.executable, 3, 60)
        self.assertEqual(report["status"], "TRUSTED_REAL_SUBPROCESS_EXECUTOR_PASS", report)
        self.assertEqual(report["observed_independent_processes"], 4)
        self.assertGreaterEqual(report["actual_peak_overlapping_processes"], 2)
        self.assertLessEqual(report["actual_peak_overlapping_processes"], 3)
        self.assertEqual(len({item["process_pid"] for item in report["per_job"].values()}), 4)
        self.assertEqual({item["python_minor"] for item in report["per_job"].values()},
                         {f"{sys.version_info[0]}.{sys.version_info[1]}"})
        self.assertGreater(report["measured_process_critical_path_ms"], report["nominal_critical_path_ms"])
        self.assertGreater(report["real_vs_nominal_critical_path_difference_ms"], 0)
        self.assertTrue(report["memory_is_only_declared_fixture_budget"])
        self.assertFalse(report["untrusted_project_code_executed"])
        self.assertFalse(report["real_cpu_throughput_proven"])

    def test_actual_single_worker_never_overlaps_processes(self):
        report = module.live_trusted_subprocess_schedule(jobs(), sys.executable, 1, 60)
        self.assertEqual(report["status"], "TRUSTED_REAL_SUBPROCESS_EXECUTOR_PASS", report)
        self.assertEqual(report["actual_peak_overlapping_processes"], 1)
        self.assertEqual(report["observed_adaptive_slot_counts"], [1])

    def test_actual_declared_memory_cap_serializes_independent_processes(self):
        fixture = [{"id": "one", "duration_ms": 25, "memory_mb": 40, "deps": []},
                   {"id": "two", "duration_ms": 25, "memory_mb": 40, "deps": []}]
        report = module.live_trusted_subprocess_schedule(fixture, sys.executable, 4, 40)
        self.assertEqual(report["status"], "TRUSTED_REAL_SUBPROCESS_EXECUTOR_PASS", report)
        self.assertEqual(report["actual_peak_overlapping_processes"], 1)
        self.assertTrue(report["memory_is_only_declared_fixture_budget"])

    def test_actual_workload_quota_denies_large_or_fake_duration(self):
        fixture = [{"id": "long", "duration_ms": 251, "memory_mb": 1, "deps": []}]
        with self.assertRaisesRegex(ValueError, "trusted_live_workload_quota_exceeded"):
            module.live_trusted_subprocess_schedule(fixture, sys.executable)
        with self.assertRaisesRegex(ValueError, "invalid_live_worker_limit"):
            module.live_trusted_subprocess_schedule(jobs(), sys.executable, 9)

    def test_actual_missing_selected_python_never_reports_green(self):
        result = module.live_trusted_subprocess_schedule(jobs(), "/absent/cpython", 2, 60)
        self.assertEqual(result["status"], "NOT_RUN_MISSING_SELECTED_PYTHON")
        self.assertFalse(result["trusted_child_executed"])

    def test_actual_failed_fixed_child_prevents_dependent_run(self):
        fixture = [{"id": "a", "duration_ms": 2, "memory_mb": 1, "deps": []},
                   {"id": "b", "duration_ms": 2, "memory_mb": 1, "deps": ["a"]}]
        def fake_child(_python, _folder, _ms):
            return {"status": "FAIL", "started_ns": 1, "finished_ns": 2,
                    "process_pid": None, "python_minor": None}
        with mock.patch.object(module, "_actual_known_trusted_child", side_effect=fake_child):
            result = module.live_trusted_subprocess_schedule(fixture, sys.executable, 2, 10)
        self.assertEqual(result["status"], "INCOMPLETE_OR_FAILED_TRUSTED_EXECUTOR")
        self.assertEqual(set(result["per_job"]), {"a"})

    def test_actual_cli_selected_python_trusted_subprocesses(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "live.json"
            target.write_text(json.dumps({"jobs": jobs()}), encoding="utf-8")
            proc = subprocess.run([sys.executable, "-I", "-S", "-B",
                                   str(ROOT / "python/adaptive_jobs.py"), "--mode", "live",
                                   "--input", str(target), "--python", sys.executable,
                                   "--workers", "2", "--memory-mb", "60"],
                                  check=False, capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["status"], "TRUSTED_REAL_SUBPROCESS_EXECUTOR_PASS")


if __name__ == "__main__":
    unittest.main()
