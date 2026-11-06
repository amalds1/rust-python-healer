"""Actual per-child Linux/Windows CPU/RSS and trusted-only scheduler tests."""

from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("resource_meter", ROOT / "python" / "resource_meter.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


class ResourceMeterTests(unittest.TestCase):
    def test_real_child_cpu_and_peak_resident_set_measured_with_pid(self):
        report = module.measure_worker(250_000, 8 * 1024 * 1024)
        self.assertEqual(report["status"], "MEASURED_TRUSTED_SUBPROCESS_NOT_PIPELINE")
        self.assertEqual(report["subprocess_exit_code"], 0)
        self.assertGreater(report["pid"], 0)
        self.assertGreater(report["child_cpu_total_s"], 0)
        self.assertGreater(report["workload_delta_cpu_total_s"], 0)
        self.assertGreater(report["child_peak_rss_kib"], 1000)
        self.assertGreater(report["wall_elapsed_s"], 0)
        self.assertGreater(report["worker_elapsed_s"], 0)
        self.assertFalse(report["source_executed"])
        self.assertFalse(report["all_pipeline_processes_measured"])
        if sys.platform == "win32":
            self.assertEqual(report["measurement_origin"],
                             "windows_owned_handle_GetProcessTimes_K32GetProcessMemoryInfo")
            self.assertEqual(report["maxrss_unit"],
                             "KiB_windows_PeakWorkingSetSize_bytes_div_1024")
            self.assertTrue(report["bound_handle_pid_verified"])
            self.assertGreater(report["child_creation_time_100ns"], 0)
            self.assertTrue(report["samples_taken_while_child_alive"])
            self.assertTrue(all(report["cleanup"].values()))
        else:
            self.assertEqual(report["measurement_origin"], "os.wait4_exact_child_linux_rusage")
            self.assertEqual(report["maxrss_unit"], "KiB_linux_ru_maxrss")

    def test_cpu_baseline_delta_is_computed_from_same_child(self):
        report = module.measure_worker(300_000, 1_048_576)
        self.assertAlmostEqual(report["child_cpu_user_s"] -
                               report["startup_baseline_cpu_user_s"],
                               report["workload_delta_cpu_user_s"], places=6)
        self.assertAlmostEqual(report["child_cpu_system_s"] -
                               report["startup_baseline_cpu_system_s"],
                               report["workload_delta_cpu_system_s"], places=6)
        self.assertAlmostEqual(report["workload_delta_cpu_total_s"],
                               report["workload_delta_cpu_user_s"] +
                               report["workload_delta_cpu_system_s"])
        self.assertEqual(report["python_minor"],
                         "{}.{}".format(sys.version_info.major, sys.version_info.minor))

    def test_memory_high_water_is_observed_in_real_linux_peak_rss(self):
        report = module.measure_worker(20_000, 16 * 1024 * 1024)
        self.assertEqual(report["requested_memory_bytes"], 16 * 1024 * 1024)
        # A child may inherit an already-high ru_maxrss from a large test
        # runner; zero *growth* is valid even when its final peak is real.
        # Never fabricate a positive delta in that situation.
        self.assertGreater(report["child_peak_rss_kib"], 16 * 1024)
        self.assertGreaterEqual(report["workload_peak_rss_growth_kib"], 0)
        self.assertGreaterEqual(report["child_peak_rss_kib"],
                                report["startup_baseline_peak_rss_kib"])
        self.assertEqual(report["child_peak_rss_kib"] -
                         report["startup_baseline_peak_rss_kib"],
                         report["workload_peak_rss_growth_kib"])

    def test_fingerprint_is_deterministic_without_claiming_cpu_time_is(self):
        a = module.measure_worker(50_000, 0)
        b = module.measure_worker(50_000, 0)
        different = module.measure_worker(50_001, 0)
        self.assertEqual(a["fingerprint"], b["fingerprint"])
        self.assertNotEqual(a["fingerprint"], different["fingerprint"])
        self.assertGreater(a["pid"], 0)
        self.assertGreater(b["pid"], 0)

    def test_several_independent_meters_are_in_real_units(self):
        report = module.measure_worker(100_000, 4_194_304)
        metrics = (
            "child_cpu_user_s", "child_cpu_system_s", "child_cpu_total_s",
            "workload_delta_cpu_total_s", "child_peak_rss_kib",
            "workload_peak_rss_growth_kib", "wall_elapsed_s")
        self.assertGreaterEqual(len(metrics), 5)
        for key in metrics:
            self.assertIsInstance(report[key], (float, int), key)
            self.assertGreaterEqual(report[key], 0, key)
        for key in ("voluntary_context_switches", "involuntary_context_switches"):
            if sys.platform == "win32":
                self.assertIsNone(report[key], "Windows must not invent context-switch counts")
                self.assertEqual(report["context_switches_status"],
                                 "NOT_RUN_WINDOWS_COUNTER_NOT_AVAILABLE")
            else:
                self.assertIsInstance(report[key], (float, int), key)
                self.assertGreaterEqual(report[key], 0, key)

    def test_invalid_worker_inputs_rejected_before_process_launch(self):
        invalid = (
            (True, 0, 2), (-1, 0, 2), (2_000_001, 0, 2),
            (1.5, 0, 2), (1, -1, 2), (1, 67_108_865, 2),
            (1, 0, float("nan")), (1, 0, -1), (1, 0, 61))
        with mock.patch.object(module.subprocess, "Popen") as launch:
            for args in invalid:
                with self.subTest(args=args):
                    with self.assertRaises(ValueError):
                        module.measure_worker(*args)
            launch.assert_not_called()

    def test_timeout_cleanup_terminates_only_its_own_child(self):
        if sys.platform == "win32":
            processes = []
            real_popen = module.subprocess.Popen

            def own_process(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                processes.append(process)
                return process

            with mock.patch.object(module.subprocess, "Popen", side_effect=own_process), \
                    mock.patch.object(module, "_windows_readline_with_deadline",
                                      side_effect=TimeoutError("test_forced_timeout")):
                with self.assertRaisesRegex(TimeoutError, "test_forced_timeout"):
                    module.measure_worker(20_000, 0)
            self.assertEqual(len(processes), 1)
            child = processes[0]
            self.assertIsNotNone(child.returncode)
            self.assertTrue(child._handle.closed)
            self.assertTrue(all(stream.closed for stream in
                                (child.stdin, child.stdout, child.stderr)))
            self.assertEqual(child.args[-3], module._TRUSTED_WINDOWS_WORKER)
            # Exercise the actual Windows pipe deadline as well as the forced
            # error path: this reviewed silent literal cannot reach READY.
            started = time.monotonic()
            with mock.patch.object(module.subprocess, "Popen", side_effect=own_process), \
                    mock.patch.object(module, "_TRUSTED_WINDOWS_WORKER",
                                      "import time; time.sleep(5)"):
                with self.assertRaises(TimeoutError):
                    module.measure_worker(1, 0, timeout_s=0.1)
            self.assertLess(time.monotonic() - started, 2.5)
            self.assertEqual(len(processes), 2)
            self.assertIsNotNone(processes[-1].returncode)
            self.assertTrue(processes[-1]._handle.closed)
            self.assertTrue(all(stream.closed for stream in
                                (processes[-1].stdin, processes[-1].stdout, processes[-1].stderr)))
        else:
            with mock.patch.object(module, "_wait_exact_child",
                                   side_effect=TimeoutError("test_forced_timeout")):
                with self.assertRaisesRegex(TimeoutError, "test_forced_timeout"):
                    module.measure_worker(20_000, 0)

    def test_worker_contains_no_callsite_for_user_code_or_filename(self):
        for literal in (module._TRUSTED_WORKER, module._TRUSTED_WINDOWS_WORKER):
            self.assertNotIn("exec(", literal)
            self.assertNotIn("eval(", literal)
            self.assertNotIn("importlib", literal)
        self.assertFalse(hasattr(module, "run_source_file"))
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "possible-execution.marker"
            report = module.measure_worker(1000, 0)
            self.assertFalse(marker.exists())
            self.assertFalse(report["source_executed"])

    def test_cli_worker_isolated_interpreter_outputs_valid_json(self):
        script = ROOT / "python" / "resource_meter.py"
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(script), "worker",
             "--iterations", "40000", "--memory-bytes", "1048576"],
            capture_output=True, text=True, check=True)
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "MEASURED_TRUSTED_SUBPROCESS_NOT_PIPELINE")
        self.assertEqual(report["iterations"], 40000)
        self.assertEqual(report["requested_memory_bytes"], 1048576)

    def test_linux_wait4_required_instead_of_global_child_usage(self):
        with mock.patch.object(module.sys, "platform", "linux"), \
                mock.patch.object(module.os, "wait4", None, create=True):
            # Capability check is explicit; no silent fallback to RUSAGE_CHILDREN.
            with self.assertRaises((TypeError, RuntimeError)):
                module.measure_worker(1, 0)

    def test_queue_noop_measures_completion_and_positive_throughput(self):
        report = module.measure_synthetic_queue(workers=2, jobs=20, hold_ms=5)
        self.assertEqual(report["status"],
                         "MEASURED_SYNTHETIC_SCHEDULER_NOT_PRODUCTION")
        self.assertEqual(report["jobs_submitted"], 20)
        self.assertEqual(report["jobs_completed"], 20)
        self.assertGreater(report["throughput_jobs_per_second"], 0)
        self.assertGreaterEqual(report["queue_depth_peak_observed"], 1)
        self.assertFalse(report["production_scheduler_instrumented"])
        self.assertFalse(report["source_executed"])

    def test_queue_pressure_causes_measurable_wait_with_single_worker(self):
        report = module.measure_synthetic_queue(workers=1, jobs=10, hold_ms=10)
        self.assertEqual(report["jobs_completed"], 10)
        self.assertGreater(report["queue_wait_p95_ms"], 20)
        self.assertGreaterEqual(report["queue_wait_max_ms"],
                                report["queue_wait_p95_ms"])
        self.assertGreaterEqual(report["queue_wait_p95_ms"],
                                report["queue_wait_p50_ms"])

    def test_queue_noop_single_job_has_valid_zero_or_nearzero_wait(self):
        report = module.measure_synthetic_queue(workers=4, jobs=1, hold_ms=0)
        self.assertEqual(report["jobs_completed"], 1)
        self.assertGreaterEqual(report["queue_wait_p50_ms"], 0)
        self.assertEqual(report["queue_wait_p50_ms"], report["queue_wait_p95_ms"])

    def test_queue_validation_rejects_bools_negative_overlimits(self):
        for args in ((True, 3, 10), (0, 2, 0), (17, 2, 0),
                     (2, 0, 0), (2, 257, 0), (2, 2, -1), (2, 2, 101)):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    module.measure_synthetic_queue(*args)

    def test_percentile_is_measured_from_real_distribution_not_average(self):
        self.assertEqual(module._percentile([1, 2, 3, 4, 5], 50), 3)
        self.assertEqual(module._percentile([1, 2, 3, 4, 5], 95), 5)
        self.assertEqual(module._percentile([], 95), 0)

    def test_cli_synthetic_queue_has_unambiguous_partial_scope(self):
        script = ROOT / "python" / "resource_meter.py"
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(script), "synthetic-queue",
             "--workers", "1", "--jobs", "3", "--hold-ms", "5"],
            capture_output=True, text=True, check=True)
        report = json.loads(completed.stdout)
        self.assertEqual(report["jobs_submitted"], 3)
        self.assertEqual(report["jobs_completed"], 3)
        self.assertFalse(report["production_scheduler_instrumented"])


if __name__ == "__main__":
    unittest.main()
