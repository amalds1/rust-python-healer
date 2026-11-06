"""Real 3.13t/3.14t/3.15t native atomic/lock tests, closed on GIL builds."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import sysconfig
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "freethreaded_native_v23.py"
spec = importlib.util.spec_from_file_location("freethreaded_native_v23", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FreeThreadedBuildAndNativeSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = module.actual_free_threaded_runtime()
        cls.free = cls.actual["free_threaded_build_verified"]
        cls.primary = module.native_thread_safety_probe(threads=4, operations=500)

    def test_actual_flags_and_soabi_consistent(self):
        if self.free:
            self.assertEqual(self.actual["status"], "ACTUAL_FREE_THREADED_NO_GIL_RUNNING")
            self.assertTrue(self.actual["py_gil_disabled_compile_flag"])
            self.assertTrue(self.actual["soabi_has_free_threaded_suffix"])
            self.assertIs(self.actual["actual_gil_enabled"], False)
        else:
            self.assertEqual(self.actual["status"], "NOT_RUNNING_SUPPORTED_FREE_THREADED_BUILD")

    def test_real_free_threading_build_variant_not_inferred_from_version(self):
        same_python_3_13_plus = sys.version_info[:2] >= (3, 13)
        self.assertEqual(self.free, bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
                         and same_python_3_13_plus and self.actual["actual_gil_enabled"] is False)

    def test_source_fixture_uses_native_atomic_and_lock_primitives(self):
        source = module._NATIVE_ATOMIC_AND_LOCKED
        self.assertIn("atomic_fetch_add_explicit", source)
        self.assertIn("PyThread_acquire_lock", source)
        self.assertIn("Py_MOD_GIL_NOT_USED", source)
        self.assertEqual(len(hashlib.sha256(source.encode()).hexdigest()), 64)

    def test_fixed_native_concurrency_positive_or_unavailable(self):
        self.assertEqual(self.primary["status"],
                         "REAL_NO_GIL_NATIVE_THREAD_SAFETY_FIXTURE_VERIFIED" if self.free
                         else "NOT_RUN_NO_REAL_FREE_THREADED_INTERPRETER")

    def test_exact_actual_native_counters_match_python_oracle(self):
        if self.free:
            self.assertEqual(self.primary["count_oracle"]["expected"], 2000)
            self.assertEqual(self.primary["count_oracle"]["atomic"], 2000)
            self.assertEqual(self.primary["count_oracle"]["locked"], 2000)
            self.assertTrue(self.primary["count_oracle"]["matched"])
        else:
            self.assertFalse(self.primary["runtime"]["free_threaded_build_verified"])

    def test_four_real_distinct_os_threads_performed_calls(self):
        if self.free:
            self.assertEqual(self.primary["actual_distinct_os_thread_ids"], 4)
            self.assertEqual(self.primary["real_native_function_calls_requested"], 4000)
            self.assertFalse(self.primary["threads_still_alive"])

    def test_imported_native_module_did_not_reenable_gil(self):
        if self.free:
            self.assertTrue(self.primary["gil_remained_disabled_after_native_import"])
            self.assertEqual(self.primary["native_fixture_kind"],
                             "ATOMIC_AND_LOCKED_CURATED")

    def test_no_unknown_native_packages_were_qualified(self):
        if self.free:
            self.assertTrue(self.primary["native_extension_loaded_from_curated_local_fixture"])
            self.assertFalse(self.primary["third_party_native_packages_qualified"])
            self.assertFalse(self.primary["unknown_project_or_package_source_compiled"])

    def test_two_independent_counting_methods_have_strict_gate(self):
        report = module.verify_native_counts(5000, 5000, 5000)
        self.assertEqual(report["status"], "TWO_INDEPENDENT_NATIVE_COUNTERS_MATCH")
        self.assertTrue(report["matched"])

    def test_wrong_or_missing_native_count_never_passes(self):
        for args in ((100, 99, 100), (100, 100, 99), (100, 101, 101)):
            with self.subTest(args=args):
                self.assertEqual(module.verify_native_counts(*args)["status"],
                                 "NATIVE_CONCURRENCY_MISMATCH_REJECTED")

    def test_malformed_native_count_never_passes(self):
        for args in ((100, True, 100), (100, None, 100), (100, 100, "100"),
                     (-1, 0, 0), (1000001, 1000001, 1000001)):
            with self.subTest(args=args):
                self.assertEqual(module.verify_native_counts(*args)["status"],
                                 "NO_EVIDENCE_NO_PASS")

    def test_real_mutation_gate_rejects_missing_call_on_all_t_runtimes(self):
        if self.free:
            negative = module.native_thread_safety_probe(threads=3, operations=300,
                                                         inject_missing_call=True)
            self.assertEqual(negative["status"], "NATIVE_TEST_MUTANT_REJECTED")
            self.assertFalse(negative["count_oracle"]["matched"])
            self.assertEqual(negative["count_oracle"]["atomic"], 899)
            self.assertEqual(negative["count_oracle"]["locked"], 899)

    def test_reject_unbounded_thread_work_without_running_native(self):
        if self.free:
            for kw in ({"threads": 0}, {"threads": 100}, {"threads": True},
                       {"operations": 0}, {"operations": 200000}):
                with self.subTest(kw=kw), self.assertRaises(ValueError):
                    module.native_thread_safety_probe(**kw)

    def test_cli_actual_gil_flags_replay(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "runtime"], capture_output=True, timeout=8)
        self.assertEqual(run.returncode, 0, run.stderr[-200:])
        detail = json.loads(run.stdout)
        self.assertEqual(detail["free_threaded_build_verified"], self.free)

    def test_cli_native_fixture_positive_or_notrun(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "native", "--threads", "3", "--operations", "200"],
                             capture_output=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stderr[-200:])
        report = json.loads(run.stdout)
        self.assertEqual(report["status"],
                         "REAL_NO_GIL_NATIVE_THREAD_SAFETY_FIXTURE_VERIFIED" if self.free
                         else "NOT_RUN_NO_REAL_FREE_THREADED_INTERPRETER")

    def test_cli_mutant_fails_quality_gate_but_reports_controlled_test(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "mutant", "--threads", "3", "--operations", "200"],
                             capture_output=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stderr[-200:])
        report = json.loads(run.stdout)
        self.assertEqual(report["status"],
                         "NATIVE_TEST_MUTANT_REJECTED" if self.free
                         else "NOT_RUN_NO_REAL_FREE_THREADED_INTERPRETER")


if __name__ == "__main__":
    unittest.main()
