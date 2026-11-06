"""Real, bounded CPython start-method and interpreter isolation checks.

Each version uses only the trusted literal worker in concurrency_probe.py.
An OS-denied forkserver is NOT_RUN, never a green test of forkserver itself.
"""

import json
import multiprocessing
from pathlib import Path
import platform
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "python" / "concurrency_probe.py"
sys.path.insert(0, str(ROOT / "python"))
import concurrency_probe as module  # noqa: E402 -- explicit trusted test-only sys.path


class ConcurrencyProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = module.probe()
        cls.methods = {item["method"]: item for item in cls.report["method_results"]}

    def test_all_three_real_start_methods_are_explicitly_probed(self):
        self.assertEqual(tuple(self.methods), module.METHODS)
        self.assertEqual(self.report["process_count_limit"], 3)
        self.assertEqual(self.report["schema_version"], 1)

    def test_fork_real_child_or_explicit_platform_denial(self):
        result = self.methods["fork"]
        if "fork" in multiprocessing.get_all_start_methods():
            self.assertEqual(result["status"], "PASS")
            self.assertTrue(result["child_pid_different"])
        else:
            self.assertEqual(result["status"], "UNSUPPORTED_ON_PLATFORM")

    def test_spawn_real_child_or_explicit_platform_denial(self):
        result = self.methods["spawn"]
        if "spawn" in multiprocessing.get_all_start_methods():
            self.assertEqual(result["status"], "PASS")
            self.assertTrue(result["child_pid_different"])
        else:
            self.assertEqual(result["status"], "UNSUPPORTED_ON_PLATFORM")

    def test_forkserver_real_child_or_visible_denial(self):
        result = self.methods["forkserver"]
        if "forkserver" not in multiprocessing.get_all_start_methods():
            self.assertEqual(result["status"], "UNSUPPORTED_ON_PLATFORM")
        elif result["status"] == "PASS":
            self.assertTrue(result["child_executed_fixed_fixture"])
            self.assertTrue(result["child_pid_different"])
        else:
            self.assertEqual(result["status"], "NOT_RUN")
            self.assertEqual(result["reason"], "os_or_environment_denied")
            self.assertFalse(result["child_executed_fixed_fixture"])

    def test_denial_never_promoted_to_overall_pass(self):
        all_completed = all(row["status"] == "PASS" for row in self.methods.values())
        if not all_completed:
            self.assertEqual(self.report["status"], "PARTIAL_OR_NOT_RUN")
        self.assertTrue(self.report["no_implicit_security_sandbox"])
        self.assertFalse(self.report["untrusted_source_executed"])

    def test_real_linux_version_specific_default_method(self):
        actual = multiprocessing.get_start_method()
        self.assertEqual(self.report["actual_default_start_method"], actual)
        if platform.system() == "Linux":
            expected = "forkserver" if sys.version_info[:2] >= (3, 14) else "fork"
            self.assertEqual(actual, expected)
            self.assertTrue(self.report["default_matches_platform_version_expectation"])
            self.assertEqual(self.report["platform_expected_default"], expected)
        else:
            self.assertIsNone(self.report["platform_expected_default"])

    def test_real_interpreter_isolation_or_version_absence(self):
        result = self.report["subinterpreter"]
        self.assertEqual(result["module"], "concurrent.interpreters")
        if sys.version_info[:2] < (3, 14):
            self.assertEqual(result["status"], "NOT_AVAILABLE_BEFORE_3_14")
        else:
            # CPython 3.14/3.15 in this compatibility matrix have the module.
            self.assertEqual(result["status"], "PASS")
            self.assertTrue(result["two_distinct_interpreters"])
            self.assertTrue(result["builtin_namespace_separate"])
            self.assertTrue(result["fixed_code_executed_in_subinterpreter"])

    def test_interpreter_isolation_is_not_a_security_sandbox_claim(self):
        result = self.report["subinterpreter"]
        self.assertFalse(result["security_boundary"])
        self.assertFalse(result["independent_memory_isolation_verified"])
        self.assertFalse(result["external_packages_tested"])
        self.assertFalse(result["untrusted_source_executed"])

    def test_runtime_version_and_os_are_in_the_report(self):
        self.assertEqual(self.report["python_minor"], "{}.{}".format(*sys.version_info[:2]))
        self.assertEqual(self.report["os"], platform.system())
        self.assertEqual(self.report["implementation"], sys.implementation.name)

    def test_invalid_methods_and_duplicates_rejected(self):
        for choices in (("not_a_start_method",), ("fork", "fork"),
                        ("spawn", "forkserver", "spawn")):
            with self.assertRaisesRegex(ValueError, "invalid_requested_methods"):
                module.probe(choices)
        with self.assertRaisesRegex(ValueError, "unknown_start_method"):
            module.inspect_method("__import__('os').system('id')")

    def test_unsupported_platform_method_explicitly_reported(self):
        with mock.patch.object(module.multiprocessing, "get_all_start_methods", return_value=[]):
            result = module.inspect_method("forkserver")
        self.assertEqual(result["status"], "UNSUPPORTED_ON_PLATFORM")
        self.assertFalse(result["child_executed_fixed_fixture"])

    def test_worker_environment_failure_not_a_pass(self):
        # Exercise the context-denied branch even on native Windows, where
        # fork is otherwise rejected earlier as unsupported. Separate real
        # method tests above still require Windows fork/forkserver refusal.
        with mock.patch.object(module.multiprocessing, "get_all_start_methods", return_value=["fork"]), \
                mock.patch.object(module.multiprocessing, "get_context", side_effect=PermissionError):
            result = module.inspect_method("fork")
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertEqual(result["error_type"], "PermissionError")
        self.assertFalse(result["child_executed_fixed_fixture"])

    def test_main_cli_spawn_json_and_no_untrusted_execution(self):
        process = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(HELPER), "--method", "spawn"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr[-500:])
        data = json.loads(process.stdout.decode("utf-8"))
        self.assertEqual(len(data["method_results"]), 1)
        self.assertEqual(data["method_results"][0]["status"], "PASS")
        self.assertFalse(data["untrusted_source_executed"])

    def test_cli_rejects_untrusted_code_injection_argument(self):
        process = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(HELPER),
             "--method", "__import__('os').system('id')"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False,
        )
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, b"")
        self.assertIn(b"invalid choice", process.stderr)

    def test_single_method_reports_bounded_child_count(self):
        result = module.probe(("fork",))
        self.assertEqual(result["process_count_limit"], 1)
        self.assertEqual(len(result["method_results"]), 1)
        self.assertEqual(result["method_results"][0]["method"], "fork")


if __name__ == "__main__":
    unittest.main()
