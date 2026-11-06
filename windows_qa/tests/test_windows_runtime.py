"""Negative Windows evidence tests; native process PASS requires a Windows VM."""

import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


SRC = Path(__file__).resolve().parents[1] / "windows_runtime.py"
SPEC = importlib.util.spec_from_file_location("windows_runtime", SRC)
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)
ACTUAL_HOST_SYSTEM = runtime.platform.system()


class WindowsRuntimeTests(unittest.TestCase):
    def setUp(self):
        # platform.system() may itself call subprocess.run() on Windows.
        # Keep host metadata outside mocks intended only for FIXED_CHILD.
        self.system_patch = mock.patch.object(runtime.platform, "system", return_value=ACTUAL_HOST_SYSTEM)
        self.system_patch.start()
        self.addCleanup(self.system_patch.stop)
        # A mocked child is not evidence of this machine's real Home edition.
        self.edition_patch = mock.patch.object(runtime.platform, "win32_edition", return_value="UNAVAILABLE", create=True)
        self.edition_patch.start()
        self.addCleanup(self.edition_patch.stop)

    def test_all_target_minor_versions_are_enumerated(self):
        self.assertEqual(runtime.SUPPORTED,
                         ("3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15"))

    def test_invalid_version_and_injection_rejected_before_probe(self):
        for value in ("3.16", "3.8", "3.12;dir", "", 3.12, None, ["3.12"]):
            with self.subTest(value=value), self.assertRaisesRegex(
                    ValueError, "invalid_expected_minor"):
                runtime.inspect_runtime(value)

    def test_actual_linux_is_not_a_windows_pass(self):
        if sys.platform == "win32":
            self.skipTest("actual Windows runtime needs its own fixture")
        report = runtime.inspect_runtime("3.12")
        self.assertEqual(report["status"], "NOT_RUN")
        self.assertEqual(report["reason"], "REAL_WINDOWS_HOST_REQUIRED")
        self.assertFalse(report["exact_windows_11_home_host_verified"])
        self.assertFalse(report["unknown_project_code_executed"])
        self.assertFalse(report["sandbox_isolation_proven"])

    def test_windows_non_x64_reports_not_run(self):
        with mock.patch.object(runtime.sys, "platform", "win32"), \
                mock.patch.object(runtime.os, "name", "nt"), \
                mock.patch.object(runtime.platform, "machine", return_value="ARM64"):
            report = runtime.inspect_runtime("3.12")
        self.assertEqual(report["status"], "NOT_RUN")
        self.assertEqual(report["reason"], "ACTUAL_WINDOWS_X64_REQUIRED")

    def test_windows_wrong_python_minor_is_fail(self):
        with mock.patch.object(runtime.sys, "platform", "win32"), \
                mock.patch.object(runtime.os, "name", "nt"), \
                mock.patch.object(runtime.platform, "machine", return_value="AMD64"):
            report = runtime.inspect_runtime("3.10" if sys.version_info.minor != 10 else "3.9")
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["reason"], "ACTUAL_CPYTHON_VERSION_MISMATCH")

    def test_windows_fixed_child_mock_pass_with_explicit_scope(self):
        identity = json.dumps({"version": list(sys.version_info[:2]),
                               "implementation": "cpython", "pid": 93210}).encode("ascii")
        completed = mock.Mock(returncode=0, stdout=identity, stderr=b"")
        expected = "{}.{}".format(*sys.version_info[:2])
        with mock.patch.object(runtime.sys, "platform", "win32"), \
                mock.patch.object(runtime.os, "name", "nt"), \
                mock.patch.object(runtime.platform, "machine", return_value="AMD64"), \
                mock.patch.object(runtime.subprocess, "run", return_value=completed) as run:
            report = runtime.inspect_runtime(expected)
        self.assertEqual(report["status"], "SCOPED_WINDOWS_PROCESS_PASS")
        self.assertFalse(report["exact_windows_11_home_host_verified"])
        self.assertEqual(report["nvidia_gpu_runtime"],
                         "NOT_RUN_DEDICATED_GPU_RUNNER_REQUIRED")
        self.assertFalse(report["production_update_qualified"])
        self.assertEqual(run.call_args.args[0][-2], "-c")
        self.assertEqual(run.call_args.args[0][-1], runtime.FIXED_CHILD)
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_forged_same_pid_fails(self):
        identity = json.dumps({"version": list(sys.version_info[:2]),
                               "implementation": "cpython", "pid": os.getpid()}).encode("ascii")
        completed = mock.Mock(returncode=0, stdout=identity, stderr=b"")
        with mock.patch.object(runtime.sys, "platform", "win32"), \
                mock.patch.object(runtime.os, "name", "nt"), \
                mock.patch.object(runtime.platform, "machine", return_value="AMD64"), \
                mock.patch.object(runtime.subprocess, "run", return_value=completed):
            report = runtime.inspect_runtime("{}.{}".format(*sys.version_info[:2]))
        self.assertEqual(report["status"], "FAIL")

    def test_fixed_child_failure_fails_without_raw_stderr(self):
        completed = mock.Mock(returncode=1, stdout=b"", stderr=b"secret=password")
        with mock.patch.object(runtime.sys, "platform", "win32"), \
                mock.patch.object(runtime.os, "name", "nt"), \
                mock.patch.object(runtime.platform, "machine", return_value="AMD64"), \
                mock.patch.object(runtime.subprocess, "run", return_value=completed):
            report = runtime.inspect_runtime("{}.{}".format(*sys.version_info[:2]))
        self.assertEqual(report["status"], "FAIL")
        self.assertNotIn("password", str(report))

    def test_timeout_is_not_run_not_pass(self):
        with mock.patch.object(runtime.sys, "platform", "win32"), \
                mock.patch.object(runtime.os, "name", "nt"), \
                mock.patch.object(runtime.platform, "machine", return_value="AMD64"), \
                mock.patch.object(runtime.subprocess, "run", side_effect=OSError("secret token")):
            report = runtime.inspect_runtime("{}.{}".format(*sys.version_info[:2]))
        self.assertEqual(report["status"], "NOT_RUN")
        self.assertNotIn("secret", str(report))

    def test_fixed_child_does_not_import_user_sources(self):
        self.assertNotIn("import pathlib", runtime.FIXED_CHILD)
        self.assertNotIn("exec(", runtime.FIXED_CHILD)
        self.assertNotIn("eval(", runtime.FIXED_CHILD)

    def test_windows_server_is_never_mislabeled_windows_11_home(self):
        with mock.patch.object(runtime.sys, "platform", "win32"), \
                mock.patch.object(runtime.os, "name", "nt"), \
                mock.patch.object(runtime.platform, "win32_edition", return_value="ServerStandard", create=True), \
                mock.patch.object(runtime.sys, "getwindowsversion", return_value=SimpleNamespace(build=26100), create=True):
            report = runtime.inspect_runtime("3.9")
        self.assertEqual(report["windows_edition"], "ServerStandard")
        self.assertFalse(report["exact_windows_11_home_host_verified"])

    def test_windows_11_home_probe_requires_real_edition_and_build(self):
        expected = "{}.{}".format(*sys.version_info[:2])
        identity = json.dumps({"version": list(sys.version_info[:2]),
                               "implementation": "cpython", "pid": 93210}).encode("ascii")
        completed = mock.Mock(returncode=0, stdout=identity, stderr=b"")
        with mock.patch.object(runtime.sys, "platform", "win32"), \
                mock.patch.object(runtime.os, "name", "nt"), \
                mock.patch.object(runtime.platform, "machine", return_value="AMD64"), \
                mock.patch.object(runtime.platform, "win32_edition", return_value="Core", create=True), \
                mock.patch.object(runtime.sys, "getwindowsversion", return_value=SimpleNamespace(build=22631), create=True), \
                mock.patch.object(runtime.subprocess, "run", return_value=completed):
            report = runtime.inspect_runtime(expected)
        self.assertTrue(report["exact_windows_11_home_host_verified"])
        self.assertFalse(report["production_update_qualified"])


if __name__ == "__main__":
    unittest.main()
