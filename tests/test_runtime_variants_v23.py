"""F174 actual PyPy/CPython evidence partition, not synthetic-only tagging."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import sysconfig
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "runtime_variants_v23.py"
spec = importlib.util.spec_from_file_location("runtime_variants_v23", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ActualRuntimeIdentityTests(unittest.TestCase):
    def test_real_running_implementation_controls_classification(self):
        result = module.actual_runtime_identity()
        self.assertEqual(result["implementation"], sys.implementation.name)
        self.assertEqual(result["status"],
                         "ACTUAL_PYPY_RUNTIME_OBSERVED" if sys.implementation.name == "pypy"
                         else "ACTUAL_CPYTHON_RUNTIME_OBSERVED")
        self.assertTrue(result["actual_sys_implementation_inspected"])

    def test_real_pypy_version_struct_separate_from_python_version(self):
        result = module.actual_runtime_identity()
        if sys.implementation.name == "pypy":
            self.assertRegex(result["pypy_implementation_version"], r"\A\d+\.\d+\.\d+\Z")
            self.assertTrue(result["soabi"].startswith("pypy"))
        else:
            self.assertIsNone(result["pypy_implementation_version"])
            if sys.platform == "win32":
                self.assertEqual(result["soabi"], sysconfig.get_config_var("SOABI"))
                self.assertEqual(result["configured_extension_suffix"],
                                 sysconfig.get_config_var("EXT_SUFFIX"))
                self.assertTrue(result["soabi_consistent_with_implementation"])
                self.assertEqual(result["cache_tag"], "cpython-{}{}".format(*sys.version_info[:2]))
            else:
                self.assertTrue(result["soabi"].startswith("cpython"))

    @unittest.skipUnless(sys.platform == "win32", "Windows metadata consistency contract")
    def test_windows_abi_contradictions_are_refused(self):
        original = module.sysconfig.get_config_var
        for key, value in (("SOABI", "cp999-win_amd64"),
                           ("EXT_SUFFIX", ".cp999-win_amd64.pyd")):
            with self.subTest(key=key), mock.patch.object(module.sysconfig, "get_config_var",
                    side_effect=lambda name: value if name == key else original(name)):
                report = module.require_runtime_identity("cpython")
            self.assertEqual(report["status"], "CROSS_IMPLEMENTATION_EVIDENCE_REJECTED")
            self.assertFalse(report["compatible_evidence_reusable"])
        with mock.patch.object(module.platform, "machine", return_value="unknown_arch"):
            self.assertFalse(module.actual_runtime_identity()["soabi_consistent_with_implementation"])

    def test_native_abi_tags_are_implementation_specific(self):
        result = module.native_wheel_abi_family_for_runtime()
        self.assertEqual(result["status"], "NATIVE_ABI_FAMILY_SEPARATED")
        self.assertTrue(result["expected_native_wheel_python_tag"].startswith(
            "pp" if sys.implementation.name == "pypy" else "cp"))
        self.assertFalse(result["foreign_cpython_binary_imported"])

    def test_actual_identity_matching_does_not_attest_external_binaries(self):
        report = module.require_runtime_identity(sys.implementation.name)
        self.assertEqual(report["status"], "REAL_RUNTIME_IMPLEMENTATION_MATCH")
        self.assertTrue(report["compatible_evidence_reusable"])
        self.assertFalse(report["other_implementation_executed_in_this_process"])

    def test_cross_implementation_evidence_refused(self):
        foreign = "cpython" if sys.implementation.name == "pypy" else "pypy"
        report = module.require_runtime_identity(foreign)
        self.assertEqual(report["status"], "CROSS_IMPLEMENTATION_EVIDENCE_REJECTED")
        self.assertFalse(report["compatible_evidence_reusable"])

    def test_spoofed_or_invalid_implementation_names_rejected(self):
        for value in ("", "cpython3", "pypy\\n", None, "graalpython", True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.require_runtime_identity(value)

    def test_cli_actual_identity_json(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "identity"], capture_output=True, timeout=8)
        self.assertEqual(run.returncode, 0, run.stderr[-200:])
        self.assertEqual(json.loads(run.stdout)["implementation"], sys.implementation.name)

    def test_cli_cross_implementation_gate_rejects(self):
        foreign = "cpython" if sys.implementation.name == "pypy" else "pypy"
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "gate", "--expected", foreign],
                             capture_output=True, timeout=8)
        self.assertEqual(run.returncode, 0)
        self.assertEqual(json.loads(run.stdout)["status"],
                         "CROSS_IMPLEMENTATION_EVIDENCE_REJECTED")

    def test_cli_native_abi_classification_no_binary_import(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "abi"], capture_output=True, timeout=8)
        self.assertEqual(run.returncode, 0)
        self.assertFalse(json.loads(run.stdout)["pypy_native_compilation_or_import_proven"])

    def test_source_and_project_code_are_never_executed(self):
        result = module.actual_runtime_identity()
        self.assertFalse(result["python_project_source_executed"])
        self.assertFalse(result["cpython_native_extension_result_reused_for_pypy"])
        self.assertFalse(result["native_package_compatibility_proven"])


if __name__ == "__main__":
    unittest.main()
