"""Independent legacy, free-threaded and non-CPython classification fixtures."""

import importlib.util
from datetime import date
from pathlib import Path
import sys
import unittest


MODULE_FILE = Path(__file__).resolve().parents[1] / "python" / "runtime_probe.py"
SPEC = importlib.util.spec_from_file_location("runtime_probe_under_test", MODULE_FILE)
runtime_probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime_probe)


class RuntimeProbeTests(unittest.TestCase):
    def test_actual_interpreter_is_read_only_and_named(self):
        result = runtime_probe.probe()
        self.assertEqual(result["status"], "INSPECTED")
        self.assertEqual(result["implementation"], sys.implementation.name)
        self.assertEqual(result["version"][:2], list(sys.version_info[:2]))

    def test_free_threaded_build_is_not_equated_with_gil_state(self):
        self.assertEqual(runtime_probe.classify("cpython", (3, 13), 1, True),
                         "FREE_THREADED_BUILD")
        self.assertEqual(runtime_probe.classify("cpython", (3, 15), 1, False),
                         "FREE_THREADED_BUILD")

    def test_standard_and_legacy_builds_are_distinct(self):
        self.assertEqual(runtime_probe.classify("cpython", (3, 12), None, None),
                         "LEGACY_GIL_BUILD")
        self.assertEqual(runtime_probe.classify("cpython", (3, 13), 0, True),
                         "STANDARD_GIL_BUILD")

    def test_other_interpreters_do_not_inherit_cpython_claims(self):
        self.assertEqual(runtime_probe.classify("pypy", (3, 11), None, None),
                         "OTHER_INTERPRETER")
        self.assertEqual(runtime_probe.classify("graalpy", (3, 12), None, None),
                         "OTHER_INTERPRETER")

    def test_externally_managed_global_install_is_explicitly_forbidden(self):
        self.assertEqual(runtime_probe.installation_policy(False, True),
                         "EXTERNALLY_MANAGED_INSTALL_FORBIDDEN")

    def test_virtual_environment_does_not_claim_system_installer_access(self):
        self.assertEqual(runtime_probe.installation_policy(True, True),
                         "VIRTUAL_ENV_NO_INSTALL_PERFORMED")
        self.assertEqual(runtime_probe.installation_policy(False, False),
                         "UNMARKED_NO_INSTALL_PERFORMED")

    def test_runtime_packaging_environment_is_metadata_only(self):
        metadata = runtime_probe.probe()["packaging_environment"]
        self.assertIsInstance(metadata["externally_managed_marker"], bool)
        self.assertIsInstance(metadata["virtual_environment_detected"], bool)
        self.assertIn(metadata["policy"], (
            "EXTERNALLY_MANAGED_INSTALL_FORBIDDEN",
            "VIRTUAL_ENV_NO_INSTALL_PERFORMED",
            "UNMARKED_NO_INSTALL_PERFORMED"))

    def test_lifecycle_all_seven_minors_as_of_2026_november(self):
        expected = {
            9: "END_OF_LIFE", 10: "END_OF_LIFE",
            11: "SECURITY_ONLY", 12: "SECURITY_ONLY", 13: "SECURITY_ONLY",
            14: "BUGFIX_AND_SECURITY", 15: "BUGFIX_AND_SECURITY",
        }
        for minor, status in expected.items():
            with self.subTest(minor=minor):
                info = runtime_probe.support_status(3, minor, date(2026, 11, 1))
                self.assertEqual(info["status"], status)
                self.assertEqual(info["source"], "https://devguide.python.org/versions/")
                self.assertEqual(info["schedule_checked_utc"], "2026-11-01")
                self.assertEqual(info["warning"] is None, status == "BUGFIX_AND_SECURITY")

    def test_lifecycle_eol_boundary_and_future_security_transition(self):
        self.assertEqual(runtime_probe.support_status(3, 10, date(2026, 10, 1))["status"],
                         "SECURITY_ONLY")
        self.assertEqual(runtime_probe.support_status(3, 10, date(2026, 10, 2))["status"],
                         "END_OF_LIFE")
        self.assertEqual(runtime_probe.support_status(3, 14, date(2027, 9, 1))["status"],
                         "BUGFIX_AND_SECURITY")
        self.assertEqual(runtime_probe.support_status(3, 14, date(2027, 11, 1))["status"],
                         "SECURITY_ONLY")
        self.assertEqual(runtime_probe.support_status(3, 14, date(2030, 11, 1))["status"],
                         "END_OF_LIFE")

    def test_unknown_future_minor_never_receives_unsupported_support_claim(self):
        future = runtime_probe.support_status(3, 16, date(2027, 11, 1))
        self.assertEqual(future["status"], "UNKNOWN")
        self.assertIsNone(future["end_of_life"])
        self.assertIsNotNone(future["warning"])
        self.assertEqual(runtime_probe.support_status(4, 0)["status"], "UNKNOWN")
