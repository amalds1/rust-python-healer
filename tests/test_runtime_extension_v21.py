"""Actual trusted v0.21 probes and negative, source-safe compatibility tests."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from python import runtime_extension_v21 as module


class TrustedTaskGroupRuntimeTests(unittest.TestCase):
    def test_real_nested_exceptiongroup_taskgroup_and_except_star_by_version(self):
        report = module.probe_exceptiongroups()
        if sys.version_info < (3, 11):  # noqa: UP036 - matrix includes CPython 3.9/3.10
            self.assertEqual(report["status"], "NOT_SUPPORTED")
            self.assertFalse(report["trusted_fixture_executed"])
        else:
            self.assertEqual(report["status"], "TRUSTED_RUNTIME_VERIFIED")
            self.assertEqual(report["taskgroup"], {"value": 1, "type": 1})
            self.assertEqual(report["nested_group"],
                             {"inner_value": 1, "outer_type": 1})
            self.assertTrue(report["except_star_runtime_executed"])
            self.assertTrue(report["trusted_fixture_executed"])
            self.assertFalse(report["arbitrary_async_project_verified"])
        self.assertFalse(report["user_source_executed"])
        self.assertNotIn("PRIVATE", json.dumps(report))

    def test_missing_interpreter_does_not_fake_taskgroup_success(self):
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(
                ValueError, "trusted_subprocess_unavailable_or_timeout"):
            module.probe_exceptiongroups(Path(temporary) / "no-python")


class StaticNotebookAndEmbeddedTests(unittest.TestCase):
    def notebook(self):
        return {"nbformat": 4, "nbformat_minor": 5, "metadata": {}, "cells": [
            {"cell_type": "markdown", "source": ["Do not run this prose"]},
            {"cell_type": "code", "source": ["x = 1\n", "print(x)\n"]},
            {"cell_type": "code", "source": "def broken(: pass\n"},
            {"cell_type": "code", "source": "%time x + 1\n"},
            {"cell_type": "code", "source": "!pip install unknown-package\n"},
        ]}

    def test_real_ast_compile_only_positive_negative_and_magics(self):
        report = module.inspect_notebook(json.dumps(self.notebook()))
        self.assertEqual(report["status"], "STATIC_NOTEBOOK_INSPECTION")
        self.assertEqual(report["code_cells"], 4)
        self.assertEqual([item["static_syntax_status"] for item in report["results"]], [
            "PYTHON_SYNTAX_VALID", "INVALID_OR_UNSUPPORTED_SYNTAX",
            "IPYTHON_MAGIC_NOT_PYTHON_AST", "IPYTHON_MAGIC_NOT_PYTHON_AST"])
        self.assertFalse(report["notebook_executed"])
        self.assertFalse(report["extensions_loaded"])
        self.assertNotIn("unknown-package", json.dumps(report))

    def test_notebook_private_code_never_executes_or_exposes_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "MUST_NOT_EXIST"
            notebook = self.notebook()
            notebook["cells"] = [{"cell_type": "code", "source":
                                  f"from pathlib import Path\n"
                                  f"Path({str(marker)!r}).write_text('SECRET')\n"}]
            report = module.inspect_notebook(json.dumps(notebook))
            self.assertEqual(report["results"][0]["static_syntax_status"],
                             "PYTHON_SYNTAX_VALID")
            self.assertFalse(marker.exists())
            self.assertNotIn("SECRET", json.dumps(report))

    def test_malformed_notebook_json_duplicate_keys_nul_and_schema_rejected(self):
        cases = ("{", '{"nbformat": 4, "nbformat": 4, "cells": []}',
                 json.dumps({"nbformat": 3, "cells": []}), "x\0",
                 json.dumps({"nbformat": 4, "cells": [{}]}),
                 json.dumps({"nbformat": 4, "cells": [
                     {"cell_type": "code", "source": 3}]}),
                 json.dumps({"nbformat": 4, "cells": [
                     {"cell_type": "code", "source": "x" * 20000}]}),
                 "x" * 140000)
        for payload in cases:
            with self.subTest(case=payload[:20]), self.assertRaises((ValueError, TypeError)):
                module.inspect_notebook(payload)

    def test_embedded_python_fences_are_read_only_and_other_fences_skipped(self):
        markdown = ("# Intro\n"
                    "```python\nx = 7\n```\n"
                    "```javascript\nalert('secret')\n```\n"
                    "```py\ndef broken(:\n```\n")
        report = module.inspect_embedded_python(markdown)
        self.assertEqual(report["code_cells"], 2)
        self.assertEqual(report["results"][0]["static_syntax_status"],
                         "PYTHON_SYNTAX_VALID")
        self.assertEqual(report["results"][1]["static_syntax_status"],
                         "INVALID_OR_UNSUPPORTED_SYNTAX")
        self.assertFalse(report["source_executed"])
        self.assertNotIn("secret", json.dumps(report))

    def test_embedded_source_limits_and_surrogate_denied(self):
        for source in ("#" * 140000, "```python\nx = '\ud800'\n```",
                       "```python\npass\n```\n" * 80):
            with self.subTest(length=len(source)), self.assertRaises(ValueError):
                module.inspect_embedded_python(source)


class AllowlistedTestsAndDifferentialTests(unittest.TestCase):
    def test_real_fixed_unittest_positive_and_negative_run(self):
        positive = module.run_allowlisted_test("unittest_pass")
        negative = module.run_allowlisted_test("unittest_negative")
        self.assertEqual(positive["status"], "TRUSTED_TEST_PASS")
        self.assertEqual(positive["tests_run"], 1)
        self.assertEqual(negative["status"], "TRUSTED_TEST_FAIL")
        self.assertEqual(negative["failure_count"], 1)
        self.assertFalse(positive["user_code_executed"])
        self.assertFalse(negative["shell_invoked"])

    def test_real_fixed_compile_command_runs_without_importing_user_code(self):
        result = module.run_allowlisted_test("compile_positive")
        self.assertEqual(result["status"], "TRUSTED_TEST_PASS")
        self.assertTrue(result["fixture_executed"])
        self.assertFalse(result["user_code_executed"])

    def test_unlisted_commands_refused_before_subprocess(self):
        for candidate in ("pytest", "python -c 'print(1)'", "unittest_pass && echo bad",
                          None, "../trusted", "unittest_pass; rm -r unknown"):
            with (self.subTest(candidate=candidate),
                  mock.patch.object(module.subprocess, "run", side_effect=AssertionError(
                      "no subprocess allowed for unlisted input")),
                  self.assertRaisesRegex(ValueError, "test_case_not_allowlisted")):
                module.run_allowlisted_test(candidate)

    def test_even_internal_subprocess_helper_refuses_unknown_program(self):
        with (mock.patch.object(module.subprocess, "run", side_effect=AssertionError(
                "source must not be executed")),
              self.assertRaisesRegex(ValueError, "trusted_subprocess_program_not_allowlisted")):
            module._fixed_subprocess("import os; os.system('unknown-source')")

    def test_fixed_differential_oracle_detects_equivalent_and_wrong_candidates(self):
        equal = module.probe_fixed_differential("equivalent_add")
        error_case = module.probe_fixed_differential("equivalent_error")
        unequal = module.probe_fixed_differential("faulty_add")
        self.assertEqual(equal["status"], "MATCHED_TRUSTED_CASES")
        self.assertEqual(error_case["status"], "MATCHED_TRUSTED_CASES")
        self.assertEqual(unequal["status"], "DIFFERENCE_DETECTED")
        self.assertEqual(unequal["matching_cases"], 0)
        for report in (equal, error_case, unequal):
            self.assertEqual(report["input_cases"], 3)
            self.assertFalse(report["arbitrary_program_equivalence_proven"])
            self.assertFalse(report["untrusted_source_executed"])

    def test_differential_unknown_input_refused_without_running(self):
        for candidate in ("", "equivalent_add --evil", None, "\ud800"):
            with (self.subTest(candidate=candidate),
                  mock.patch.object(module.subprocess, "run", side_effect=AssertionError(
                      "unknown candidate must not execute")),
                  self.assertRaises(ValueError)):
                module.probe_fixed_differential(candidate)


class ReadOnlyFrameworkDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_pytest_unittest_tox_nox_all_observed_from_local_configs(self):
        (self.root / "pytest.ini").write_text("[pytest]\naddopts = -q\n", encoding="utf-8")
        (self.root / "tox.ini").write_text("[tox]\nenv_list = py39\n", encoding="utf-8")
        (self.root / "noxfile.py").write_text("raise RuntimeError('PRIVATE_EXECUTED')\n",
                                              encoding="utf-8")
        tests = self.root / "tests"
        tests.mkdir()
        (tests / "test_real.py").write_text("pass\n", encoding="utf-8")
        report = module.discover_test_frameworks(self.root)
        self.assertEqual(report["status"], "READ_ONLY_FRAMEWORK_DISCOVERY")
        self.assertEqual(report["frameworks"],
                         {"pytest": True, "unittest": True, "tox": True, "nox": True})
        self.assertEqual(report["unittest_pattern_files"], 1)
        self.assertFalse(report["configs_executed_or_imported"])
        self.assertFalse(report["test_commands_executed"])
        self.assertNotIn("PRIVATE_EXECUTED", json.dumps(report))

    def test_pyproject_pytest_and_tox_metadata_detection(self):
        (self.root / "pyproject.toml").write_text(
            "[tool.pytest.ini_options]\ntestpaths = ['tests']\n[tool.tox]\n",
            encoding="utf-8")
        report = module.discover_test_frameworks(self.root)
        self.assertTrue(report["frameworks"]["pytest"])
        self.assertTrue(report["frameworks"]["tox"])
        self.assertFalse(report["frameworks"]["nox"])
        self.assertFalse(report["frameworks"]["unittest"])

    def test_absent_config_does_not_infer_frameworks(self):
        report = module.discover_test_frameworks(self.root)
        self.assertEqual(report["frameworks"],
                         {"pytest": False, "unittest": False, "tox": False, "nox": False})

    def test_discovery_refuses_config_and_test_symlink_hardlink_and_oversize(self):
        (self.root / "pytest.ini").symlink_to(self.root / "outside.ini")
        with self.assertRaisesRegex(ValueError, "discovery_config_symlink_refused"):
            module.discover_test_frameworks(self.root)
        (self.root / "pytest.ini").unlink()
        (self.root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
        os.link(self.root / "pytest.ini", self.root / "hardlink.ini")
        with self.assertRaisesRegex(ValueError, "discovery_config_not_unique"):
            module.discover_test_frameworks(self.root)
        (self.root / "hardlink.ini").unlink()
        (self.root / "pytest.ini").write_text("a" * 20000, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "discovery_config_not_unique"):
            module.discover_test_frameworks(self.root)
        (self.root / "pytest.ini").unlink()
        (self.root / "tests").symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "discovery_tests_symlink_refused"):
            module.discover_test_frameworks(self.root)

    def test_discovery_root_symlink_and_nonexisting_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        for candidate in (alias, self.root / "does-not-exist"):
            with self.assertRaisesRegex(ValueError, "discovery_root_invalid_or_symlink"):
                module.discover_test_frameworks(candidate)


class InjectedFailureAndForkserverTests(unittest.TestCase):
    def test_forkserver_unavailable_or_failed_child_keeps_honest_complete_shape(self):
        with tempfile.TemporaryDirectory() as folder:
            missing = module.probe_forkserver(Path(folder) / "missing-python")
        failed = mock.Mock(returncode=1, stdout=b"", stderr=b"fixed failure")
        with mock.patch.object(module.subprocess, "run", return_value=failed):
            child_failure = module.probe_forkserver()
        for report in (missing, child_failure):
            self.assertEqual(report["status"], "NOT_RUN")
            self.assertFalse(report["distinct_child_process"])
            self.assertFalse(report["arbitrary_process_start_methods_verified"])
            self.assertFalse(report["user_source_executed"])

    def test_actual_sqlite_transaction_rolls_back_on_injected_failure(self):
        report = module.probe_injected_failure("sqlite_rollback")
        self.assertEqual(report["status"], "INJECTED_FAILURE_RECOVERED")
        self.assertEqual(report["observations"]["table_rows_after_failure"], 0)
        self.assertTrue(report["observations"]["sqlite_transaction_rolled_back"])
        self.assertFalse(report["user_files_modified"])

    def test_network_failure_stub_is_not_real_network_contact(self):
        report = module.probe_injected_failure("network_stub")
        self.assertEqual(report["status"], "INJECTED_FAILURE_RECOVERED")
        self.assertEqual(report["observations"]["stub_calls"], 1)
        self.assertTrue(report["observations"]["injected_connection_failure_caught"])
        self.assertFalse(report["observations"]["actual_network_used"])
        self.assertFalse(report["network_used"])

    def test_actual_tempfile_update_rollback_and_broken_rollback_detected(self):
        recovered = module.probe_injected_failure("update_rollback")
        broken = module.probe_injected_failure("update_broken_rollback")
        self.assertEqual(recovered["status"], "INJECTED_FAILURE_RECOVERED")
        self.assertTrue(recovered["observations"]["restored_previous_bytes"])
        self.assertEqual(broken["status"], "INJECTED_FAILURE_NOT_RECOVERED")
        self.assertFalse(broken["observations"]["restored_previous_bytes"])
        self.assertFalse(broken["user_files_modified"])

    def test_failure_injection_unknown_cases_rejected_before_touching_files(self):
        for candidate in ("", "database-real", None, "/tmp/target", "update_rollback;rm"):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                module.probe_injected_failure(candidate)

    def test_real_forkserver_probe_reports_os_blocker_honestly(self):
        report = module.probe_forkserver(sys.executable)
        self.assertIn(report["status"],
                      ("TRUSTED_FORKSERVER_OBSERVED", "NOT_SUPPORTED", "NOT_RUN"))
        if report["status"] == "TRUSTED_FORKSERVER_OBSERVED":
            self.assertTrue(report["distinct_child_process"])
        else:
            self.assertFalse(report["distinct_child_process"])
        self.assertFalse(report["user_source_executed"])
        self.assertFalse(report["arbitrary_process_start_methods_verified"])


if __name__ == "__main__":
    unittest.main()
