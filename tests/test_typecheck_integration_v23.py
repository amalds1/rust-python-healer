"""Real external mypy+Pyright process integration against trusted fixtures."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "python" / "typecheck_integration_v23.py"
TOOLS = ROOT / ".v23-typecheck-tools"
TOOLS_39 = ROOT / ".v23-typecheck-mypy39"
CHECKER_PYTHON = os.environ.get("RPH_CHECKER_PYTHON") or shutil.which("python3.12")
if CHECKER_PYTHON is None and os.name == "nt":
    private_runtime = ROOT.parent / "python-runtimes/cpython-3.12-windows-x86_64-none/python.exe"
    if private_runtime.is_file():
        CHECKER_PYTHON = str(private_runtime.resolve())
spec = importlib.util.spec_from_file_location("typecheck_integration_v23", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ExternalTypecheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if CHECKER_PYTHON is None or not TOOLS.is_dir():
            raise unittest.SkipTest("not_installed_real_mypy_and_pyright_REQUIRED_FOR_F093")
        try:
            cls.default_installed = module._pypa_tool_versions(TOOLS)
            cls.legacy_installed = module._pypa_tool_versions(TOOLS_39)
        except ValueError:
            raise unittest.SkipTest("not_installed_real_mypy_and_pyright_REQUIRED_FOR_F093")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rph-v23-typecheck-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.version = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
        self.installed = (self.legacy_installed if self.version == "3.9"
                          else self.default_installed)
        self._configs()

    def _configs(self, pyright_file=False):
        (self.root / "pyproject.toml").write_text(
            "[tool.mypy]\npython_version = '" + self.version + "'\nstrict = true\n"
            "show_error_codes = true\n"
            "[tool.pyright]\npythonVersion = '" + self.version + "'\n"
            "typeCheckingMode = 'strict'\ninclude = ['.']\n")
        if pyright_file:
            (self.root / "pyrightconfig.json").write_text(json.dumps({
                "pythonVersion": self.version, "typeCheckingMode": "strict", "include": ["."]}))

    def _run(self, source="value: int = 3\n"):
        (self.root / "fixture.py").write_text(source)
        return module.check_trusted_project(self.root, sys.executable,
                                            CHECKER_PYTHON, TOOLS,
                                            expected_versions=self.installed,
                                            python39_tool_root=TOOLS_39)

    def test_real_typecheckers_are_locally_installed_with_explicit_versions(self):
        self.assertEqual(self.installed, {"mypy": "1.18.2" if self.version == "3.9" else "2.4.1",
                                          "pyright": "1.1.414"})

    def test_real_mypy_and_pyright_clean_fixture_both_pass(self):
        report = self._run("value: int = 3\ntext: str = 'hello'\n")
        self.assertEqual(report["status"], "TWO_REAL_CHECKERS_AGREE_CLEAN")
        self.assertTrue(report["mypy_and_pyright_agree_on_error_presence"])
        self.assertEqual(report["mypy"]["exit_code"], 0)
        self.assertEqual(report["pyright"]["exit_code"], 0)
        self.assertEqual(report["actual_target_python_minor"], self.version)
        self.assertFalse(report["user_project_runtime_executed"])
        self.assertFalse(report["os_sandbox_proven"])

    def test_real_mypy_and_pyright_reject_incompatible_assignment(self):
        report = self._run("value: int = 'bad assignment'\n")
        self.assertEqual(report["status"], "TWO_REAL_CHECKERS_AGREE_TYPE_ERRORS")
        self.assertGreaterEqual(report["mypy"]["error_count"], 1)
        self.assertGreaterEqual(report["pyright"]["error_count"], 1)

    def test_real_pep634_match_syntax_minimum_python_version(self):
        # The same source is parsed by *both actual checkers*, separately
        # under Python 3.9 and 3.10+ target semantics, not executed by us.
        report = self._run("def classify(value: int) -> int:\n"
                           "    match value:\n"
                           "        case 3:\n"
                           "            return 3\n"
                           "        case _:\n"
                           "            return 0\n")
        if self.version == "3.9":
            self.assertEqual(report["status"], "TWO_REAL_CHECKERS_AGREE_TYPE_ERRORS")
            self.assertGreater(report["mypy"]["error_count"], 0)
            self.assertGreater(report["pyright"]["error_count"], 0)
        else:
            self.assertEqual(report["status"], "TWO_REAL_CHECKERS_AGREE_CLEAN")

    def test_real_external_checkers_timing_and_resources_are_recorded(self):
        report = self._run()
        for tool in ("mypy", "pyright"):
            self.assertGreater(report[tool]["duration_ms"], 0)
            self.assertGreater(report[tool]["peak_child_rss_kib"], 0)
            self.assertTrue(report[tool]["external_checker_process_executed"])
            self.assertEqual(len(report[tool]["output_bytes_sha256"]), 64)

    def test_real_pyrightconfig_json_precedence_verified(self):
        self._configs(pyright_file=True)
        report = self._run()
        self.assertEqual(report["status"], "TWO_REAL_CHECKERS_AGREE_CLEAN")
        self.assertIsNotNone(report["project_config"]["pyrightconfig_sha256"])

    def test_real_dual_project_config_conflict_reports_pyright_precedence(self):
        self._configs(pyright_file=True)
        data = (self.root / "pyproject.toml").read_text().replace(
            "typeCheckingMode = 'strict'", "typeCheckingMode = 'basic'")
        (self.root / "pyproject.toml").write_text(data)
        report = self._run()
        self.assertEqual(report["project_config"]["precedence"], "pyrightconfig.json")

    def test_pyproject_mypy_plugin_execution_is_refused_before_checker(self):
        data = (self.root / "pyproject.toml").read_text().replace(
            "strict = true", "strict = true\nplugins = ['evil.plugin']")
        (self.root / "pyproject.toml").write_text(data)
        (self.root / "fixture.py").write_text("value: int = 3\n")
        with self.assertRaisesRegex(ValueError, "unsafe_or_mismatched_mypy_config"):
            module.check_trusted_project(self.root, sys.executable, CHECKER_PYTHON, TOOLS,
                                         python39_tool_root=TOOLS_39)

    def test_pyright_disabled_typechecking_is_refused(self):
        (self.root / "pyrightconfig.json").write_text(json.dumps({
            "pythonVersion": self.version, "typeCheckingMode": "off", "include": ["."]}))
        (self.root / "fixture.py").write_text("value: int = 3\n")
        with self.assertRaisesRegex(ValueError, "unsafe_or_mismatched_pyright_config"):
            module.check_trusted_project(self.root, sys.executable, CHECKER_PYTHON, TOOLS,
                                         python39_tool_root=TOOLS_39)

    def test_mismatched_project_python_version_is_refused(self):
        data = (self.root / "pyproject.toml").read_text().replace(
            "python_version = '" + self.version + "'", "python_version = '3.16'")
        (self.root / "pyproject.toml").write_text(data)
        (self.root / "fixture.py").write_text("value: int = 3\n")
        with self.assertRaisesRegex(ValueError, "unsafe_or_mismatched_mypy_config"):
            module.check_trusted_project(self.root, sys.executable, CHECKER_PYTHON, TOOLS,
                                         python39_tool_root=TOOLS_39)

    def test_private_root_is_required(self):
        (self.root / "fixture.py").write_text("value: int = 3\n")
        self.root.chmod(0o755)
        if os.name == "nt":
            sys.path.insert(0,str(ROOT/"tests"))
            import windows_privacy_fixtures
            windows_privacy_fixtures.set_public_read_acl(self.root)
        with self.assertRaisesRegex(ValueError, "private_root_required"):
            module.check_trusted_project(self.root, sys.executable, CHECKER_PYTHON, TOOLS,
                                         python39_tool_root=TOOLS_39)

    def test_symlinked_or_hardlinked_source_is_refused(self):
        original = self.root / "safe.py"
        original.write_text("value: int = 3\n")
        (self.root / "fixture.py").symlink_to(original)
        with self.assertRaisesRegex(ValueError, "project_symlink_forbidden"):
            module.check_trusted_project(self.root, sys.executable, CHECKER_PYTHON, TOOLS,
                                         python39_tool_root=TOOLS_39)
        (self.root / "fixture.py").unlink()
        (self.root / "fixture.py").write_text("value: int = 3\n")
        os.link(self.root / "fixture.py", self.root / "copy.py")
        with self.assertRaisesRegex(ValueError, "unsafe_fixture_file"):
            module.check_trusted_project(self.root, sys.executable, CHECKER_PYTHON, TOOLS)

    def test_unknown_python_interpreter_version_is_not_claimed(self):
        (self.root / "fixture.py").write_text("value: int = 3\n")
        with mock.patch.object(module, "_actual_interpreter_minor", return_value="3.16"):
            with self.assertRaisesRegex(ValueError, "target_python_minor_not_qualified"):
                module.check_trusted_project(self.root, sys.executable, CHECKER_PYTHON, TOOLS,
                                             python39_tool_root=TOOLS_39)

    def test_checker_version_pin_mismatch_fails_closed(self):
        (self.root / "fixture.py").write_text("value: int = 3\n")
        with self.assertRaisesRegex(ValueError, "tool_version_pin_mismatch"):
            module.check_trusted_project(self.root, sys.executable, CHECKER_PYTHON,
                                         TOOLS, expected_versions={"mypy": "0.1", "pyright": "1.1.414"},
                                         python39_tool_root=TOOLS_39)

    def test_mypy_and_pyright_cli_capabilities_no_checker_execution(self):
        proc = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE)],
                              capture_output=True, check=False, timeout=8)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["status"],
                         "TRUSTED_MYPY_PYRIGHT_ADAPTER_AVAILABLE")

    def test_mypy_and_pyright_cli_real_checker(self):
        (self.root / "fixture.py").write_text("value: int = 3\n")
        proc = subprocess.run([sys.executable, "-I", "-B", str(SOURCE),
                               "--mode", "check", "--project", str(self.root),
                               "--target-python", sys.executable,
                               "--checker-python", CHECKER_PYTHON,
                               "--tool-root", str(TOOLS),
                               "--python39-tool-root", str(TOOLS_39)],
                              capture_output=True, check=False, timeout=25)
        self.assertEqual(proc.returncode, 0, proc.stderr[:100])
        self.assertEqual(json.loads(proc.stdout)["status"], "TWO_REAL_CHECKERS_AGREE_CLEAN")


if __name__ == "__main__":
    unittest.main()
