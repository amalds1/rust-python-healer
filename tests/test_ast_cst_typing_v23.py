"""CPython 3.9–3.15 real LibCST wheel and external mypy/Pyright oracles."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "python" / "ast_cst_typing_v23.py"
LIBCST_TOOLS = ROOT / ".v23-libcst-{}.{}".format(sys.version_info.major,
                                                    sys.version_info.minor)
CHECKER_TOOLS = ROOT / ".v23-typecheck-tools"
CHECKER_TOOLS39 = ROOT / ".v23-typecheck-mypy39"
CHECKER_PYTHON = os.environ.get("RPH_CHECKER_PYTHON") or shutil.which("python3.12")
if CHECKER_PYTHON is None and os.name == "nt":
    private_runtime = ROOT.parent / "python-runtimes/cpython-3.12-windows-x86_64-none/python.exe"
    if private_runtime.is_file():
        CHECKER_PYTHON = str(private_runtime.resolve())
sys.path.insert(0, str(ROOT / "python"))
spec = importlib.util.spec_from_file_location("ast_cst_typing_v23", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RealAstCstTypecheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (CHECKER_PYTHON is None or not LIBCST_TOOLS.is_dir() or
                not CHECKER_TOOLS.is_dir() or not CHECKER_TOOLS39.is_dir()):
            # A missing real oracle must never make the release matrix green
            # through an implicit unittest skip.
            raise RuntimeError("mandatory_real_libcst_and_mypy_pyright_wheels_missing")
        # Fail rather than skip if a malicious or wrong-version package exists.
        cls.libcst = module._libcst_preflight(LIBCST_TOOLS)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rph-v23-cst-typing-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.minor = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
        (self.root / "pyproject.toml").write_text(
            "[tool.mypy]\npython_version = '" + self.minor + "'\nstrict = true\n"
            "show_error_codes = true\n"
            "[tool.pyright]\npythonVersion = '" + self.minor + "'\n"
            "typeCheckingMode = 'strict'\ninclude = ['.']\n")
        self._write_good()

    def _write_good(self):
        (self.root / "library.py").write_text(
            "# library API\n"
            "def add(left: int, right: int) -> int:\n"
            "    return left + right\n")
        (self.root / "client.py").write_text(
            "# consumer\nfrom library import add\n"
            "result: int = add(2, 5)\n")

    def _analyze(self):
        return module.analyze_reviewed_multimodule(
            self.root, sys.executable, CHECKER_PYTHON, CHECKER_TOOLS,
            LIBCST_TOOLS, python39_checker_tool_root=CHECKER_TOOLS39)

    def test_actual_libcst_version_and_cpython_native_wheel_tag(self):
        libcst = module._libcst_preflight(LIBCST_TOOLS)
        self.assertTrue(Path(libcst.__file__).resolve().is_relative_to(LIBCST_TOOLS))
        self.assertEqual(module.PINNED_LIBCST, "1.9.0")
        wheel = next(LIBCST_TOOLS.glob("libcst-*.dist-info/WHEEL")).read_text()
        self.assertIn("cp3{}-".format(sys.version_info.minor), wheel)

    def test_two_real_oracles_clean_crossmodule_import(self):
        report = self._analyze()
        self.assertEqual(report["status"], "CST_AST_AND_TWO_CHECKERS_AGREE_CLEAN")
        self.assertEqual(report["module_count"], 2)
        self.assertTrue(report["real_cst_parser_executed"])
        self.assertTrue(report["real_mypy_executed"])
        self.assertTrue(report["real_pyright_executed"])
        self.assertFalse(report["user_code_imported_or_executed"])

    def test_real_crossmodule_wrong_argument_both_checkers_reject(self):
        (self.root / "client.py").write_text(
            "from library import add\nresult: int = add('bad', 5)\n")
        report = self._analyze()
        self.assertEqual(report["status"], "CST_AST_AND_TWO_CHECKERS_AGREE_ERRORS")
        self.assertGreater(report["external_typecheck"]["mypy"]["error_count"], 0)
        self.assertGreater(report["external_typecheck"]["pyright"]["error_count"], 0)

    def test_real_crossmodule_signature_mutation_propagates(self):
        (self.root / "library.py").write_text(
            "def add(left: str, right: int) -> int:\n    return right\n")
        report = self._analyze()
        self.assertEqual(report["status"], "CST_AST_AND_TWO_CHECKERS_AGREE_ERRORS")
        self.assertGreater(report["external_typecheck"]["mypy"]["error_count"], 0)
        self.assertGreater(report["external_typecheck"]["pyright"]["error_count"], 0)

    def test_real_alias_reexport_and_wrong_value_type(self):
        (self.root / "library.py").write_text("def get_name() -> str:\n    return 'correct'\n")
        (self.root / "client.py").write_text(
            "from library import get_name as alias\nvalue: int = alias()\n")
        report = self._analyze()
        self.assertEqual(report["status"], "CST_AST_AND_TWO_CHECKERS_AGREE_ERRORS")

    def test_real_class_method_crossmodule_type_check(self):
        (self.root / "library.py").write_text(
            "class Calculator:\n"
            "    def double(self, number: int) -> int:\n"
            "        return number * 2\n")
        (self.root / "client.py").write_text(
            "from library import Calculator\n"
            "result: int = Calculator().double('not an int')\n")
        report = self._analyze()
        self.assertEqual(report["status"], "CST_AST_AND_TWO_CHECKERS_AGREE_ERRORS")

    def test_real_libcst_roundtrip_preserves_crlf_unicode_comments_and_positions(self):
        source = ("# naïve café comment\r\n"
                  "π = 3  # trailing\r\n"
                  "value: int = π\r\n")
        raw = source.encode("utf-8")
        report = module._inspect_source("unicode.py", raw, self.libcst)
        self.assertTrue(report["byte_identical_roundtrip"])
        self.assertTrue(report["source_has_non_ascii"])
        self.assertGreaterEqual(report["matching_identifier_positions"], 2)
        self.assertEqual(report["source_sha256"], report["roundtrip_sha256"])

    def test_comments_and_code_positions_are_backed_by_real_cst(self):
        report = self._analyze()
        for source in report["source_models"].values():
            self.assertTrue(source["all_ast_names_in_real_libcst"])
            self.assertGreater(source["libcst_nodes_with_positions"], 3)
            self.assertGreater(source["cpython_ast_nodes"], 3)
            self.assertGreater(source["complete_cpython_ast_source_ranges"], 2)

    def test_invalid_python_is_not_falsely_qualified(self):
        with self.assertRaisesRegex(ValueError, "source_rejected_by_real_ast_or_cst"):
            module._inspect_source("invalid.py", b"if True print('oops')\n", self.libcst)

    def test_pep634_pattern_match_is_version_gated_by_actual_ast(self):
        source = (b"def classify(n: int) -> int:\n"
                  b"    match n:\n"
                  b"        case 3:\n"
                  b"            return 3\n"
                  b"        case _:\n"
                  b"            return 0\n")
        if self.minor == "3.9":
            with self.assertRaisesRegex(ValueError, "source_rejected_by_real_ast_or_cst"):
                module._inspect_source("pep634.py", source, self.libcst)
        else:
            self.assertTrue(module._inspect_source("pep634.py", source, self.libcst)
                            ["byte_identical_roundtrip"])

    def test_reviewed_project_cannot_import_or_execute_user_source(self):
        sentinel = self.root.parent / (self.root.name + "-not-executed")
        (self.root / "client.py").write_text(
            "from pathlib import Path\n"
            "from library import add\n"
            "Path(" + repr(str(sentinel)) + ").write_text('BAD')\n"
            "result: int = add(2, 5)\n")
        report = self._analyze()
        self.assertEqual(report["status"], "CST_AST_AND_TWO_CHECKERS_AGREE_CLEAN")
        self.assertFalse(sentinel.exists())

    def test_symlinked_source_file_is_refused_before_static_tools(self):
        (self.root / "client.py").unlink()
        (self.root / "client.py").symlink_to(self.root / "library.py")
        with self.assertRaisesRegex(ValueError, "project_symlink_forbidden"):
            self._analyze()

    def test_hardlinked_source_is_refused(self):
        os.link(self.root / "library.py", self.root / "extra.py")
        with self.assertRaisesRegex(ValueError, "unsafe_fixture_file"):
            self._analyze()

    def test_public_project_directory_is_refused(self):
        self.root.chmod(0o755)
        if os.name == "nt":
            sys.path.insert(0,str(ROOT/"tests"))
            import windows_privacy_fixtures
            windows_privacy_fixtures.set_public_read_acl(self.root)
        with self.assertRaisesRegex(ValueError, "private_root_required"):
            self._analyze()

    def test_project_requires_at_least_two_modules(self):
        (self.root / "client.py").unlink()
        with self.assertRaisesRegex(ValueError, "two_reviewed_source_modules_required"):
            self._analyze()

    def test_wrong_target_interpreter_is_refused(self):
        other = ("3.10" if self.minor == "3.9" else "3.9")
        incompatible_python = ROOT.parent / ".python-bin" / ("python" + other)
        if os.name == "nt":
            patch = "3.10.21" if other == "3.10" else "3.9.25"
            incompatible_python = ROOT.parent / "python-runtimes" / ("cpython-"+patch+"-windows-x86_64-none") / "python.exe"
        with self.assertRaisesRegex(ValueError, "libcst_and_ast_interpreter_must_match_target"):
            module.analyze_reviewed_multimodule(
                self.root, incompatible_python, CHECKER_PYTHON, CHECKER_TOOLS,
                LIBCST_TOOLS, python39_checker_tool_root=CHECKER_TOOLS39)

    def test_cli_capabilities_read_only_no_parser_or_checker_execution(self):
        proc = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE)],
                              capture_output=True, check=False, timeout=8)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["status"],
                         "AST_LIBCST_TYPE_ORACLE_ADAPTER_AVAILABLE")

    def test_cli_real_libcst_and_type_checkers(self):
        proc = subprocess.run([sys.executable, "-I", "-B", str(SOURCE),
                               "--mode", "inspect", "--project", str(self.root),
                               "--target-python", sys.executable,
                               "--checker-python", CHECKER_PYTHON,
                               "--typechecker-tools", str(CHECKER_TOOLS),
                               "--libcst-tools", str(LIBCST_TOOLS),
                               "--typechecker-tools39", str(CHECKER_TOOLS39)],
                              capture_output=True, check=False, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr[:120])
        self.assertEqual(json.loads(proc.stdout)["status"],
                         "CST_AST_AND_TWO_CHECKERS_AGREE_CLEAN")


if __name__ == "__main__":
    unittest.main()
