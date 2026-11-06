"""Safe static extraction against real interpreter stdlib + hostile fixtures."""

from importlib.util import module_from_spec, spec_from_file_location
from contextlib import closing
import inspect
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("stdlib_api_extract", ROOT / "python" / "stdlib_api_extract.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


class StdlibAPIExtractTests(unittest.TestCase):
    def fixture(self, root):
        path = Path(root)
        package = path / "examplepkg"
        package.mkdir()
        (package / "__init__.py").write_text(
            "def public(first, /, second=1, *, critical, **extras):\n"
            "    return first\n"
            "class Service:\n"
            "    async def execute(self, *, flag=True):\n"
            "        return flag\n"
            "def outer():\n"
            "    def only_local():\n"
            "        return 1\n"
            "    return only_local()\n")
        return path, package

    def test_function_method_and_nested_signature_positions(self):
        with tempfile.TemporaryDirectory() as root:
            path, _ = self.fixture(root)
            result = module.extract(path)
            self.assertEqual(result["status"], "INDEXED_STATIC_PY_UNVERIFIED")
            rows = {s["qualified_name"]: s for s in result["api_symbols"]}
            self.assertEqual(rows["public"]["signature"]["positional_only"], ["first"])
            self.assertEqual(rows["public"]["signature"]["positional_or_keyword"], ["second"])
            self.assertEqual(rows["public"]["signature"]["required_keyword_only"], ["critical"])
            self.assertEqual(rows["public"]["signature"]["varkw"], "extras")
            self.assertEqual(rows["Service"]["kind"], "CLASS")
            self.assertEqual(rows["Service.execute"]["kind"], "ASYNC_FUNCTION")
            self.assertEqual(rows["Service.execute"]["line"], 4)
            self.assertTrue(rows["outer.only_local"]["nested_function"])
            self.assertFalse(rows["public"]["signature"]["runtime_signature_verified"])

    def test_source_side_effect_and_secret_defaults_are_never_executed_or_exposed(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            marker = path / "executed-marker.txt"
            (path / "unsafe.py").write_text(
                "def print_secret(key='NEVER_EXPORT_PRIVATE_TOKEN'):\n"
                "    pass\n"
                "open({!r},'w').write('bad')\n".format(str(marker)))
            report = module.extract(path)
            self.assertEqual(report["status"], "INDEXED_STATIC_PY_UNVERIFIED")
            self.assertFalse(report["source_executed"])
            self.assertFalse(report["modules_imported"])
            self.assertFalse(marker.exists())
            self.assertNotIn("NEVER_EXPORT_PRIVATE_TOKEN", json.dumps(report))

    def test_module_names_and_import_declarations_are_not_conflated(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            (path / "direct.py").write_text("from json import loads\n")
            package = path / "mypackage"
            package.mkdir()
            (package / "__init__.py").write_text("def included():\n    pass\n")
            report = module.extract(path)
            self.assertEqual({item["module"] for item in report["modules"]},
                             {"direct", "mypackage"})
            self.assertEqual([x["qualified_name"] for x in report["api_symbols"]], ["included"])
            self.assertFalse(report["dynamic_api_exports_verified"])

    def test_conditional_definitions_are_candidates_not_runtime_proof(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            (path / "conditional.py").write_text(
                "if False:\n    def inaccessible():\n        pass\n"
                "try:\n    def alternative():\n        pass\n"
                "except Exception:\n    def fallback():\n        pass\n")
            report = module.extract(path)
            found = {x["qualified_name"] for x in report["api_symbols"]}
            self.assertEqual(found, {"inaccessible", "alternative", "fallback"})
            self.assertFalse(report["runtime_signature_verified"])

    def test_symlink_and_hardlink_refused_without_reading_external_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            source = path / "source.py"
            source.write_text("def original():\n    pass\n")
            link = path / "linked.py"
            link.symlink_to(source)
            skipped = module.extract(path)
            self.assertEqual(skipped["source_files_refused"], 1)
            hard = path / "hardlinked.py"
            os.link(source, hard)
            skipped = module.extract(path)
            self.assertEqual(skipped["source_files_refused"], 3)
            self.assertEqual(skipped["api_candidates_indexed"], 0)

    def test_symlink_root_and_nonsource_files_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            (path / "notes.txt").write_text("def not_python(): pass")
            link = path / "symlink-root"
            link.symlink_to(path, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "invalid_stdlib_root"):
                module.extract(link)
            report = module.extract(path)
            self.assertEqual(report["status"], "NO_FILES_INDEXED")

    def test_symlinked_directory_outside_root_is_not_followed(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            project, external = Path(root), Path(outside)
            (external / "private_source.py").write_text("def outsider(): pass\n")
            (project / "escape").symlink_to(external, target_is_directory=True)
            (project / "safe.py").write_text("def expected(): pass\n")
            report = module.extract(project)
            self.assertEqual(report["module_files_indexed"], 1)
            self.assertEqual(report["api_symbols"][0]["qualified_name"], "expected")
            self.assertNotIn("outsider", json.dumps(report))

    def test_file_budget_refuses_false_full_index(self):
        with tempfile.TemporaryDirectory() as root:
            project = Path(root)
            (project / "first.py").write_text("def one(): pass\n")
            (project / "second.py").write_text("def two(): pass\n")
            original = module.MAX_FILES
            try:
                module.MAX_FILES = 1
                with self.assertRaisesRegex(ValueError, "too_many_stdlib_sources"):
                    module.extract(project)
            finally:
                module.MAX_FILES = original

    def test_oversized_or_invalid_encoding_is_never_counted_as_indexed(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            (path / "invalid.py").write_bytes(b"def broken():\n\xff\n")
            report = module.extract(path)
            self.assertEqual(report["status"], "INDEXED_PARTIAL_UNVERIFIED")
            self.assertEqual(report["module_files_indexed"], 0)
            self.assertEqual(report["source_files_refused"], 1)
            (path / "oversized.py").write_bytes(b"a" * (module.MAX_FILE_BYTES + 1))
            report = module.extract(path)
            self.assertEqual(report["source_files_refused"], 2)

    def test_quotas_fail_closed_instead_of_claiming_full_stdlib(self):
        with tempfile.TemporaryDirectory() as root:
            path, _ = self.fixture(root)
            prior = module.MAX_AST_NODES
            try:
                module.MAX_AST_NODES = 1
                result = module.extract(path)
            finally:
                module.MAX_AST_NODES = prior
            self.assertEqual(result["status"], "INDEXED_PARTIAL_UNVERIFIED")
            self.assertEqual(result["module_files_indexed"], 0)

    def test_site_packages_are_not_included_as_stdlib(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            (path / "real.py").write_text("def expected(): pass\n")
            installed = path / "site-packages"
            installed.mkdir()
            (installed / "thirdparty.py").write_text("def untrusted(): pass\n")
            report = module.extract(path)
            self.assertEqual(report["module_files_indexed"], 1)
            self.assertEqual(report["api_symbols"][0]["qualified_name"], "expected")

    def test_sqlite_index_is_consistent_and_existing_target_never_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            path, _ = self.fixture(root)
            result = module.extract(path)
            db = path / "static-api.sqlite"
            output = module.write_index(db, result)
            self.assertEqual(output["status"], "INDEX_WRITTEN_UNVERIFIED")
            with closing(sqlite3.connect(str(db))) as conn:
                self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM modules").fetchone()[0], 1)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM api_symbols").fetchone()[0], 5)
            with self.assertRaisesRegex(ValueError, "index_target_must_be_a_new_regular_filename"):
                module.write_index(db, result)

    def test_cli_embedded_helper_index_writes_without_executing_source(self):
        with tempfile.TemporaryDirectory() as root:
            path, _ = self.fixture(root)
            db = path / "catalog.sqlite"
            run = subprocess.run([sys.executable, "-I", "-S", "-B", "-c",
                                  (ROOT / "python" / "stdlib_api_extract.py").read_text(),
                                  "--stdlib-root", str(path), "--db", str(db)],
                                 capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            report = json.loads(run.stdout)
            self.assertEqual(report["sqlite"]["api_candidates"], 5)
            self.assertEqual(report["module_files_indexed"], 1)
            self.assertNotIn(str(path), run.stdout)

    def test_full_current_stdlib_contains_independently_known_ast_and_json_apis(self):
        # Each interpreter is authoritative for its own stdlib AST grammar.
        import ast as trusted_ast
        import json as trusted_json
        report = module.extract()
        self.assertGreater(report["module_files_indexed"], 100)
        self.assertGreater(report["api_candidates_indexed"], 1000)
        keys = {(x["module"], x["qualified_name"]): x for x in report["api_symbols"]}
        self.assertIn(("ast", "parse"), keys)
        self.assertIn(("json", "loads"), keys)
        self.assertEqual(keys[("ast", "parse")]["signature"]["positional_or_keyword"][0],
                         list(inspect.signature(trusted_ast.parse).parameters)[0])
        self.assertEqual(keys[("json", "loads")]["signature"]["positional_or_keyword"][0],
                         list(inspect.signature(trusted_json.loads).parameters)[0])
        self.assertEqual(report["python_minor"],
                         "{}.{}".format(sys.version_info.major, sys.version_info.minor))
        self.assertFalse(report["native_extension_apis_verified"])


if __name__ == "__main__":
    unittest.main()
