"""Bounded complete reviewed C API + real broad AST stdlib evidence."""

from importlib.util import module_from_spec, spec_from_file_location
import hashlib
import inspect
import json
from pathlib import Path
import subprocess
import sys
import sysconfig
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "stdlib_native_complete_v23.py"
spec = spec_from_file_location("stdlib_native_complete_v23", SCRIPT)
module = module_from_spec(spec)
spec.loader.exec_module(module)


class ReviewedNativeApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proof = module.native_runtime_inventory()

    def test_actual_native_symbols_and_module_provenance_broad(self):
        self.assertGreaterEqual(self.proof["reviewed_module_count"], 30)
        self.assertGreaterEqual(self.proof["available_native_modules"], 29)
        self.assertGreaterEqual(self.proof["collected_native_symbols"], 1200)
        self.assertGreaterEqual(self.proof["native_symbols_with_signature"], 500)
        self.assertFalse(self.proof["downloaded_or_project_code_executed"])

    def test_independent_runtime_getattr_static_oracle_complete(self):
        self.assertEqual(self.proof["status"], "REVIEWED_NATIVE_API_ORACLE_COMPLETE")
        self.assertEqual(self.proof["uncovered_independent_native_symbols"], [])
        self.assertLessEqual(self.proof["independent_oracle_native_symbols"],
                             self.proof["collected_native_symbols"])

    def test_real_native_math_signature_comes_from_inert_c_metadata(self):
        import math
        expected = getattr(math.sqrt, "__text_signature__")
        row = next(symbol for symbol in self.proof["native_symbols"]
                   if symbol["symbol"] == "math.sqrt")
        self.assertEqual(row["signature"], expected)
        self.assertIn("x", row["signature"])
        self.assertEqual(row["doc_sha256"], hashlib.sha256(
            inspect.getdoc(math.sqrt).encode()).hexdigest())

    def test_inherited_builtin_public_native_members_included(self):
        names = {row["symbol"] for row in self.proof["native_symbols"]}
        self.assertIn("builtins.ValueError.with_traceback", names)
        self.assertIn("builtins.int.bit_length", names)

    def test_existing_stdlib_module_bytes_are_actually_sha256_hashed(self):
        import bz2
        origin = next(row["module_origin"] for row in self.proof["modules"]
                      if row["module"] == "bz2")
        self.assertEqual(origin["kind"], "EXISTING_REAL_MODULE_BYTES")
        self.assertEqual(origin["sha256"], hashlib.sha256(
            Path(bz2.__file__).read_bytes()).hexdigest())

    def test_selected_allowlist_excludes_potential_import_side_effects(self):
        self.assertTrue(module.FORBIDDEN_IMPORTS.isdisjoint(module.REVIEWED_MODULES))
        self.assertFalse(self.proof["dynamic_module_imported_outside_reviewed_allowlist"])
        self.assertFalse(self.proof["all_CPythons_C_API_functions_covered"])

    def test_unknown_or_side_effectful_module_rejected_before_import(self):
        for candidate in ("antigravity", "pip", "os;sh", "usercustomize"):
            with self.assertRaisesRegex(ValueError, "module_not_approved"):
                module.native_runtime_inventory([candidate])

    def test_native_and_runtime_version_hash_are_stable(self):
        result = module.native_runtime_inventory()
        self.assertEqual(self.proof["native_inventory_sha256"],
                         result["native_inventory_sha256"])
        self.assertEqual(self.proof["python_micro"], "{}.{}.{}".format(
            *sys.version_info[:3]))
        self.assertEqual(self.proof["native_inventory_sha256"], module._digest(
            module._json_bytes(self.proof["native_symbols"])))

    def test_missing_native_signatures_explicit_not_fabricated(self):
        self.assertGreater(self.proof["native_symbols_missing_signature"], 0)
        self.assertEqual(self.proof["native_symbols_missing_signature"] +
                         self.proof["native_symbols_with_signature"],
                         self.proof["collected_native_symbols"])


class RealBroadStaticAndNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = module.combined_inventory()

    def test_broad_real_local_stdlib_ast_plus_native_scope_gated(self):
        self.assertEqual(self.report["status"], "BROAD_STDLIB_AST_PLUS_NATIVE_LOCAL_PASS")
        self.assertTrue(self.report["qualified_f068_bounded_local_scope"])
        self.assertGreaterEqual(self.report["source_files_scanned"], 500)
        self.assertGreaterEqual(self.report["static_api_declaration_candidates"], 10000)
        self.assertGreaterEqual(self.report["native_runtime_symbols"], 1200)

    def test_real_stdlib_source_bytes_sha_and_refused_files_reported(self):
        self.assertGreater(self.report["source_bytes_hashed"], 1_000_000)
        self.assertEqual(len(self.report["static_catalog_sha256"]), 64)
        self.assertEqual(len(self.report["native_catalog_sha256"]), 64)
        self.assertGreaterEqual(self.report["source_files_refused"], 0)

    def test_no_unfounded_full_stdlib_or_clevel_coverage_claims(self):
        self.assertFalse(self.report["all_stdlib_public_modules_complete"])
        self.assertFalse(self.report["all_C_level_exported_symbols_complete"])
        self.assertFalse(self.report["external_publisher_provenance_authenticated"])
        self.assertEqual(self.report["uncovered_independent_native_symbols"], [])


class StdlibNativeCliTests(unittest.TestCase):
    def command(self, *arguments):
        return subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)] +
                              list(arguments), capture_output=True, text=True,
                              timeout=15, check=False)

    def test_safe_default_json_capabilities_without_runtime_imports(self):
        run = self.command()
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["status"], "BROAD_STDLIB_API_CAPABILITIES_ONLY")
        self.assertFalse(report["full_c_api_claimed"])
        self.assertFalse(report["untrusted_code_executed"])

    def test_cli_native_json_oracle_and_actual_symbols_summary(self):
        run = self.command("--mode", "native")
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["uncovered_independent_native_symbols"], [])
        self.assertGreaterEqual(report["collected_native_symbols"], 1200)
        self.assertNotIn("native_symbols", report)

    def test_cli_combined_json_is_bounded_and_real(self):
        run = self.command("--mode", "combined")
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertTrue(report["qualified_f068_bounded_local_scope"])
        self.assertGreaterEqual(report["static_api_declaration_candidates"], 10000)
        self.assertEqual(report["python_minor"], "{}.{}".format(*sys.version_info[:2]))

    def test_explicit_extract_requires_pinned_installed_stdlib_root(self):
        root = Path(sysconfig.get_path("stdlib")).resolve()
        hashed = hashlib.sha256(str(root).encode("utf-8")).hexdigest()
        run = self.command("--mode", "extract", "--source-root", str(root),
                           "--source-root-sha256", hashed)
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertTrue(report["qualified_f068_bounded_local_scope"])
        self.assertGreaterEqual(report["source_files_scanned"], 500)

    def test_explicit_extract_refuses_mismatched_source_pin(self):
        root = Path(sysconfig.get_path("stdlib")).resolve()
        run = self.command("--mode", "extract", "--source-root", str(root),
                           "--source-root-sha256", "f" * 64)
        self.assertNotEqual(run.returncode, 0)
        self.assertFalse(run.stdout.strip())


if __name__ == "__main__":
    unittest.main()
