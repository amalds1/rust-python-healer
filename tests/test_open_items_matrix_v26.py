"""F001-F260 audit cannot convert scoped tests into a false full PASS."""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools" / "open_items_matrix_v26.py"
SPEC = importlib.util.spec_from_file_location("open_items_matrix_v26", SOURCE)
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


class OpenItemMatrixTests(unittest.TestCase):
    def test_live_260_item_registry_not_assumed_complete(self):
        items = MATRIX.checklist_items(ROOT / "docs" / "FUNCTION_CHECKLIST.md")
        self.assertEqual(len(items), 260)
        self.assertEqual(sum(x["status"] != "IMPLEMENTED_TESTED" for x in items), 25)

    def test_all_missing_runtimes_are_not_run(self):
        report = MATRIX.collect(MATRIX.checklist_items(ROOT / "docs" / "FUNCTION_CHECKLIST.md"), {})
        self.assertEqual(report["status"], "INCOMPLETE_NOT_ALL_PASS")
        self.assertEqual(report["planned_feature_minor_cells"], 175)
        self.assertEqual(len(report["results"]), 7)
        self.assertEqual(sum(x["evidence"] == "NOT_RUN" for minor in report["results"]
                             for x in minor["features"]), 175)
        self.assertIs(report["all_260_functions_qualified"], False)

    def test_duplicate_or_removed_item_never_succeeds(self):
        items = MATRIX.checklist_items(ROOT / "docs" / "FUNCTION_CHECKLIST.md")
        items[0]["status"] = "PARTIAL"
        with self.assertRaisesRegex(ValueError, "open_checklist_changed_review_required"):
            MATRIX.collect(items, {})

    def test_untrusted_module_name_rejected(self):
        with self.assertRaisesRegex(ValueError, "untrusted_regression_filename"):
            MATRIX.scoped_test(sys.executable, "../../secrets.py")

    def test_missing_curated_regression_gives_not_run(self):
        outcome = MATRIX.scoped_test(sys.executable, "test_rph_intentionally_absent_098765.py")
        self.assertEqual(outcome["status"], "NOT_RUN")

    def test_real_python_minor_not_conflated_with_other_minors(self):
        actual = "{}.{}".format(*sys.version_info[:2])
        result = MATRIX.python_identity(sys.executable, actual)
        self.assertEqual(result["minor"], actual)
        self.assertEqual(len(result["executable_sha256"]), 64)
        with self.assertRaisesRegex(ValueError, "python_minor_identity_mismatch"):
            MATRIX.python_identity(sys.executable, "3.99")

    def test_real_scoped_test_not_promoted_to_full_feature(self):
        result = MATRIX.scoped_test(sys.executable, "test_oci_layout_v25.py")
        # The real OCI suite needs symlink privileges. A failed prerequisite
        # must remain a scoped failure, not make the matrix claim feature PASS.
        if result["status"] == "SCOPED_FAIL":
            self.assertNotEqual(result["exit_code"], 0)
        else:
            self.assertEqual(result["status"], "SCOPED_PASS_NOT_FULL_FEATURE")
            self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["executed_tests"], 12)
        self.assertEqual(result["skipped"], 0)
        self.assertFalse(result["raw_output_stored"])

    def test_actual_portable_scoped_success_is_still_not_full_feature(self):
        result = MATRIX.scoped_test(sys.executable, "test_graph_runtime_qualification.py")
        self.assertEqual(result["status"], "SCOPED_PASS_NOT_FULL_FEATURE")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["executed_tests"], 6)
        self.assertEqual(result["skipped"], 0)

    def test_missing_interpreter_is_not_qualified(self):
        with tempfile.TemporaryDirectory() as dirname:
            binary = Path(dirname) / "fake_python"
            binary.write_text("not an interpreter\n")
            report = MATRIX.collect(MATRIX.checklist_items(ROOT / "docs" / "FUNCTION_CHECKLIST.md"),
                                    {"3.9": binary})
            self.assertEqual(report["results"][0]["status"], "NOT_RUN")
            self.assertEqual(report["results"][0]["reason"], "INVALID_INTERPRETER")


if __name__ == "__main__":
    unittest.main()
