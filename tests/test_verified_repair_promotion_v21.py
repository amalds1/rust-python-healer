"""F029/F030/F093/F193 exact API migration and trusted-only promotion checks."""

from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("verified_repair_promotion_v21",
                              ROOT / "python" / "verified_repair_promotion_v21.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


class MigrationTests(unittest.TestCase):
    def test_selected_collections_abc_migration_is_beyond_colon(self):
        source = "from collections import Mapping\nx = 1\n"
        result = module.migrate_collections_abc(source)
        self.assertEqual(result["status"], "SINGLE_STDLIB_API_IMPORT_MIGRATED")
        self.assertEqual(result["candidate"], "from collections.abc import Mapping\nx = 1\n")
        self.assertTrue(result["independent_validation"]["valid"])
        self.assertFalse(result["source_executed"])
        self.assertFalse(result["behavior_equivalence_proven"])

    def test_alias_and_inline_comments_preserved_exactly(self):
        source = "from collections import MutableMapping as DictMap  # sensitive comment\n"
        result = module.migrate_collections_abc(source)
        self.assertEqual(result["candidate"], source.replace("collections", "collections.abc"))
        self.assertTrue(result["independent_validation"]["comments_and_format_preserved"])

    def test_indented_import_with_tabs_is_preserved(self):
        source = "def use():\n\tfrom collections import Iterable as I  #comment\n\treturn I\n"
        result = module.migrate_collections_abc(source)
        self.assertEqual(result["candidate"], source.replace("collections", "collections.abc"))

    def test_crlf_formatting_and_unrelated_lines_preserved(self):
        source = "# first\r\nfrom collections import Sequence as S   # keep\r\nx = 'é'\r\n"
        result = module.migrate_collections_abc(source)
        self.assertEqual(result["candidate"], source.replace("collections", "collections.abc"))

    def test_multiple_unrelated_imports_are_preserved(self):
        source = "from math import sqrt\nfrom collections import Mapping\nimport json\n"
        result = module.migrate_collections_abc(source)
        self.assertEqual(result["candidate"], source.replace("collections", "collections.abc"))

    def test_one_of_several_supported_selected_imports_is_ambiguous(self):
        source = "from collections import Mapping\nfrom collections import Iterable\n"
        result = module.migrate_collections_abc(source)
        self.assertEqual(result["status"], "NO_PATCH")
        self.assertEqual(result["reason"], "no_unique_supported_import")

    def test_mixed_collection_and_abc_import_is_refused(self):
        source = "from collections import Mapping, deque\n"
        self.assertEqual(module.migrate_collections_abc(source)["status"], "NO_PATCH")

    def test_future_and_already_migrated_imports_not_rewritten(self):
        for source in ("from collections.abc import Mapping\n", "from collections import deque\n"):
            with self.subTest(source=source):
                self.assertEqual(module.migrate_collections_abc(source)["status"], "NO_PATCH")

    def test_dynamic_import_and_multiline_import_refused(self):
        for source in ("Mapping = __import__('collections').Mapping\n",
                       "from collections import (\n    Mapping,\n)\n"):
            with self.subTest(source=source):
                self.assertEqual(module.migrate_collections_abc(source)["status"], "NO_PATCH")

    def test_independent_oracle_rejects_unrelated_ast_change(self):
        original = "from collections import Mapping\nanswer = 7\n"
        changed = "from collections.abc import Mapping\nanswer = 8\n"
        verdict = module.independently_validate_collections_migration(original, changed)
        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["reason"], "additional_ast_changes_detected")

    def test_independent_oracle_rejects_alias_and_comment_tamper(self):
        original = "from collections import Mapping as M  # private\n"
        alias_change = "from collections.abc import Mapping as N  # private\n"
        comment_change = "from collections.abc import Mapping as M  # public\n"
        self.assertFalse(module.independently_validate_collections_migration(original, alias_change)["valid"])
        self.assertFalse(module.independently_validate_collections_migration(original, comment_change)["valid"])

    def test_oracle_rejects_wrong_abi_package_or_number_of_migrations(self):
        original = "from collections import Mapping\n"
        wrong = "from totally.different import Mapping\n"
        self.assertFalse(module.independently_validate_collections_migration(original, wrong)["valid"])
        self.assertFalse(module.independently_validate_collections_migration(original, original)["valid"])

    def test_untrusted_user_source_is_never_imported_or_executed(self):
        source = "raise RuntimeError('never execute')\nfrom collections import Mapping\n"
        report = module.migrate_collections_abc(source)
        self.assertEqual(report["status"], "SINGLE_STDLIB_API_IMPORT_MIGRATED")
        self.assertFalse(report["source_executed"])

    def test_large_source_or_invalid_unicode_fails_closed(self):
        self.assertEqual(module.migrate_collections_abc("x" * (module.MAX_SOURCE_BYTES + 1))["status"],
                         "NO_PATCH")
        self.assertEqual(module.migrate_collections_abc("\ud800")["status"], "NO_PATCH")

    def test_invalid_syntax_fails_closed_and_does_not_leak(self):
        source = "from collections import Mapping\nSECRET_TOKEN= 'PRIVATE_786'\ndef broken(\n"
        result = module.migrate_collections_abc(source)
        self.assertEqual(result["status"], "NO_PATCH")
        self.assertNotIn("PRIVATE_786", json.dumps(result))

    def test_token_budget_invalidates_oracle(self):
        old = module.MAX_TOKENS
        try:
            module.MAX_TOKENS = 3
            source = "from collections import Mapping\n"
            result = module.independently_validate_collections_migration(
                source, "from collections.abc import Mapping\n")
        finally:
            module.MAX_TOKENS = old
        self.assertFalse(result["valid"])

    def test_no_output_claim_of_semantic_equivalence_for_migration(self):
        result = module.migrate_collections_abc("from collections import Mapping\n")
        self.assertFalse(result["independent_validation"]["semantics_equivalent_proven"])


class TrustedPromotionTests(unittest.TestCase):
    def test_actual_original_and_repaired_fixture_are_distinct(self):
        result = module.assess_fixed_repair_promotion("equivalent")
        self.assertTrue(result["sources_differ"])
        self.assertNotEqual(result["original_sha256"], result["repaired_sha256"])

    def test_trusted_behavior_equivalence_gate_accepts_known_equivalent_refactor(self):
        result = module.assess_fixed_repair_promotion("equivalent")
        self.assertEqual(result["status"], "PROMOTED_ONLY_FOR_TRUSTED_FIXTURE")
        self.assertTrue(result["behavior_equivalent_on_fixed_inputs"])
        self.assertTrue(result["independent_expected_results_passed"])
        self.assertTrue(result["promotion_gate_passed"])
        self.assertFalse(result["full_behavior_equivalence_proven"])

    def test_actual_before_after_line_coverage_has_real_instrumented_counts(self):
        result = module.assess_fixed_repair_promotion("equivalent")
        for target in ("original", "repaired"):
            self.assertEqual(result[target]["line_covered"], result[target]["line_total"])
            self.assertGreaterEqual(result[target]["line_total"], 5)
            self.assertTrue(result[target]["tracer_restored"])

    def test_actual_before_after_branch_coverage_all_truth_outcomes(self):
        result = module.assess_fixed_repair_promotion("equivalent")
        for target in ("original", "repaired"):
            self.assertEqual(result[target]["branch_covered"], result[target]["branch_total"])
            self.assertEqual(result[target]["branch_total"], 4)

    def test_actual_before_after_mutation_score_on_fixed_mutants(self):
        result = module.assess_fixed_repair_promotion("equivalent")
        self.assertEqual(result["original_mutation"], {"killed": 4, "total": 4})
        self.assertEqual(result["repaired_mutation"], {"killed": 4, "total": 4})

    def test_regression_blocked_even_with_full_coverage_and_mutation_score(self):
        result = module.assess_fixed_repair_promotion("regressive")
        self.assertEqual(result["status"], "BLOCKED_BY_TRUSTED_FIXTURE_GATE")
        self.assertFalse(result["behavior_equivalent_on_fixed_inputs"])
        self.assertFalse(result["independent_expected_results_passed"])
        self.assertFalse(result["promotion_gate_passed"])
        self.assertEqual(result["repaired"]["line_covered"], result["repaired"]["line_total"])
        self.assertEqual(result["repaired"]["branch_covered"], result["repaired"]["branch_total"])

    def test_invalid_case_cannot_inject_source(self):
        for case in ("arbitrary-code", "../user.py", "raise RuntimeError()", None, 2):
            with self.subTest(case=case):
                result = module.assess_fixed_repair_promotion(case)
                self.assertEqual(result["status"], "NOT_PROMOTED")
                self.assertFalse(result["arbitrary_user_source_executed"])

    def test_private_fixture_compiler_rejects_untrusted_source_even_if_called_directly(self):
        with self.assertRaisesRegex(ValueError, "untrusted_python_source_execution_refused"):
            module._compile_trusted_fixture("print('UNTRUSTED_SOURCE_SHOULD_NOT_EXECUTE')\n")

    def test_deterministic_coverage_results_on_real_selected_interpreter(self):
        before = sys.gettrace()
        a = module.assess_fixed_repair_promotion("equivalent")
        b = module.assess_fixed_repair_promotion("equivalent")
        self.assertEqual(a, b)
        self.assertIs(sys.gettrace(), before)

    def test_existing_trace_hook_is_restored(self):
        before = sys.gettrace()

        def previous_hook(frame, event, arg):
            return previous_hook

        try:
            sys.settrace(previous_hook)
            result = module.assess_fixed_repair_promotion("equivalent")
            self.assertTrue(result["original"]["tracer_restored"])
            self.assertTrue(result["repaired"]["tracer_restored"])
            self.assertIs(sys.gettrace(), previous_hook)
        finally:
            sys.settrace(before)


class OfflineAnalyzersTests(unittest.TestCase):
    def test_ruff_real_lint_is_not_mypy_or_pyright(self):
        report = module.inspect_offline_typecheckers()
        self.assertEqual(report["ruff_lint"], "TRUSTED_FIXTURE_PASS")
        self.assertFalse(report["ruff_is_typechecker"])
        self.assertFalse(report["mypy_typecheck_verified"])
        self.assertFalse(report["pyright_typecheck_verified"])
        self.assertEqual(report["status"], "NOT_RUN_TYPECHECKERS_UNAVAILABLE")

    def test_ruff_missing_returns_not_run_not_fabricated_pass(self):
        old = module.RUFF_TOOL
        try:
            module.RUFF_TOOL = Path("/missing/no/ruff")
            report = module.inspect_offline_typecheckers()
        finally:
            module.RUFF_TOOL = old
        self.assertEqual(report["ruff_lint"], "NOT_RUN")
        self.assertFalse(report["mypy_typecheck_verified"])

    def test_typecheck_probe_does_not_install_or_read_user_project_source(self):
        report = module.inspect_offline_typecheckers()
        self.assertFalse(report["dependencies_installed"])
        self.assertFalse(report["user_project_source_executed"])
        self.assertFalse(report["network_used"])


if __name__ == "__main__":
    unittest.main()
