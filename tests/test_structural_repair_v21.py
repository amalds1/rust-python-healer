"""F010/F027/F028/F091/F092/F097/F099/F193 stdlib-only versioned QA."""

from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("structural_repair_v21", ROOT / "python" / "structural_repair_v21.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(folder, filename, content):
    file = Path(folder) / filename
    file.write_text(content, encoding="utf-8")
    return file


class RepairTests(unittest.TestCase):
    def test_two_independent_strategies_repair_and_preserve_inline_comment(self):
        src = "if True  # beautiful comment\n    answer = 42\n"
        report = module.propose_colon_repair(src)
        self.assertEqual(report["status"], "COMPILES_TWO_INDEPENDENT_STRATEGIES")
        self.assertEqual(report["strategy_count"], 2)
        self.assertEqual(report["candidate"], "if True:  # beautiful comment\n    answer = 42\n")
        self.assertTrue(report["validation"]["formatting_and_comments_preserved"])
        self.assertFalse(report["source_executed"])

    def test_quoted_hash_and_real_comment_are_not_confused(self):
        src = "if value == '#inside'  # after quote\n    pass\n"
        result = module.propose_colon_repair(src)
        self.assertEqual(result["status"], "COMPILES_TWO_INDEPENDENT_STRATEGIES")
        self.assertEqual(result["candidate"], src.replace("'#inside'  #", "'#inside':  #"))

    def test_crlf_and_whitespace_preserved(self):
        src = "if True \t # keep this\r\n\tprint('x')\r\n"
        result = module.propose_colon_repair(src)
        self.assertEqual(result["status"], "COMPILES_TWO_INDEPENDENT_STRATEGIES")
        self.assertEqual(result["candidate"], "if True: \t # keep this\r\n\tprint('x')\r\n")

    def test_correction_works_on_function_and_else_headers(self):
        for source in ("def f(x)\n    return x\n", "if False:\n    pass\nelse\n    pass\n"):
            with self.subTest(source=source):
                result = module.propose_colon_repair(source)
                self.assertEqual(result["status"], "COMPILES_TWO_INDEPENDENT_STRATEGIES")

    def test_independent_advice_validator_rejects_semantic_rewrite(self):
        src = "if x < 2\n    pass\n"
        altered = "if x > 2:\n    pass\n"
        result = module.validate_colon_advice(src, altered)
        self.assertFalse(result["advice_valid"])
        self.assertFalse(result["semantics_verified"])

    def test_advice_validator_rejects_additional_comment_rewrite(self):
        src = "if True  # private original\n    pass\n"
        bad = "if True:  # public changed\n    pass\n"
        result = module.validate_colon_advice(src, bad)
        self.assertFalse(result["advice_valid"])

    def test_validator_requires_syntax_error_in_original(self):
        src = "if True:\n    pass\n"
        result = module.validate_colon_advice(src, "if True::\n    pass\n")
        self.assertFalse(result["advice_valid"])

    def test_advice_validator_rejects_dict_colon_unrelated_to_compound_header(self):
        original = "x = {'a' 1}\n"
        candidate = "x = {'a': 1}\n"
        result = module.validate_colon_advice(original, candidate)
        self.assertFalse(result["advice_valid"])
        self.assertEqual(result["reason"], "insertion_not_on_compound_header")

    def test_unpaired_surrogates_fail_closed_without_source_echo(self):
        source = "if True\n  x='\ud800'\n"
        result = module.propose_colon_repair(source)
        self.assertEqual(result["reason"], "source_invalid_unicode")
        self.assertEqual(module.inspect_ast_and_tokens(source)["reason"], "source_invalid_unicode")

    def test_unrepairable_syntax_not_presented_as_fixed(self):
        for src in ("x = (\n", "def f(:\n    return 1\n",
                    "if True:\n pass\n x = 1\n", "hello = 9\n",
                    "if (True and\n   False)\n    pass\n"):
            with self.subTest(src=src):
                result = module.propose_colon_repair(src)
                self.assertEqual(result["status"], "NO_PATCH")

    def test_valid_syntax_no_repair_even_when_header_exists(self):
        self.assertEqual(module.propose_colon_repair("if True:\n    pass\n")["status"], "NO_PATCH")

    def test_repair_does_not_claim_behavior(self):
        result = module.propose_colon_repair("while False\n  pass\n")
        self.assertEqual(result["status"], "COMPILES_TWO_INDEPENDENT_STRATEGIES")
        self.assertFalse(result["semantic_correctness_proven"])
        self.assertFalse(result["validation"]["user_code_executed"])


class AstTokenTests(unittest.TestCase):
    def test_ast_nodes_with_source_parent_and_utf8_byte_offsets(self):
        text = "name = 'café'  # comment\nprint(name)\n"
        result = module.inspect_ast_and_tokens(text)
        self.assertEqual(result["status"], "AST_PLUS_LOSSLESS_TOKEN_TRIVIA")
        self.assertTrue(result["exact_token_roundtrip"])
        self.assertEqual(result["comment_count"], 1)
        self.assertTrue(any(n["kind"] == "Assign" for n in result["ast_nodes"]))
        self.assertTrue(any(n["kind"] == "Call" for n in result["ast_nodes"]))
        self.assertTrue(all("start_utf8_byte_column" in n for n in result["ast_nodes"]))
        self.assertFalse(result["full_cst_built"])

    def test_token_stream_distinguishes_comments_newlines_and_indents(self):
        src = "# header\ndef f():\n    # inside\n    return 2\n"
        result = module.inspect_ast_and_tokens(src)
        kinds = {token["kind"] for token in result["tokens"]}
        self.assertIn("COMMENT", kinds)
        self.assertIn("INDENT", kinds)
        self.assertIn("DEDENT", kinds)
        self.assertTrue(result["exact_token_roundtrip"])

    def test_no_source_secrets_copied_into_structural_report(self):
        secret = "TOP_SECRET_VALUE_4738"
        result = module.inspect_ast_and_tokens("private = '{}'\n".format(secret))
        self.assertNotIn(secret, json.dumps(result))
        self.assertFalse(result["source_executed"])

    def test_ast_reports_version_specific_match_syntax(self):
        src = "match 3:\n    case 3:\n        pass\n"
        report = module.inspect_ast_and_tokens(src)
        expected = "NOT_RUN" if sys.version_info.minor == 9 else "AST_PLUS_LOSSLESS_TOKEN_TRIVIA"
        self.assertEqual(report["status"], expected)

    def test_ast_budget_limit_is_a_hard_failure(self):
        old = module.MAX_AST_NODES
        try:
            module.MAX_AST_NODES = 1
            report = module.inspect_ast_and_tokens("x = 1\n")
        finally:
            module.MAX_AST_NODES = old
        self.assertEqual(report["reason"], "ast_node_limit")

    def test_token_quota_cannot_be_exceeded_silently(self):
        old = module.MAX_TOKENS
        try:
            module.MAX_TOKENS = 3
            report = module.inspect_ast_and_tokens("a = 1\n")
        finally:
            module.MAX_TOKENS = old
        self.assertEqual(report["status"], "NOT_RUN")
        self.assertEqual(report["reason"], "token_count_limit")


class CrossModuleTypesTests(unittest.TestCase):
    def test_structured_crossmodule_annotation_from_import_without_running_module(self):
        with tempfile.TemporaryDirectory() as folder:
            alpha = fixture(folder, "alpha.py",
                            "raise RuntimeError('not executed')\ndef score() -> int:\n    return 7\n")
            beta = fixture(folder, "beta.py", "from alpha import score as calculate\nanswer = calculate()\n")
            report = module.inspect_crossmodule_types({"alpha.py": alpha, "beta.py": beta})
            self.assertEqual(report["status"], "CROSSMODULE_STATIC_CANDIDATES")
            inferred = report["inferred_assignments"]
            self.assertEqual(len(inferred), 1)
            self.assertEqual(inferred[0]["candidate_type"], "int")
            self.assertFalse(report["modules_imported"])
            self.assertFalse(report["semantic_types_proven"])

    def test_module_import_alias_attribute_call(self):
        with tempfile.TemporaryDirectory() as folder:
            alpha = fixture(folder, "alpha.py", "def describe() -> str:\n    return 'x'\n")
            beta = fixture(folder, "beta.py", "import alpha as a\nresult = a.describe()\n")
            report = module.inspect_crossmodule_types({"alpha.py": alpha, "beta.py": beta})
            self.assertEqual(report["inferred_assignments"][0]["candidate_type"], "str")

    def test_literal_return_without_annotation_is_candidate_only(self):
        with tempfile.TemporaryDirectory() as folder:
            alpha = fixture(folder, "alpha.py", "def flag():\n    return True\n")
            beta = fixture(folder, "beta.py", "from alpha import flag\nv = flag()\n")
            report = module.inspect_crossmodule_types({"alpha.py": alpha, "beta.py": beta})
            self.assertEqual(report["inferred_assignments"][0]["candidate_type"], "bool")
            self.assertEqual(report["inferred_assignments"][0]["confidence"],
                             "LITERAL_RETURN_CANDIDATE_NOT_PROVEN")

    def test_unknown_import_and_dynamic_return_not_proven(self):
        with tempfile.TemporaryDirectory() as folder:
            alpha = fixture(folder, "alpha.py", "def foo(x):\n    return x\n")
            beta = fixture(folder, "beta.py", "from alpha import foo\nv = foo(4)\n")
            report = module.inspect_crossmodule_types({"alpha.py": alpha, "beta.py": beta})
            self.assertEqual(report["inferred_assignments"], [])
            self.assertGreater(report["unresolved_calls"], 0)

    def test_import_binding_shadowed_before_call_is_not_typed(self):
        with tempfile.TemporaryDirectory() as folder:
            alpha = fixture(folder, "alpha.py", "def score() -> int:\n    return 1\n")
            beta = fixture(folder, "beta.py", "from alpha import score\nscore=lambda: 'unsafe'\nx=score()\n")
            report = module.inspect_crossmodule_types({"alpha.py": alpha, "beta.py": beta})
            self.assertEqual(report["inferred_assignments"], [])

    def test_late_import_does_not_retroactively_type_prior_call(self):
        with tempfile.TemporaryDirectory() as folder:
            alpha = fixture(folder, "alpha.py", "def score() -> int:\n    return 1\n")
            beta = fixture(folder, "beta.py", "x=score()\nfrom alpha import score\n")
            report = module.inspect_crossmodule_types({"alpha.py": alpha, "beta.py": beta})
            self.assertEqual(report["inferred_assignments"], [])

    def test_circular_imports_do_not_trigger_import_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            alpha = fixture(folder, "alpha.py", "from beta import b\ndef a() -> int:\n    return 1\n")
            beta = fixture(folder, "beta.py", "from alpha import a\ndef b() -> str:\n    return 'x'\nx = a()\n")
            result = module.inspect_crossmodule_types({"alpha.py": alpha, "beta.py": beta})
            self.assertEqual(result["inferred_assignments"][0]["candidate_type"], "int")
            self.assertFalse(result["user_code_executed"])

    def test_symlink_and_hardlink_modules_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            real = fixture(folder, "alpha.py", "def safe() -> int:\n    return 1\n")
            alias = Path(folder) / "symlink.py"
            alias.symlink_to(real)
            self.assertEqual(module.inspect_crossmodule_types({"symlink.py": alias})["status"], "NOT_RUN")
            hard = Path(folder) / "hardlink.py"
            os.link(real, hard)
            self.assertEqual(module.inspect_crossmodule_types({"alpha.py": real})["reason"],
                             "source_not_private_regular_file")

    def test_crossmodule_size_and_module_count_limits(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "large.py"
            with source.open("wb") as handle:
                handle.truncate(module.MAX_SOURCE_BYTES + 1)
            report = module.inspect_crossmodule_types({"large.py": source})
            self.assertEqual(report["reason"], "source_size_limit")
            many = {"file{}.py".format(i): source for i in range(module.MAX_MODULES + 1)}
            self.assertEqual(module.inspect_crossmodule_types(many)["reason"],
                             "invalid_module_inventory")


class FlowAliasCoverageTests(unittest.TestCase):
    def test_cfg_contains_true_false_and_unconditional_exit_edges(self):
        src = "def f(n):\n    if n > 0:\n        return 1\n    return -1\nf(2)\n"
        report = module.inspect_cfg_calls(src)
        self.assertEqual(report["status"], "PARTIAL_STATIC_CONTROL_FLOW_AND_CALL_GRAPH")
        labels = {edge["edge"] for edge in report["edges"]}
        self.assertIn("IF_TRUE", labels)
        self.assertIn("IF_FALSE", labels)
        self.assertIn("STOP", labels)
        self.assertEqual(report["possible_calls"][0]["to"], "f")
        self.assertFalse(report["runtime_call_targets_verified"])

    def test_cfg_loop_backedges_and_exit_are_recorded(self):
        src = "def f(n):\n    while n > 0:\n        n = n - 1\n    return n\n"
        report = module.inspect_cfg_calls(src)
        labels = {edge["edge"] for edge in report["edges"]}
        self.assertIn("LOOP_BODY_POSSIBLE", labels)
        self.assertIn("LOOP_EXIT_POSSIBLE", labels)
        self.assertFalse(report["exceptional_control_flow_verified"])

    def test_cfg_bounded_node_and_edge_limit(self):
        old = module.MAX_GRAPH_EDGES
        try:
            module.MAX_GRAPH_EDGES = 1
            result = module.inspect_cfg_calls("def f():\n    return 7\nf()\n")
        finally:
            module.MAX_GRAPH_EDGES = old
        self.assertEqual(result["reason"], "cfg_edge_budget")

    def test_alias_equivalence_at_end_of_straightline_assignments(self):
        src = "def f():\n    a = []\n    b = a\n    c = b\n    return c\n"
        report = module.inspect_straightline_aliases(src)
        self.assertEqual(report["alias_groups"][0]["bound_names"], ["a", "b", "c"])
        self.assertFalse(report["heap_points_to_proven"])

    def test_alias_reassignment_kills_old_binding_equivalence(self):
        src = "def f():\n    a = []\n    b = a\n    a = {}\n    return b\n"
        report = module.inspect_straightline_aliases(src)
        self.assertEqual(report["alias_groups"], [])

    def test_delete_and_walrus_disable_alias_claims(self):
        src = "def f():\n    a = []\n    b = a\n    del a\n"
        expression = "def g():\n    a=[]\n    b=a\n    print(c := 3)\n"
        report = module.inspect_straightline_aliases(src + expression)
        self.assertEqual(report["alias_groups"], [])
        self.assertEqual(report["skipped_control_or_dynamic_functions"], 2)

    def test_control_branches_and_dynamic_exec_disable_alias_claims(self):
        src = "def f():\n    a=[]\n    if True:\n        b=a\n"
        dynamic = "def g():\n    a=[]\n    b=a\n    exec('b=5')\n"
        report = module.inspect_straightline_aliases(src + dynamic)
        self.assertEqual(report["alias_groups"], [])
        self.assertEqual(report["skipped_control_or_dynamic_functions"], 2)

    def test_trusted_fixture_coverage_is_complete_and_trace_restored(self):
        before = sys.gettrace()
        report = module.measure_hardcoded_fixture_coverage()
        self.assertEqual(report["status"], "TRUSTED_FIXTURE_COVERAGE_MEASURED")
        self.assertEqual(report["line_covered"], report["line_total"])
        self.assertEqual(report["branch_covered"], report["branch_total"])
        self.assertEqual(report["mutants_killed"], report["mutants_total"])
        self.assertEqual(report["mutants_total"], 4)
        self.assertTrue(report["tracer_restored"])
        self.assertIs(before, sys.gettrace())
        self.assertFalse(report["arbitrary_code_executed"])

    def test_coverage_trace_restored_with_preexisting_trace(self):
        previous = sys.gettrace()

        def other_tracer(_frame, _event, _arg):
            return other_tracer

        try:
            sys.settrace(other_tracer)
            report = module.measure_hardcoded_fixture_coverage()
            self.assertTrue(report["tracer_restored"])
            self.assertIs(sys.gettrace(), other_tracer)
        finally:
            sys.settrace(previous)


if __name__ == "__main__":
    unittest.main()
