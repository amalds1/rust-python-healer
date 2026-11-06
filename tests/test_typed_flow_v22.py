"""Independent, data-only multi-file AST/CFG/typing/alias regression checks."""

import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "typed_flow_v22.py"
spec = importlib.util.spec_from_file_location("typed_flow_v22", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class StaticGraphFlowTests(unittest.TestCase):
    def setUp(self):
        self.sources = {
            "core.py": "def add(left: int, right: int) -> int:\n    return left + right\n",
            "app.py": ("from core import add\n"
                       "good = add(1, 2)\n"
                       "bad = add(1, 'oops')\n"),
        }

    def report(self, sources=None):
        return module.analyze_sources(self.sources if sources is None else sources)

    def test_f092_independent_ast_inventories_return_annotation(self):
        row = self.report()
        self.assertTrue(row["supports_multi_module_static_resolution"])
        self.assertEqual(len(row["type_mismatches"]), 1)
        self.assertEqual(row["type_mismatches"][0]["expected"], "int")
        self.assertEqual(row["type_mismatches"][0]["actual"], "str")
        self.assertFalse(row["target_modules_imported"])

    def test_f092_annotated_assign_type_mismatch(self):
        result = self.report({"one.py": "count: int = 'error'\n"})
        self.assertEqual(result["type_mismatches"][0]["kind"], "ANNOTATION_TYPE")

    def test_f092_return_type_mismatch_annotated_method(self):
        result = self.report({"one.py": "def f() -> str:\n    return 10\n"})
        self.assertEqual(result["type_mismatches"][0]["kind"], "RETURN_TYPE")

    def test_f092_unknown_generic_type_does_not_raise_false_positive(self):
        result = self.report({"one.py": "def f(a: list[int]):\n    return a\nf(3)\n"})
        self.assertEqual(result["type_mismatches"], [])
        self.assertFalse(result["full_python_dynamic_semantics_proven"])

    def test_f092_cross_module_explicit_alias_is_resolved(self):
        result = self.report({"mod.py": "def f(x: str) -> str:\n    return x\n",
                              "caller.py": "import mod as local\ny = local.f(99)\n"})
        self.assertEqual(result["static_call_edges"][0]["to_module"], "mod")
        self.assertEqual(result["type_mismatches"][0]["expected"], "str")

    def test_f097_control_flow_real_branch_merge(self):
        result = self.report({"one.py": (
            "def f(flag):\n"
            "    if flag:\n"
            "        value = 1\n"
            "    else:\n"
            "        value = 2\n"
            "    return value\n")})
        graph = result["control_flow_graphs"][0]
        branches = {edge["branch"] for edge in graph["edges"]}
        self.assertIn("true", branches)
        self.assertIn("false", branches)
        self.assertIn("terminal", branches)
        self.assertEqual(graph["nodes"][0]["kind"], "ENTRY")
        self.assertEqual(graph["nodes"][-1]["kind"], "EXIT")

    def test_f097_loop_creates_real_back_edge(self):
        result = self.report({"one.py": (
            "def f(n):\n"
            "    x = 0\n"
            "    while x < n:\n"
            "        x += 1\n"
            "    return x\n")})
        edges = result["control_flow_graphs"][0]["edges"]
        self.assertTrue(any(edge["branch"] == "loop_back" for edge in edges))
        self.assertTrue(any(edge["branch"] == "exhausted" for edge in edges))

    def test_f097_local_static_call_edges_and_imported_ones(self):
        result = self.report({"a.py": "def inner():\n    return 3\ndef outer():\n    return inner()\n",
                              "b.py": "from a import outer\nresult = outer()\n"})
        edges = {(row["from_module"], row["to_function"]) for row in result["static_call_edges"]}
        self.assertEqual(edges, {("a", "inner"), ("b", "outer")})
        self.assertTrue(all(row["status"] == "STATIC_NAME_RESOLUTION_ONLY"
                            for row in result["static_call_edges"]))

    def test_f097_unknown_dynamic_calls_recorded_unproven(self):
        row = self.report({"a.py": "def f(obj):\n    return obj.dynamic_call()\n"})
        self.assertEqual(row["static_call_edges"], [])
        self.assertGreaterEqual(row["unresolved_dynamic_call_count"], 1)

    def test_f099_local_list_alias_and_mutation(self):
        row = self.report({"a.py": (
            "def f():\n"
            "    items = []\n"
            "    mirror = items\n"
            "    mirror.append(3)\n"
            "    return items\n")})
        trace = row["alias_dataflow"][0]
        self.assertEqual(trace["mutations"][0]["method"], "append")
        self.assertEqual(trace["mutations"][0]["aliases_at_mutation"],
                         ["items", "mirror"])
        self.assertTrue(trace["branch_sensitive"])

    def test_f099_reassignment_breaks_stale_alias(self):
        row = self.report({"a.py": (
            "def f():\n"
            "    first = []\n"
            "    second = first\n"
            "    second = []\n"
            "    second.append(4)\n"
            "    return first\n")})
        trace = row["alias_dataflow"][0]
        self.assertEqual(trace["mutations"][0]["aliases_at_mutation"], ["second"])

    def test_f099_branch_aliasing_is_explicitly_unknown(self):
        row = self.report({"a.py": (
            "def f(flag):\n"
            "    first = []\n"
            "    if flag:\n"
            "        second = first\n"
            "    return first\n")})
        self.assertFalse(row["alias_dataflow"][0]["branch_sensitive"])

    def test_f099_dictionary_mutation_observed_without_execution(self):
        row = self.report({"a.py": (
            "def f():\n"
            "    bag = {}\n"
            "    other = bag\n"
            "    other.update({'x': 1})\n")})
        self.assertEqual(row["alias_dataflow"][0]["mutations"][0]["method"], "update")
        self.assertFalse(row["project_source_executed"])

    def test_f092_actual_python_ast_parser_is_independent_syntax_oracle(self):
        source = "def f(x: int) -> int:\n    return x\n"
        ast.parse(source)
        result = self.report({"one.py": source})
        self.assertEqual(result["type_mismatches"], [])
        self.assertEqual(result["control_flow_graphs"][0]["function"], "f")

    def test_invalid_syntax_blocks_false_result(self):
        with self.assertRaisesRegex(ValueError, "invalid_python_syntax"):
            self.report({"x.py": "def f(:\n"})

    def test_python_module_name_parent_escape_refused(self):
        with self.assertRaisesRegex(ValueError, "invalid_module_name"):
            self.report({"../escape.py": "x = 1\n"})

    def test_source_size_and_module_budget_limit(self):
        with self.assertRaisesRegex(ValueError, "invalid_source_size"):
            self.report({"x.py": "x" * 1000001})
        with self.assertRaisesRegex(ValueError, "invalid_module_count"):
            self.report({"p{}.py".format(i): "x=1\n" for i in range(33)})

    def test_unicode_sha256_is_real_and_source_not_executed(self):
        text = "message = 'héllø'\n"
        row = self.report({"utf8.py": text})
        import hashlib
        self.assertEqual(row["versions"]["utf8"], hashlib.sha256(text.encode()).hexdigest())
        self.assertFalse(row["project_source_executed"])

    def test_version_aware_python_syntax_does_not_silently_pass(self):
        source = "match value:\n    case 1: pass\n"
        if sys.version_info >= (3, 10):
            self.assertEqual(self.report({"m.py": source})["type_mismatches"], [])
        else:
            with self.assertRaisesRegex(ValueError, "invalid_python_syntax"):
                self.report({"m.py": source})

    def test_cli_capability_is_truthful_and_read_only(self):
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)],
                                capture_output=True, text=True, timeout=6, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["status"], "BOUNDED_STATIC_ANALYSIS_CAPABILITIES")
        self.assertFalse(data["unknown_source_execution"])
        self.assertFalse(data["dynamic_semantics_proven"])


if __name__ == "__main__":
    unittest.main()
