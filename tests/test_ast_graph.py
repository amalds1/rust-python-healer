"""Static CPython AST graph checks: never execute the target code."""

from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("ast_graph", ROOT / "python" / "ast_graph.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


class AstGraphTests(unittest.TestCase):
    def test_definitions_imports_and_static_candidate_calls_have_positions(self):
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / "sample.py"
            script.write_text("import os\nfrom typing import Any\n"
                              "def top(value):\n    return value\n"
                              "class Worker:\n    async def work(self):\n        return top(3)\n")
            data = module.analyze_file(script)
            self.assertEqual(data["status"], "INSPECTED_PARTIAL")
            self.assertEqual(data["syntax_parse"], "PASS")
            self.assertFalse(data["compile_proven"])
            self.assertFalse(data["source_executed"])
            names = {item["qualified_name"]: item for item in data["symbols"]}
            self.assertEqual(set(names), {"top", "Worker", "Worker.work"})
            self.assertEqual(names["top"]["line"], 3)
            self.assertEqual(names["Worker.work"]["line"], 6)
            self.assertEqual(names["Worker.work"]["kind"], "ASYNC_FUNCTION")
            self.assertEqual(data["imports"][0]["modules"], ["os"])
            self.assertEqual(data["imports"][1]["module"], "typing")
            self.assertEqual(data["possible_calls"][0]["from"], "Worker.work")
            self.assertEqual(data["possible_calls"][0]["to"], "top")
            self.assertEqual(data["possible_calls"][0]["status"],
                             "POSSIBLE_STATIC_NAME_NOT_VERIFIED")
            self.assertFalse(data["call_graph_verified"])

    def test_shadowed_function_stays_unverified_candidate(self):
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / "alias.py"
            script.write_text("def top():\n    return 1\n"
                              "def second():\n    top = None\n    return top()\n")
            data = module.analyze_file(script)
            self.assertEqual(data["status"], "INSPECTED_PARTIAL")
            self.assertEqual(len(data["possible_calls"]), 1)
            self.assertEqual(data["possible_calls"][0]["status"],
                             "POSSIBLE_STATIC_NAME_NOT_VERIFIED")

    def test_syntax_error_does_not_leak_source_or_secret_literals(self):
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / "secret.py"
            script.write_text("api_token = 'VERY_PRIVATE_VALUE'\nif True\n pass\n")
            data = module.analyze_file(script)
            self.assertEqual(data["status"], "SYNTAX_ERROR")
            self.assertEqual(data["line"], 2)
            self.assertNotIn("VERY_PRIVATE_VALUE", json.dumps(data))
            self.assertFalse(data["source_executed"])

    def test_pep263_source_encoding_without_import(self):
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / "latin.py"
            script.write_bytes(b"# coding: latin-1\n\ndef caf\xe9():\n    return 42\n")
            data = module.analyze_file(script)
            self.assertEqual(data["status"], "INSPECTED_PARTIAL")
            self.assertEqual(data["symbols"][0]["qualified_name"], "caf\xe9")
            self.assertEqual(data["symbols"][0]["line"], 3)

    def test_invalid_utf8_never_claims_success(self):
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / "invalid.py"
            script.write_bytes(b"value = '\xff'\n")
            data = module.analyze_file(script)
            self.assertEqual(data["status"], "INVALID_ENCODING")
            self.assertFalse(data["compile_proven"])

    def test_external_symlink_and_hardlink_sources_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            source = path / "original.py"
            source.write_text("VALUE = 1\n")
            link = path / "linked.py"
            link.symlink_to(source)
            data = module.analyze_file(link)
            self.assertEqual(data["status"], "NOT_RUN")
            self.assertEqual(data["reason"], "source_not_regular_file")
            hardlink = path / "hardlinked.py"
            import os
            os.link(source, hardlink)
            data = module.analyze_file(source)
            self.assertEqual(data["status"], "NOT_RUN")
            self.assertEqual(data["reason"], "source_hardlink_refused")

    def test_missing_and_oversized_sources_never_parse(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            missing = module.analyze_file(path / "missing.py")
            self.assertEqual(missing["status"], "NOT_RUN")
            too_big = path / "huge.py"
            too_big.write_bytes(b"x" * (module.MAX_SOURCE_BYTES + 1))
            data = module.analyze_file(too_big)
            self.assertEqual(data["status"], "NOT_RUN")
            self.assertEqual(data["reason"], "source_size_limit")

    def test_too_many_nodes_is_not_a_false_pass(self):
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / "small.py"
            script.write_text("answer = 1\nanswer += 2\n")
            prior = module.MAX_NODES
            try:
                module.MAX_NODES = 3
                data = module.analyze_file(script)
            finally:
                module.MAX_NODES = prior
            self.assertEqual(data["status"], "NOT_RUN")
            self.assertEqual(data["reason"], "ast_node_limit")

    def test_newer_python_syntax_is_observed_by_selected_interpreter(self):
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / "match.py"
            script.write_text("match 2:\n    case 2:\n        pass\n")
            data = module.analyze_file(script)
            expected = "SYNTAX_ERROR" if sys.version_info < (3, 10) else "INSPECTED_PARTIAL"
            self.assertEqual(data["status"], expected)

    def test_helper_cli_does_not_execute_risky_source(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            marker = path / "source_executed.txt"
            script = path / "run.py"
            script.write_text("from pathlib import Path\nPath({!r}).write_text('bad')\n".format(str(marker)))
            helper = (ROOT / "python" / "ast_graph.py").read_text(encoding="utf-8")
            proc = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", helper, str(script)],
                                  capture_output=True, text=True, timeout=15, check=True)
            report = json.loads(proc.stdout)
            self.assertEqual(report["status"], "INSPECTED_PARTIAL")
            self.assertFalse(report["source_executed"])
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
