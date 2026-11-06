"""Deterministic property, fuzz, mutation and metamorphic regression checks.

Only trusted, hardcoded local functions and synthetic fixtures are exercised.
Never execute a scanned third-party Python project or random source bytes.
"""

import ast
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import inspect
import json
from pathlib import Path
import random
import sqlite3
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_python_helper(name, file):
    spec = spec_from_file_location(name, ROOT / "python" / file)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


quality = load_python_helper("policy_property", "qualification_policy.py")
static = load_python_helper("ast_property", "ast_graph.py")
versioned = load_python_helper("version_property", "version_regression.py")
updater = load_python_helper("updater_property", "knowledge_updater.py")


def trusted_policy():
    return {"schema_version": 1, "policy_id": "P-property", "maximum_reserves": 1,
            "thresholds": {
                axis: {"metric": metric, "comparison": compare,
                       "limit": {"SAFETY": 0, "CORRECTNESS": 0, "SPEED": 50,
                                 "RELIABILITY": 10, "COMPATIBILITY": 7,
                                 "FUTURE_READINESS": 30}[axis]}
                for axis, (metric, compare) in quality.METRICS.items()}}


class PropertyFuzzMutationMetamorphicTests(unittest.TestCase):
    def test_updater_ingest_seeded_fuzz_preserves_sqlite_schema_and_content_hashes(self):
        """F195 ingestion fuzz offline, without any network downloader invocation."""
        rng = random.Random(0xF195)
        with sqlite3.connect(":memory:") as conn:
            conn.executescript((ROOT / "sql" / "knowledge.sql").read_text(encoding="utf-8"))
            base = {
                "source": "python_docs", "uri": "https://docs.python.org/3.9/library/",
                "title": "Trusted fixture", "package": "stdlib", "version": "3.9",
                "python_constraint": "3.9",
            }
            accepted = 0
            for index in range(96):
                mutated = dict(base)
                mutated["uri"] += "fuzz-" + str(index)
                token = rng.choice(["' OR 1=1 --", "\x00", "🦀", "" * 20,
                                    "CREATE TABLE leaked--", "\\'", "\n" * 40])
                mutated["content"] = "source " + token + str(rng.getrandbits(64))
                updater.index_document(conn, mutated)
                stored = conn.execute("SELECT content,sha256 FROM documents WHERE uri=?",
                                      (mutated["uri"],)).fetchone()
                self.assertEqual(stored[0], mutated["content"])
                self.assertEqual(stored[1], hashlib.sha256(mutated["content"].encode()).hexdigest())
                accepted += 1
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0], accepted)
            self.assertIsNotNone(conn.execute("SELECT name FROM sqlite_master WHERE name='documents'").fetchone())
            for harmful in ("A" * 2_000_001, "\udcff"):
                mutated = dict(base, uri="https://docs.python.org/3.9/invalid",
                               content=harmful)
                with self.assertRaises((ValueError, UnicodeError)):
                    updater.index_document(conn, mutated)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0], accepted)

    def test_property_variant_identity_is_deterministic_and_code_config_dependent(self):
        rng = random.Random(116_2026)
        fingerprints = set()
        for i in range(100):
            left = hashlib.sha256(rng.getrandbits(64).to_bytes(8, "big")).hexdigest()
            right = hashlib.sha256(("cfg-" + str(i)).encode()).hexdigest()
            expected = quality.identity("fixed-engine", left, right)
            self.assertEqual(expected, quality.identity("fixed-engine", left, right))
            self.assertNotEqual(expected, quality.identity("fixed-engine", right, left))
            fingerprints.add(expected)
        self.assertEqual(len(fingerprints), 100)

    def test_property_exact_six_gates_never_accept_weakened_safety_and_correctness(self):
        original = trusted_policy()
        self.assertEqual(len(quality.validate_policy(original)), 6)
        for axis in quality.AXES:
            mutated = json.loads(json.dumps(original))
            mutated["thresholds"].pop(axis)
            with self.assertRaisesRegex(ValueError, "six_thresholds_required"):
                quality.validate_policy(mutated)
        for axis in ("SAFETY", "CORRECTNESS"):
            weakened = json.loads(json.dumps(original))
            weakened["thresholds"][axis]["limit"] = 1
            with self.assertRaisesRegex(ValueError, "critical_failures_must_be_zero"):
                quality.validate_policy(weakened)

    def test_source_mutation_kills_weakened_safety_threshold_check(self):
        """Change an actual trusted function AST comparator and detect the mutant."""
        original = trusted_policy()
        original["thresholds"]["SAFETY"]["limit"] = 1
        with self.assertRaises(ValueError):
            quality.validate_policy(original)

        tree = ast.parse(textwrap.dedent(inspect.getsource(quality.validate_policy)))

        class DisableSafetyGuard(ast.NodeTransformer):
            changed = 0

            def visit_If(self, node):
                self.generic_visit(node)
                if (isinstance(node.test, ast.BoolOp) and
                        isinstance(node.test.op, ast.And) and
                        any(isinstance(expr, ast.Compare) and
                                isinstance(expr.left, ast.Name) and
                                expr.left.id == "limit" for expr in node.test.values)):
                    node.test = ast.Constant(value=False)
                    self.changed += 1
                return node

        transformer = DisableSafetyGuard()
        mutated_tree = ast.fix_missing_locations(transformer.visit(tree))
        self.assertEqual(transformer.changed, 1, "source mutation must hit exact real guard")
        isolated_scope = dict(quality.__dict__)
        exec(compile(mutated_tree, "<trusted_function_mutant>", "exec"), isolated_scope)
        self.assertEqual(len(isolated_scope["validate_policy"](original)), 6,
                         "mutated guard should be killed by strict original regression")

    def test_mutation_cannot_silently_disable_dap_or_policy_schema_gates(self):
        valid = trusted_policy()
        for invalid in (None, False, [], {"schema_version": True},
                        {"schema_version": 1, "policy_id": "bad"}):
            with self.assertRaises((ValueError, TypeError)):
                quality.validate_policy(invalid)
        valid["thresholds"]["RELIABILITY"]["limit"] = 9
        with self.assertRaises(ValueError):
            quality.validate_policy(valid)

    def test_fuzz_random_bytes_never_execute_ast_source_or_invent_compile_proof(self):
        rng = random.Random(24_061)
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "fuzz.py"
            for _ in range(175):
                raw = bytes(rng.randrange(0, 256) for _ in range(rng.randrange(0, 260)))
                file.write_bytes(raw)
                report = static.analyze_file(file)
                self.assertIn(report["status"], (
                    "INSPECTED_PARTIAL", "INVALID_ENCODING", "SYNTAX_ERROR", "NOT_RUN"))
                self.assertIs(report["source_executed"], False)
                self.assertIs(report["compile_proven"], False)

    def test_fuzz_invalid_regression_manifests_never_report_match(self):
        rng = random.Random(931)
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "bad-manifest.json"
            for _ in range(175):
                target.write_bytes(bytes(rng.randrange(256) for _ in range(rng.randrange(1, 320))))
                result = versioned.inspect(target)
                self.assertNotEqual(result["status"], "BASELINE_MATCH")
                self.assertFalse(result["untrusted_source_executed"])

    def test_metamorphic_ast_comments_do_not_change_symbol_relationships(self):
        template = ("def output(x):\n    return x\n\n"
                    "def caller():\n    return output(1)\n")
        with tempfile.TemporaryDirectory() as folder:
            script = Path(folder) / "project.py"
            observations = []
            for comment_count in range(0, 6):
                script.write_text("# maintained comment\n" * comment_count + template)
                report = static.analyze_file(script)
                self.assertEqual(report["status"], "INSPECTED_PARTIAL")
                observations.append((
                    tuple(item["qualified_name"] for item in report["symbols"]),
                    tuple((item["from"], item["to"]) for item in report["possible_calls"])))
            self.assertTrue(all(value == observations[0] for value in observations))

    def test_metamorphic_regression_reference_is_independent_of_json_dict_key_order(self):
        data = versioned.observations()
        a = versioned.reference(data)
        data["bytecode"] = dict(reversed(list(data["bytecode"].items())))
        data["ast"] = dict(reversed(list(data["ast"].items())))
        self.assertEqual(a, versioned.reference(data))


if __name__ == "__main__":
    unittest.main()
