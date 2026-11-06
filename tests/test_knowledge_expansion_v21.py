"""v0.21 selected runtime APIs, safe .pyi correlation and honest sync gates."""

from importlib.util import module_from_spec, spec_from_file_location
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("knowledge_expansion_v21",
                               ROOT / "python" / "knowledge_expansion_v21.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)
SHA = hashlib.sha256(b"external-model-binary-declared").hexdigest()
URI = "https://models.example.org/embeddings/immutable-v1"


class KnowledgeExpansionV21Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.stub = self.folder / "types.pyi"
        self.implementation = self.folder / "types.py"

    def test_trusted_runtime_probe_contains_real_native_stdlib_functions(self):
        report = module.native_stdlib_probe()
        self.assertEqual(report["status"], "SELECTED_TRUSTED_RUNTIME_APIS_OBSERVED")
        self.assertEqual(report["python_minor"],
                         "{}.{}".format(sys.version_info.major, sys.version_info.minor))
        rows = {(entry["module"], entry["symbol"]): entry
                for entry in report["symbols"]}
        self.assertIn(("math", "sin"), rows)
        self.assertIn(("math", "cos"), rows)
        self.assertEqual(rows[("math", "sin")]["type_name"],
                         "builtin_function_or_method")
        self.assertTrue(rows[("math", "sin")]["callable"])
        self.assertFalse(report["all_stdlib_apis_covered"])
        self.assertFalse(report["third_party_code_executed"])
        self.assertFalse(report["arbitrary_module_imports_allowed"])

    def test_native_probe_untrusted_input_cannot_select_module(self):
        with self.assertRaises(ValueError):
            module.native_stdlib_probe(0)
        with self.assertRaises(ValueError):
            module.native_stdlib_probe(float("nan"))
        self.assertNotIn("user_module", module._NATIVE_PROBE)
        self.assertNotIn("eval(", module._NATIVE_PROBE)

    def test_static_rename_correlation_by_parameter_shape(self):
        self.stub.write_text("def deprecated(a: int, *, flag: bool) -> int: ...\n"
                             "def stable(a: int) -> int: ...\n", encoding="utf-8")
        self.implementation.write_text("def replacement(a, *, flag):\n    return 2\n"
                                       "def stable(a):\n    return 1\n", encoding="utf-8")
        report = module.correlate_stub_renames(self.stub, self.implementation)
        self.assertEqual(report["possible_renames"][0]["stub_symbol"], "deprecated")
        self.assertEqual(report["possible_renames"][0]["implementation_symbol"],
                         "replacement")
        self.assertEqual(report["same_name_symbols"], ["stable"])
        self.assertFalse(report["source_executed"])
        self.assertFalse(report["runtime_renames_verified"])
        self.assertFalse(report["annotations_evaluated"])

    def test_ambiguous_shape_does_not_claim_certain_rename(self):
        self.stub.write_text("def old(a): ...\n", encoding="utf-8")
        self.implementation.write_text("def possible_a(a): ...\n"
                                       "def possible_b(a): ...\n", encoding="utf-8")
        report = module.correlate_stub_renames(self.stub, self.implementation)
        self.assertEqual(report["possible_renames"], [])
        self.assertEqual(report["ambiguous_or_missing_stub_symbols"], ["old"])

    def test_two_possible_old_names_to_one_new_are_ambiguous(self):
        self.stub.write_text("def old_a(a): ...\ndef old_b(a): ...\n",
                             encoding="utf-8")
        self.implementation.write_text("def replacement(a): ...\n", encoding="utf-8")
        report = module.correlate_stub_renames(self.stub, self.implementation)
        self.assertEqual(report["possible_renames"], [])
        self.assertEqual(set(report["ambiguous_or_missing_stub_symbols"]),
                         {"old_a", "old_b"})

    def test_overloaded_stub_declarations_not_silently_collapsed(self):
        self.stub.write_text("from typing import overload\n"
                             "@overload\ndef old(a: int): ...\n"
                             "@overload\ndef old(a: str): ...\n", encoding="utf-8")
        self.implementation.write_text("def renamed(a): ...\n", encoding="utf-8")
        report = module.correlate_stub_renames(self.stub, self.implementation)
        self.assertEqual(report["possible_renames"], [])

    def test_untrusted_py_source_effects_and_annotations_not_executed(self):
        marker = self.folder / "EXECUTED.marker"
        self.stub.write_text("def old(secret: Dangerous()) -> None: ...\n",
                             encoding="utf-8")
        self.implementation.write_text("open({!r},'w').write('bad')\n"
                                       "def new(secret):\n    pass\n".format(str(marker)),
                                       encoding="utf-8")
        result = module.correlate_stub_renames(self.stub, self.implementation)
        self.assertEqual(len(result["possible_renames"]), 1)
        self.assertFalse(marker.exists())
        self.assertNotIn("Dangerous", json.dumps(result))

    def test_native_rename_scoped_to_same_class(self):
        self.stub.write_text("class A:\n    def old(self, x): ...\n"
                             "class B:\n    def old(self, x): ...\n", encoding="utf-8")
        self.implementation.write_text("class A:\n    def new(self, x): ...\n"
                                       "class B:\n    def another(self, x): ...\n",
                                       encoding="utf-8")
        report = module.correlate_stub_renames(self.stub, self.implementation)
        candidates = {(row["stub_symbol"], row["implementation_symbol"])
                      for row in report["possible_renames"]}
        self.assertEqual(candidates, {("A.old", "A.new"), ("B.old", "B.another")})

    def test_reject_symlink_hardlink_wrong_extensions_and_invalid_ast(self):
        self.stub.write_text("def old(a): ...\n", encoding="utf-8")
        self.implementation.write_text("def new(a): ...\n", encoding="utf-8")
        link = self.folder / "alias.pyi"
        link.symlink_to(self.stub)
        with self.assertRaisesRegex(ValueError, "invalid_static_source_extension_or_symlink"):
            module.correlate_stub_renames(link, self.implementation)
        hard = self.folder / "hard.pyi"
        os.link(self.stub, hard)
        with self.assertRaisesRegex(ValueError, "static_source_not_unique_bounded_file"):
            module.correlate_stub_renames(self.stub, self.implementation)
        hard.unlink()
        self.stub.write_text("def invalid syntax(\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "static_ast_parse_failed"):
            module.correlate_stub_renames(self.stub, self.implementation)

    def test_semantic_quality_known_labels_and_mrr_exact(self):
        docs = [{"id": "math", "vector": [1, 0]},
                {"id": "bytes", "vector": [0, 1]},
                {"id": "other", "vector": [-1, 0]}]
        questions = [{"vector": [1, 0], "relevant": ["math"]},
                     {"vector": [0, 1], "relevant": ["bytes"]}]
        report = module.validate_declared_semantic_quality("declared-v1", SHA, URI,
                                                            docs, questions, top_k=1)
        self.assertEqual(report["recall_at_k"], 1.0)
        self.assertEqual(report["mean_reciprocal_rank"], 1.0)
        self.assertFalse(report["model_binary_loaded"])
        self.assertFalse(report["declared_model_publisher_verified"])
        self.assertFalse(report["embedding_generated_locally"])

    def test_semantic_quality_fails_for_irrelevant_vectors_without_overclaim(self):
        docs = [{"id": "truth", "vector": [0, 1]},
                {"id": "wrong", "vector": [1, 0]}]
        qs = [{"vector": [1, 0], "relevant": ["truth"]}]
        report = module.validate_declared_semantic_quality("declared-v1", SHA, URI,
                                                            docs, qs, top_k=1)
        self.assertEqual(report["recall_at_k"], 0)
        self.assertEqual(report["mean_reciprocal_rank"], 0.5)

    def test_semantic_quality_rejects_fake_provenance_duplicate_and_nan(self):
        docs = [{"id": "a", "vector": [1, 0]},
                {"id": "b", "vector": [0, 1]}]
        qs = [{"vector": [1, 0], "relevant": ["a"]}]
        with self.assertRaises(ValueError):
            module.validate_declared_semantic_quality("bad id", SHA, URI, docs, qs)
        with self.assertRaises(ValueError):
            module.validate_declared_semantic_quality("model-v1", "z" * 64, URI, docs, qs)
        with self.assertRaises(ValueError):
            module.validate_declared_semantic_quality("model-v1", SHA,
                                                      "https://user:password@a.org/x", docs, qs)
        with self.assertRaises(ValueError):
            module.validate_declared_semantic_quality("model-v1", SHA, URI,
                                                      docs + [docs[0]], qs)
        with self.assertRaises(ValueError):
            module.validate_declared_semantic_quality("model-v1", SHA, URI,
                                                      docs, [{"vector": [float("nan"), 0],
                                                              "relevant": ["a"]}])

    def test_future_version_testschema_is_a_draft_not_proof(self):
        report = module.generate_future_testschema("3.16", "3.15",
                                                   ["F067", "F089", "F220"])
        self.assertEqual(report["target_python_minor"], "3.16")
        self.assertFalse(report["runner_same_version"])
        self.assertFalse(report["future_grammar_auto_learned"])
        self.assertFalse(report["tests_executed"])
        self.assertFalse(report["new_interpreter_authenticated"])
        self.assertIn("updater", report["required_suites"])

    def test_testschema_duplicate_bad_features_and_invalid_minor_refused(self):
        with self.assertRaises(ValueError):
            module.generate_future_testschema("3.7", "3.15", [])
        with self.assertRaises(ValueError):
            module.generate_future_testschema("3.16", "3.15", ["F067", "F067"])
        with self.assertRaises(ValueError):
            module.generate_future_testschema("3.16", "3.15", ["bad feature"])

    def test_official_pep_sync_fails_closed_without_independent_authentication(self):
        report = module.pep_official_sync_gate({"status": "Final"})
        self.assertEqual(report["status"], "AUTHENTICATED_OFFICIAL_SOURCE_REQUIRED")
        self.assertFalse(report["automatic_pep_sync"])
        with self.assertRaises(ValueError):
            module.pep_official_sync_gate({"status": "Final"}, True)

    def test_cli_native_probe_and_future_schema_no_source_execution(self):
        script = ROOT / "python" / "knowledge_expansion_v21.py"
        for args in (("native-probe",),
                     ("future-schema", "--target", "3.16", "--observed", "3.15"),
                     ("pep-source-gate",)):
            with self.subTest(args=args):
                result = subprocess.run([sys.executable, "-I", "-S", "-B", str(script),
                                         *args], capture_output=True, text=True, check=True)
                self.assertIn("status", json.loads(result.stdout))


if __name__ == "__main__":
    unittest.main()
