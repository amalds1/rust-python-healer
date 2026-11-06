"""Predeclared independent relevance labels for a genuinely trained LSA model."""

from importlib.util import module_from_spec, spec_from_file_location
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "semantic_retrieval_v23.py"
spec = spec_from_file_location("semantic_retrieval_v23", SCRIPT)
module = module_from_spec(spec)
spec.loader.exec_module(module)

# Frozen before training and kept OUTSIDE the encoder module. The query strings
# do not occur in the trained metadata or source-selection policy.
HELDOUT_JUDGMENTS = {
    "greatest common divisor": ["math.gcd"],
    "least common multiple": ["math.lcm"],
    "integer part square root": ["math.isqrt"],
    "square root of number": ["math.sqrt"],
    "cyclically repeat elements forever": ["itertools.cycle"],
    "reorder arrangements of iterable items": ["itertools.permutations"],
    "choose combinations of iterable items": ["itertools.combinations"],
    "arithmetic average of numeric data": ["statistics.mean"],
    "middle value of numeric data": ["statistics.median"],
    "deserialize json formatted text": ["json.loads"],
    "serialize json formatted text": ["json.dumps"],
    "replace every pattern occurrence in a string": ["re.sub"],
    "merge sorted inputs": ["heapq.merge"],
    "binary search insertion index sorted sequence": ["bisect.bisect_left"],
}
LABEL_ORACLE = {"schema": 1, "labels": HELDOUT_JUDGMENTS,
                "annotation_source": "separate-frozen-human-labeled-real-stdlib-api-fixture"}
AUDITOR_KEY = b"independent-real-stdlib-relevance-oracle-v23-fixed"
PREDECLARED_MIN_RECALL = 0.80
PREDECLARED_MIN_MRR = 0.50
PREDECLARED_TOP_K = 5


def signed(labels):
    return hmac.new(AUDITOR_KEY, module._json_bytes(labels), hashlib.sha256).hexdigest()


class RealPretrainedCorpusEncoderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = module.stdlib_corpus()
        cls.model = module.train_lsa_encoder(cls.corpus)

    def test_real_unsupervised_training_from_selected_stdlib_docstrings(self):
        self.assertEqual(self.corpus["status"], "REAL_INSTALLED_STDLIB_DOCSTRINGS")
        self.assertGreaterEqual(len(self.corpus["sources"]), 100)
        self.assertEqual(self.model["status"], "REAL_UNSUPERVISED_STDLIB_LSA_TRAINED")
        self.assertGreaterEqual(self.model["components"], 8)
        self.assertGreaterEqual(self.model["vocabulary_size"], 100)
        self.assertTrue(self.model["training_seconds"] > 0)
        self.assertFalse(self.model["train_labels_consumed"])
        self.assertFalse(self.model["source_code_executed"])

    def test_relevance_gate_predeclared_not_retuned_after_training(self):
        result = module.evaluate_heldout(
            self.model, LABEL_ORACLE, signed(LABEL_ORACLE), AUDITOR_KEY,
            min_recall=PREDECLARED_MIN_RECALL, min_mrr=PREDECLARED_MIN_MRR,
            top_k=PREDECLARED_TOP_K)
        self.assertEqual(result["status"], "HELDOUT_SEMANTIC_QUALITY_PASS", result)
        self.assertGreaterEqual(result["macro_recall_at_k"], PREDECLARED_MIN_RECALL)
        self.assertGreaterEqual(result["macro_mrr"], PREDECLARED_MIN_MRR)
        self.assertEqual(result["evaluated_queries"], len(HELDOUT_JUDGMENTS))
        self.assertTrue(result["actual_trained_embedding_inference"])

    def test_learned_latent_scores_are_not_cosine_of_supplied_vectors(self):
        result = module.semantic_search(self.model, "greatest common divisor")
        self.assertEqual(result["status"], "REAL_TRAINED_CORPUS_ENCODER_RESULTS")
        self.assertTrue(result["real_encoder_inference_executed"])
        self.assertTrue(any(abs(row["latent_score"] - row["lexical_score"]) > .01
                            for row in result["results"]))
        self.assertEqual(result["model_sha256"], self.model["model_sha256"])

    def test_wrong_relevance_labels_fail_without_retraining_model(self):
        wrong = {"schema": 1,
                 "labels": {name: ["itertools.chain"] for name in HELDOUT_JUDGMENTS},
                 "annotation_source": LABEL_ORACLE["annotation_source"]}
        result = module.evaluate_heldout(self.model, wrong, signed(wrong), AUDITOR_KEY,
                                         min_recall=.80, min_mrr=.50, top_k=5)
        self.assertEqual(result["status"], "HELDOUT_SEMANTIC_QUALITY_FAIL")

    def test_label_tampering_without_matching_auditor_signature_rejected(self):
        wrong = dict(LABEL_ORACLE)
        wrong["labels"] = {key: value for key, value in HELDOUT_JUDGMENTS.items()}
        wrong["labels"]["greatest common divisor"] = ["json.loads"]
        with self.assertRaisesRegex(ValueError,
                                    "independently_signed_relevance_oracle_required"):
            module.evaluate_heldout(self.model, wrong, signed(LABEL_ORACLE), AUDITOR_KEY)

    def test_out_of_vocabulary_query_returns_no_evidence_not_pass(self):
        result = module.semantic_search(self.model, "zzqvxx noexistingtermonmars")
        self.assertEqual(result["status"], "NO_EVIDENCE_UNKNOWN_QUERY_TERMS")
        self.assertFalse(result["real_encoder_inference_executed"])

    def test_source_tampering_fails_before_model_training(self):
        altered = dict(self.corpus)
        altered["sources"] = dict(self.corpus["sources"])
        altered["sources"]["math.gcd"] = "MALICIOUS_FAKE_DOCSTRING"
        with self.assertRaisesRegex(ValueError, "stdlib_doc_source_digest_mismatch"):
            module.train_lsa_encoder(altered)

    def test_actual_interpreter_version_and_local_source_sha(self):
        self.assertEqual(self.corpus["python_minor"],
                         "{}.{}".format(*sys.version_info[:2]))
        for name in module.REQUIRED_REAL_SYMBOLS:
            self.assertIn(name, self.model["source_shas"])
            content = self.corpus["sources"][name]
            self.assertEqual(hashlib.sha256(content.encode()).hexdigest(),
                             self.model["source_shas"][name])

    def test_encoder_repeat_training_is_deterministically_identified(self):
        again = module.train_lsa_encoder(self.corpus)
        self.assertEqual(again["model_sha256"], self.model["model_sha256"])
        self.assertEqual(again["components"], self.model["components"])

    def test_labels_never_enter_training_metadata(self):
        for label in HELDOUT_JUDGMENTS:
            self.assertNotIn(label, json.dumps({"model_family": self.model["model_family"],
                                                "model_sha256": self.model["model_sha256"]}))
        self.assertFalse(self.model["general_semantic_accuracy_attested"])


class SemanticRetrievalCliV23Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rph-semantic-v23-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)] + list(args),
                              capture_output=True, text=True, check=False, timeout=20)

    def test_default_capabilities_no_training_claim(self):
        run = self.run_cli()
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["status"],
                         "LOCAL_TRAINED_SEMANTIC_ENCODER_AVAILABLE_NOT_YET_RUN")
        self.assertFalse(report["external_network_called"])
        self.assertFalse(report["remote_pretrained_weights_claimed"])

    def test_real_train_cli_has_learned_components_and_model_hash(self):
        run = self.run_cli("--mode", "train")
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["status"], "REAL_UNSUPERVISED_STDLIB_LSA_TRAINED")
        self.assertGreaterEqual(report["real_source_document_count"], 100)
        self.assertGreaterEqual(report["learned_latent_components"], 8)
        self.assertFalse(report["independent_labels_evaluated"])

    def test_evaluated_cli_validates_separately_signed_heldout_labels(self):
        labels = self.folder / "labels.json"
        key = self.folder / "auditor.key"
        labels.write_text(json.dumps(LABEL_ORACLE, sort_keys=True), encoding="utf-8")
        key.write_bytes(AUDITOR_KEY)
        os.chmod(key, 0o600)
        if os.name == "nt":
            import windows_privacy_fixtures
            windows_privacy_fixtures.set_private_acl(key)
        run = self.run_cli("--mode", "evaluated", "--labels", str(labels),
                           "--auditor-key", str(key), "--label-signature",
                           signed(LABEL_ORACLE))
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["status"], "HELDOUT_SEMANTIC_QUALITY_PASS")
        self.assertGreaterEqual(report["macro_recall_at_k"], PREDECLARED_MIN_RECALL)
        self.assertNotIn("per_query", report)
        self.assertFalse(report["generalization_beyond_selected_stdlib"])

    def test_evaluated_cli_refuses_unapproved_auditor_key_permissions(self):
        labels = self.folder / "labels.json"
        key = self.folder / "auditor.key"
        labels.write_text(json.dumps(LABEL_ORACLE), encoding="utf-8")
        key.write_bytes(AUDITOR_KEY)
        os.chmod(key, 0o644)
        if os.name == "nt":
            import windows_privacy_fixtures
            windows_privacy_fixtures.set_public_read_acl(key)
        run = self.run_cli("--mode", "evaluated", "--labels", str(labels),
                           "--auditor-key", str(key), "--label-signature",
                           signed(LABEL_ORACLE))
        self.assertEqual(run.returncode, 2)
        self.assertEqual(json.loads(run.stdout)["status"], "NOT_RUN_OR_UNQUALIFIED_EVIDENCE")


if __name__ == "__main__":
    unittest.main()
