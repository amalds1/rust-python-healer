"""Real trained competing-model inference, independent oracle and feedback."""

import hashlib
from contextlib import closing
import hmac
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
import real_model_router_v23 as router  # noqa: E402


# Predeclared independent, held-out stdlib API labels, never fed to either
# training routine. Query wording differs from stdlib API symbol names.
REAL_HELDOUT_LABELS = {
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
ORACLE = {"schema": 1, "annotation_source": "independent-frozen-human-labeled-api-query-set-v23",
          "labels": REAL_HELDOUT_LABELS}
KEY = b"separate-real-two-model-frozen-auditor-key-v23"
SIGNATURE = hmac.new(KEY, router._json_bytes(ORACLE), hashlib.sha256).hexdigest()
CLI = ROOT / "python" / "real_model_router_v23.py"


class ActuallyTrainedRouterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = router.stdlib_corpus()
        cls.models = router.train_pair(cls.corpus)
        cls.calibration = router.calibrate_router(cls.models, ORACLE, SIGNATURE, KEY)

    def test_distinct_actual_trained_model_families_and_inference(self):
        a, b = self.models.values()
        self.assertNotEqual(a["model_sha256"], b["model_sha256"])
        self.assertNotEqual(a["model_family"], b["model_family"])
        self.assertEqual(a["corpus_sha256"], b["corpus_sha256"])
        self.assertGreaterEqual(a["components"], 8)
        self.assertTrue(b["trained_parameters_from_real_docs"])
        self.assertGreaterEqual(b["training_documents"], 100)
        self.assertGreaterEqual(b["vocabulary_size"], 100)
        self.assertFalse(b["relevance_labels_consumed_during_training"])

    def test_nb_inference_uses_learned_log_probabilities(self):
        result = router.nb_search(self.models["multinomial_naive_bayes"],
                                  "greatest common divisor")
        self.assertEqual(result["status"], "REAL_TRAINED_NB_DOCUMENT_INFERENCE")
        self.assertEqual(result["results"][0]["doc_id"], "math.gcd")
        self.assertTrue(result["real_nb_inference_executed"])
        self.assertLess(result["results"][0]["score"], 0)

    def test_both_model_families_pass_independent_quality_gate(self):
        self.assertEqual(self.calibration["status"],
                         "DUAL_MODEL_REAL_INFERENCE_CALIBRATION")
        self.assertEqual(self.calibration["evaluated_real_stdlib_queries"], 14)
        for name, result in self.calibration["model_reports"].items():
            self.assertEqual(result["model_family"], name)
            self.assertEqual(result["independent_queries_evaluated"], 14)
            self.assertTrue(result["eligible"], name)
            self.assertGreaterEqual(result["recall_at_5"], router.MIN_QUALITY_RECALL)
            self.assertGreaterEqual(result["mrr"], router.MIN_QUALITY_MRR)
            self.assertGreater(result["inference_p50_us"], 0)
            self.assertGreaterEqual(result["inference_p95_us"],
                                    result["inference_p50_us"])
            self.assertGreaterEqual(result["inference_max_us"],
                                    result["inference_p95_us"])
            self.assertGreater(result["inference_cpu_p95_us"], 0)
            self.assertGreater(result["inference_cpu_total_us"], 0)
            self.assertEqual(result["compute_cost_unit"],
                             "actual_process_CPU_microseconds_not_money")

    def test_actual_router_predicts_relevant_api_without_source_execution(self):
        result = router.route_query(self.models, self.calibration,
                                    "greatest common divisor", auditor_key=KEY)
        self.assertEqual(result["status"], "REAL_MEASURED_DUAL_MODEL_ROUTED")
        self.assertIn(result["selected_model"], router.MODEL_FAMILIES)
        self.assertEqual(result["results"][0]["doc_id"], "math.gcd")
        self.assertGreater(result["actual_execution_us"], 0)
        self.assertGreater(result["actual_execution_cpu_compute_us"], 0)
        self.assertEqual(result["applicability_domain"], "stdlib_api_documentation")
        self.assertTrue(result["applicability_verified_on_independent_signed_query"])
        self.assertFalse(result["source_code_executed"])
        self.assertFalse(result["remote_llm_inference_executed"])
        self.assertFalse(result["online_policy_feedback_learning"])

    def test_wrong_signed_oracle_must_fail_quality_gate(self):
        modified = {"schema": 1, "annotation_source": ORACLE["annotation_source"],
                    "labels": {q: ["itertools.chain"] for q in REAL_HELDOUT_LABELS}}
        signature = hmac.new(KEY, router._json_bytes(modified),
                             hashlib.sha256).hexdigest()
        report = router.calibrate_router(self.models, modified, signature, KEY)
        self.assertTrue(all(not item["eligible"]
                            for item in report["model_reports"].values()))
        result = router.route_query(self.models, report,
                                    "greatest common divisor", auditor_key=KEY)
        self.assertEqual(result["status"], "NO_QUALIFIED_MODEL_FOR_POLICY")

    def test_heldout_tamper_without_hmac_is_rejected(self):
        changed = dict(ORACLE)
        changed["labels"] = dict(ORACLE["labels"])
        changed["labels"]["greatest common divisor"] = ["json.loads"]
        with self.assertRaisesRegex(ValueError, "independent_signed_oracle_required"):
            router.calibrate_router(self.models, changed, SIGNATURE, KEY)

    def test_strict_latency_budget_fails_closed(self):
        result = router.route_query(self.models, self.calibration,
                                    "greatest common divisor", max_p95_us=.0001,
                                    auditor_key=KEY)
        self.assertEqual(result["status"], "NO_QUALIFIED_MODEL_FOR_POLICY")

    def test_strict_measured_cpu_cost_budget_fails_closed(self):
        result = router.route_query(self.models, self.calibration,
                                    "greatest common divisor", max_p95_cpu_us=.0001,
                                    auditor_key=KEY)
        self.assertEqual(result["status"], "NO_QUALIFIED_MODEL_FOR_POLICY")

    def test_disallowed_general_bug_repair_task_fails_closed(self):
        result = router.route_query(self.models, self.calibration,
                                    "greatest common divisor", auditor_key=KEY,
                                    task_domain="untrusted_python_program_auto_repair")
        self.assertEqual(result["status"], "UNSUPPORTED_TASK_DOMAIN_FAIL_CLOSED")
        self.assertFalse(result["source_code_executed"])

    def test_unaudited_python_doc_task_fails_closed_as_not_qualified(self):
        result = router.route_query(self.models, self.calibration,
                                    "find a function to parse yaml", auditor_key=KEY)
        self.assertEqual(result["status"],
                         "UNSUPPORTED_QUERY_OUTSIDE_AUDITED_APPLICABILITY")

    def test_strict_quality_budget_fails_closed(self):
        result = router.route_query(self.models, self.calibration,
                                    "greatest common divisor", min_recall=.99,
                                    auditor_key=KEY)
        self.assertEqual(result["status"], "NO_QUALIFIED_MODEL_FOR_POLICY")

    def test_calibration_quality_and_latency_tamper_rejected(self):
        altered = dict(self.calibration)
        altered["model_reports"] = dict(self.calibration["model_reports"])
        altered["model_reports"]["tfidf_svd_lsa"] = dict(
            altered["model_reports"]["tfidf_svd_lsa"])
        altered["model_reports"]["tfidf_svd_lsa"]["recall_at_5"] = 1.0
        with self.assertRaisesRegex(ValueError, "measured_calibration_tampered"):
            router.route_query(self.models, altered,
                               "greatest common divisor", auditor_key=KEY)

    def test_calibration_rejects_wrong_auditor_key(self):
        with self.assertRaisesRegex(ValueError, "measured_calibration_tampered"):
            router.route_query(self.models, self.calibration,
                               "greatest common divisor", auditor_key=b"x"*32)

    def test_source_docstring_tamper_rejected_for_nb(self):
        changed = dict(self.corpus)
        changed["sources"] = dict(self.corpus["sources"])
        changed["sources"]["math.gcd"] = "changed untrusted text"
        with self.assertRaisesRegex(ValueError, "document_digest_mismatch"):
            router.train_nb_documents(changed)

    def test_out_of_vocabulary_query_fails_closed_in_both(self):
        for family in router.MODEL_FAMILIES:
            result = router._infer(family, self.models[family],
                                   "zzxqqyzv marsunknownword")
            self.assertEqual(result["status"], "NO_EVIDENCE_UNKNOWN_QUERY_TERMS")
        route = router.route_query(self.models, self.calibration,
                                   "zzxqqyzv marsunknownword", auditor_key=KEY)
        self.assertEqual(route["status"],
                         "UNSUPPORTED_QUERY_OUTSIDE_AUDITED_APPLICABILITY")

    def test_real_feedback_is_hmac_verified_and_responds_to_observed_reward(self):
        with tempfile.TemporaryDirectory(prefix="rph-actual-feedback-v23-") as base:
            database = Path(base) / "signed-feedback.sqlite3"
            query = "arithmetic average of numeric data"
            result = router.append_measured_feedback(database, self.models,
                                                     self.calibration, query, KEY)
            self.assertEqual(result["records"], 2)
            self.assertFalse(result["user_opinion_fabricated"])
            stats = router.verified_feedback(database, KEY)
            self.assertEqual(stats["verified_record_count"], 2)
            reroute = router.route_query(self.models, self.calibration, query,
                                         auditor_key=KEY, feedback_db=database)
            # This exact query is independently wrong for LSA but right for NB.
            # Signed real-run policy feedback *changes* the default LSA choice.
            self.assertEqual(reroute["selected_model"], "multinomial_naive_bayes")
            self.assertTrue(reroute["online_policy_feedback_learning"])
            self.assertEqual(reroute["actual_signed_feedback_records_used"], 2)
            self.assertIn("statistics.mean",
                          [entry["doc_id"] for entry in reroute["results"]])

    def test_measured_sqlite_feedback_tamper_blocks_reuse_and_reappend(self):
        with tempfile.TemporaryDirectory(prefix="rph-feedback-tamper-") as base:
            database = Path(base) / "feedback.sqlite"
            query = "greatest common divisor"
            router.append_measured_feedback(database, self.models,
                                            self.calibration, query, KEY)
            with closing(sqlite3.connect(str(database))) as conn, conn:
                conn.execute("UPDATE measured_routes SET hit=0 WHERE model_family=?",
                             ("tfidf_svd_lsa",))
            with self.assertRaisesRegex(ValueError, "measured_feedback_integrity_failure"):
                router.verified_feedback(database, KEY)
            with self.assertRaisesRegex(ValueError, "measured_feedback_integrity_failure"):
                router.append_measured_feedback(database, self.models,
                                                self.calibration, query, KEY)

    def test_unsigned_nonoracle_feedback_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="rph-feedback-unknown-") as base:
            with self.assertRaisesRegex(ValueError, "no_independent_ground_truth"):
                router.append_measured_feedback(Path(base)/"feedback.db", self.models,
                                                self.calibration, "unknown task text", KEY)

    def test_symlink_feedback_path_is_not_followed(self):
        with tempfile.TemporaryDirectory(prefix="rph-feedback-link-") as base:
            target = Path(base)/"target.db"
            target.write_text("do not overwrite", encoding="utf-8")
            symlink = Path(base)/"link.db"
            symlink.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "unsafe_feedback_database_path"):
                router.append_measured_feedback(symlink, self.models,
                                                self.calibration, "greatest common divisor", KEY)
            self.assertEqual(target.read_text(encoding="utf-8"), "do not overwrite")

    def test_independent_judgments_did_not_enter_model_training(self):
        self.assertFalse(self.calibration["independent_labels_train_consumed"])
        self.assertFalse(self.calibration["general_python_bug_autofix_quality_attested"])
        self.assertFalse(self.calibration["remote_llm_inference_attested"])
        for query in REAL_HELDOUT_LABELS:
            self.assertNotIn(query, json.dumps({"model_sha256": self.models[
                "multinomial_naive_bayes"]["model_sha256"]}))


class TwoModelRouterCliTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="rph-dual-cli-")
        self.addCleanup(self.folder.cleanup)
        base = Path(self.folder.name)
        self.labels = base/"labels.json"
        self.key = base/"key.private"
        self.labels.write_text(json.dumps(ORACLE, sort_keys=True), encoding="utf-8")
        self.key.write_bytes(KEY)
        os.chmod(self.key, 0o600)
        if os.name == "nt":
            import windows_privacy_fixtures
            windows_privacy_fixtures.set_private_acl(self.key)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-I", "-S", "-B", str(CLI)] + list(args),
                              capture_output=True, text=True, check=False, timeout=30)

    def test_default_safe_capabilities_no_training_or_network(self):
        run = self.run_cli()
        self.assertEqual(run.returncode, 0, run.stderr)
        result = json.loads(run.stdout)
        self.assertEqual(result["status"],
                         "TWO_GENUINELY_TRAINABLE_LOCAL_MODELS_NOT_YET_RUN")
        self.assertFalse(result["trained_model_inference_executed"])
        self.assertFalse(result["external_network_called"])
        self.assertEqual(len(result["model_families"]), 2)

    def test_explicit_evaluated_cli_uses_two_actual_models(self):
        run = self.run_cli("--mode", "evaluate", "--labels", str(self.labels),
                           "--auditor-key", str(self.key),
                           "--label-signature", SIGNATURE,
                           "--query", "greatest common divisor")
        self.assertEqual(run.returncode, 0, run.stderr)
        result = json.loads(run.stdout)
        self.assertEqual(result["status"], "REAL_MEASURED_DUAL_MODEL_ROUTED")
        self.assertTrue(result["actual_two_trained_models"])
        self.assertTrue(result["signed_independent_labels_used"])
        self.assertTrue(all(row["eligible"] for row in result["calibration"].values()))
        self.assertTrue(all(row["inference_p95_us"] > 0
                            for row in result["calibration"].values()))
        self.assertTrue(all(row["inference_cpu_p95_us"] > 0
                            for row in result["calibration"].values()))
        self.assertNotIn("per_query", json.dumps(result))

    def test_cli_refuses_world_readable_private_key(self):
        os.chmod(self.key, 0o644)
        if os.name == "nt":
            import windows_privacy_fixtures
            windows_privacy_fixtures.set_public_read_acl(self.key)
        run = self.run_cli("--mode", "evaluate", "--labels", str(self.labels),
                           "--auditor-key", str(self.key),
                           "--label-signature", SIGNATURE)
        self.assertEqual(run.returncode, 2)
        self.assertEqual(json.loads(run.stdout)["status"],
                         "NOT_RUN_OR_UNQUALIFIED_DUAL_MODEL_EVIDENCE")

    def test_cli_refuses_unsigned_evaluation(self):
        run = self.run_cli("--mode", "evaluate")
        self.assertEqual(run.returncode, 2)
        self.assertEqual(json.loads(run.stdout)["status"],
                         "NOT_RUN_OR_UNQUALIFIED_DUAL_MODEL_EVIDENCE")


if __name__ == "__main__":
    unittest.main()
