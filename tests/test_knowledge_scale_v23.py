"""Measured native/FTS/semantic/DuckDB evidence without invented scale."""

from contextlib import closing
import hashlib
import hmac
from importlib.util import module_from_spec, spec_from_file_location
import inspect
import json
import math
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
DUCKDB_DIRS = {
    "3.9": "duckdb-test39-v23", "3.10": "duckdb-test310-v23",
    "3.11": "duckdb-test11-v23", "3.12": "duckdb-test312-v23",
    "3.13": "duckdb-test13-v23", "3.14": "duckdb-test14-v23",
    "3.15": "duckdb-test15-v23",
}
MINOR = "{}.{}".format(*sys.version_info[:2])
DUCKDB_PATH = WORKSPACE / DUCKDB_DIRS[MINOR]
if os.name == "nt":
    _wheel_target = {"3.9":"duckdb-1.4.4-cp39-cp39", "3.10":"duckdb-1.4.4-cp310-cp310",
                     "3.11":"duckdb-2.0.0-cp311-cp311"}.get(MINOR,"duckdb-2.0.0-cp312-abi3")
    DUCKDB_PATH = ROOT / ".v23-model-tools" / _wheel_target
if DUCKDB_PATH.is_dir():
    sys.path.insert(0, str(DUCKDB_PATH))
memory_spec = spec_from_file_location("knowledge_test_process_memory", ROOT / "python/process_memory.py")
memory = module_from_spec(memory_spec)
memory_spec.loader.exec_module(memory)
SCRIPT = ROOT / "python" / "knowledge_scale_v23.py"
spec = spec_from_file_location("knowledge_scale_v23", SCRIPT)
module = module_from_spec(spec)
spec.loader.exec_module(module)


def sha(raw):
    if type(raw) is str:
        raw = raw.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def pinned(examples):
    return sha(json.dumps(examples, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False))


def signed(data, key):
    return hmac.new(key, module._json_bytes(data), hashlib.sha256).hexdigest()


class SyntaxSchemaV23Tests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(self.conn.close)
        self.samples = module.SYNTAX_SAMPLES

    def test_real_compilation_yields_actual_version_correct_capabilities(self):
        result = module.migrate_syntax_schema(self.conn, self.samples, pinned(self.samples))
        self.assertEqual(result["status"], "LOCAL_SYNTAX_AWARE_SCHEMA_MIGRATED")
        self.assertEqual(len(result["new_schema_columns"]), len(self.samples))
        self.assertFalse(result["unknown_python_source_executed"])
        for name, source in self.samples.items():
            try:
                compile(source, "<independent-oracle>", "exec", dont_inherit=True)
            except SyntaxError:
                verdict = 0
            else:
                verdict = 1
            self.assertEqual(result["syntax_compile_verdicts"][name], verdict)
            column = "syntax_" + name
            stored = self.conn.execute('SELECT "{}" FROM v23_syntax_capabilities'.format(
                column)).fetchone()[0]
            self.assertEqual(stored, verdict)

    def test_true_ddl_migration_adds_new_versioned_syntax_column(self):
        first = {"feature_one": "x=1\n"}
        module.migrate_syntax_schema(self.conn, first, pinned(first))
        second = dict(first, feature_two="def f():\n return 1\n")
        report = module.migrate_syntax_schema(self.conn, second, pinned(second))
        self.assertEqual(report["new_schema_columns"], ["feature_two"])
        columns = [r[1] for r in self.conn.execute("PRAGMA table_info(v23_syntax_capabilities)")]
        self.assertIn("syntax_feature_two", columns)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM v23_syntax_events").fetchone()[0], 2)

    def test_repeating_manifest_is_idempotent_and_reruns_real_compile(self):
        module.migrate_syntax_schema(self.conn, self.samples, pinned(self.samples))
        new = module.migrate_syntax_schema(self.conn, self.samples, pinned(self.samples))
        self.assertEqual(new["new_schema_columns"], [])
        self.assertEqual(self.conn.execute("SELECT count(*) FROM v23_syntax_meta").fetchone()[0],
                         len(self.samples))

    def test_changed_feature_identity_fails_closed_with_no_new_columns(self):
        first = {"stable_name": "pass\n"}
        module.migrate_syntax_schema(self.conn, first, pinned(first))
        tampered = dict(first, stable_name="break\n", later_new="pass\n")
        with self.assertRaisesRegex(ValueError, "syntax_feature_identity_changed"):
            module.migrate_syntax_schema(self.conn, tampered, pinned(tampered))
        self.assertEqual([r[0] for r in self.conn.execute(
            "SELECT feature_name FROM v23_syntax_meta")], ["stable_name"])

    def test_injected_failure_rolls_back_actual_alter_table(self):
        with self.assertRaisesRegex(ValueError, "injected_transaction_rollback"):
            module.migrate_syntax_schema(self.conn, self.samples, pinned(self.samples),
                                         inject_failure=True)
        found = self.conn.execute("SELECT name FROM sqlite_master "
                                  "WHERE name='v23_syntax_capabilities'").fetchone()
        self.assertIsNone(found)

    def test_manifest_digest_pin_wrong_rejected_pretransaction(self):
        with self.assertRaisesRegex(ValueError, "syntax_manifest_digest_pin_mismatch"):
            module.migrate_syntax_schema(self.conn, self.samples, "f" * 64)
        self.assertFalse(self.conn.execute("SELECT name FROM sqlite_master "
                                           "WHERE name='v23_syntax_meta'").fetchall())

    def test_malicious_ddl_feature_name_rejected_before_any_mutation(self):
        bad = {"x\";DROP TABLE documents;--": "pass\n"}
        with self.assertRaisesRegex(ValueError, "invalid_syntax_feature"):
            module.migrate_syntax_schema(self.conn, bad, pinned(bad))
        self.assertFalse(self.conn.execute("SELECT name FROM sqlite_master").fetchall())

    def test_feature_count_quota_cannot_be_exceeded(self):
        too_many = {"feature_{}".format(i): "pass\n" for i in range(33)}
        with self.assertRaisesRegex(ValueError, "invalid_versioned_syntax_manifest"):
            module.migrate_syntax_schema(self.conn, too_many, pinned(too_many))

    def test_new_future_syntax_can_extend_schema_without_executing_payload(self):
        new_sample = {"future_syntax_x": "open('/tmp/THIS_DOES_NOT_EXIST','w').write('bad')\n"}
        result = module.migrate_syntax_schema(self.conn, new_sample, pinned(new_sample))
        self.assertFalse(result["unknown_python_source_executed"])
        self.assertFalse(Path("/tmp/THIS_DOES_NOT_EXIST").exists())
        self.assertEqual(result["syntax_compile_verdicts"]["future_syntax_x"], 1)


class NativeApiV23Tests(unittest.TestCase):
    def test_real_native_cpython_exports_and_signatures_measured(self):
        data = module.native_api_inventory()
        self.assertEqual(data["status"], "REAL_SELECTED_NATIVE_STDLIB_INTROSPECTION_PARTIAL")
        self.assertGreaterEqual(data["native_symbols_observed"], 150)
        self.assertGreaterEqual(data["native_symbols_with_signature"], 100)
        self.assertEqual(len(data["native_symbols"]), data["native_symbols_observed"])
        self.assertFalse(data["full_stdlib_complete"])
        self.assertFalse(data["dynamic_or_untrusted_code_imported"])

    def test_signatures_are_actual_runtime_data_not_static_magic(self):
        import math as trusted_math
        report = module.native_api_inventory()
        self.assertIn("math.sqrt", {row["symbol"] for row in report["native_symbols"]})
        measured = next(row["signature"] for row in report["native_symbols"]
                        if row["symbol"] == "math.sqrt")
        self.assertEqual(measured, str(inspect.signature(trusted_math.sqrt)))

    def test_canonical_sha_and_exact_running_version_reproducible(self):
        first = module.native_api_inventory()
        second = module.native_api_inventory()
        self.assertEqual(first["native_inventory_sha256"], second["native_inventory_sha256"])
        self.assertEqual(first["python_micro"], "{}.{}.{}".format(*sys.version_info[:3]))
        self.assertEqual(first["native_inventory_sha256"], sha(module._json_bytes(
            first["native_symbols"])))

    def test_native_inventory_does_not_claim_uninspected_full_stdlib(self):
        report = module.native_api_inventory()
        self.assertEqual(set(report["selected_modules"]), set(module.NATIVE_ALLOWLIST))
        self.assertFalse(report["full_stdlib_complete"])
        self.assertGreaterEqual(report["native_symbols_without_signature"], 0)


class SemanticQualityV23Tests(unittest.TestCase):
    def setUp(self):
        import math
        import itertools
        import builtins
        self.docs = {"gcd": inspect.getdoc(math.gcd),
                     "isqrt": inspect.getdoc(math.isqrt),
                     "chain": inspect.getdoc(itertools.chain),
                     "sum": inspect.getdoc(builtins.sum)}
        if any(not self.docs[key] for key in self.docs):
            self.skipTest("real CPython documentation unavailable")
        self.embedding = {
            "documents": {"gcd": [1, 0, 0, 0], "isqrt": [0, 1, 0, 0],
                          "chain": [0, 0, 1, 0], "sum": [0, 0, 0, 1]},
            "queries": {"common_divisor": [1, 0, 0, 0],
                        "integer_root": [0, 1, 0, 0],
                        "concatenate_iterables": [0, 0, 1, 0],
                        "add_numbers": [0, 0, 0, 1]},
            "model": "external-model-fixed-local-vector-test-not-learned",
            "dimension": 4,
            "document_source_sha256": {key: sha(doc) for key, doc in self.docs.items()},
        }
        self.labels = {"judgments": {"common_divisor": ["gcd"],
                                     "integer_root": ["isqrt"],
                                     "concatenate_iterables": ["chain"],
                                     "add_numbers": ["sum"]},
                       "source": "independent-curated-labels-real-native-docstrings",
                       "annotation_version": "v23-fixture-1"}
        self.producer_key = b"trusted-fixture-model-signing-key-1111"
        self.auditor_key = b"independent-fixture-label-signing-key-2"

    def judge(self, **kwargs):
        return module.evaluate_labeled_vectors(
            self.embedding, self.labels, signed(self.embedding, self.producer_key),
            signed(self.labels, self.auditor_key), self.producer_key,
            self.auditor_key, **kwargs)

    def test_real_cosine_ranking_against_independent_labeled_stdlib_docs(self):
        result = self.judge(top_k=1)
        self.assertEqual(result["status"], "LOCAL_SIGNED_RELEVANCE_GATE_PASS")
        self.assertEqual(result["macro_recall_at_k"], 1)
        self.assertEqual(result["macro_mrr"], 1)
        self.assertEqual(result["macro_ndcg_at_k"], 1)
        self.assertEqual(result["genuine_source_digest_count"], 4)
        self.assertFalse(result["model_semantic_generalization_proven"])

    def test_deliberately_wrong_embedding_rank_causes_real_quality_fail(self):
        self.embedding["queries"]["integer_root"] = [1, 0, 0, 0]
        result = self.judge(top_k=1, min_recall=0.95)
        self.assertEqual(result["status"], "LOCAL_SIGNED_RELEVANCE_GATE_FAIL")
        self.assertLess(result["macro_recall_at_k"], 0.95)

    def test_wrong_signature_tampered_doc_embeddings_rejected(self):
        original_sig = signed(self.embedding, self.producer_key)
        self.embedding["queries"]["integer_root"] = [1, 0, 0, 0]
        with self.assertRaisesRegex(ValueError, "quality_dataset_signature_mismatch"):
            module.evaluate_labeled_vectors(self.embedding, self.labels,
                                            original_sig, signed(self.labels, self.auditor_key),
                                            self.producer_key, self.auditor_key)

    def test_auditor_and_producer_keys_must_be_distinct(self):
        with self.assertRaisesRegex(ValueError, "auditor_key_must_differ"):
            module.evaluate_labeled_vectors(self.embedding, self.labels,
                                            signed(self.embedding, self.producer_key),
                                            signed(self.labels, self.producer_key),
                                            self.producer_key, self.producer_key)

    def test_invalid_label_ids_and_duplicate_relevance_rejected(self):
        self.labels["judgments"]["integer_root"] = ["isqrt", "isqrt"]
        with self.assertRaisesRegex(ValueError, "invalid_independent_relevance_labels"):
            self.judge()

    def test_nonfinite_or_zero_embeddings_are_never_ranked(self):
        self.embedding["queries"]["common_divisor"] = [math.nan, 0, 0, 0]
        with self.assertRaisesRegex(ValueError, "nonfinite_embedding_component"):
            self.judge()
        self.embedding["queries"]["common_divisor"] = [0, 0, 0, 0]
        with self.assertRaisesRegex(ValueError, "invalid_embedding_norm"):
            self.judge()

    def test_missing_source_sha256_binding_refuses_quality_claim(self):
        del self.embedding["document_source_sha256"]["gcd"]
        with self.assertRaisesRegex(ValueError, "source_provenance_sha256_required"):
            self.judge()

    def test_heuristic_fixture_model_not_misrepresented_as_general_semantics(self):
        result = self.judge(top_k=1)
        self.assertFalse(result["externally_independent_labels_attested"])
        self.assertFalse(result["model_semantic_generalization_proven"])


class DuckDbV23Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rph-duckdb-v23-")
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "historical.duckdb"
        self.engine = module.real_duckdb_module()
        if self.engine is None:
            self.skipTest("NOT_RUN_NATIVE_DUCKDB_UNAVAILABLE")

    def measured_events(self):
        events = []
        for index in range(20):
            start = time.perf_counter_ns()
            compile("value=42\n", "<trusted-measured-fixture>", "exec")
            duration = max(0.000001, (time.perf_counter_ns()-start) / 1e6)
            events.append({"run_id": "run_{}".format(index),
                           "python_minor": MINOR,
                           "candidate_id": "candidate_fast" if index % 2 else "candidate_slow",
                           "duration_ms": duration,
                           "rss_kib": int(memory.peak_rss_kib()),
                           "status": "FAIL" if index % 5 == 0 else "PASS",
                           "sha256": sha(b"value=42\n")})
        return events

    def test_actual_duckdb_engine_not_a_sqlite_substitute(self):
        self.assertTrue(module.real_duckdb_module())
        connection = self.engine.connect(":memory:")
        try:
            self.assertEqual(connection.execute("SELECT 42").fetchone()[0], 42)
        finally:
            connection.close()

    def test_actual_persisted_duckdb_p95_history_metrics(self):
        events = self.measured_events()
        result = module.analytical_duckdb_history(self.db, events, pinned(events))
        self.assertEqual(result["status"], "REAL_NATIVE_DUCKDB_ANALYTICS_MEASURED")
        self.assertTrue(result["actual_duckdb_sql_executed"])
        self.assertEqual(result["historical_rows"], 20)
        self.assertEqual(result["historical_groups"], 2)
        self.assertEqual(result["independent_query_rounds"], 5)
        self.assertTrue(self.db.is_file())
        self.assertEqual(sum(r["runs"] for r in result["aggregate_rows"]), 20)

    def test_query_group_counts_verified_by_independent_python_oracle(self):
        events = self.measured_events()
        result = module.analytical_duckdb_history(self.db, events, pinned(events))
        for group in result["aggregate_rows"]:
            reference = [e for e in events if e["python_minor"] == group["python_minor"]
                         and e["candidate_id"] == group["candidate_id"]]
            self.assertEqual(group["runs"], len(reference))
            self.assertEqual(group["passed"], sum(e["status"] == "PASS"
                                                  for e in reference))
            self.assertEqual(group["rss_peak_kib"], max(e["rss_kib"] for e in reference))

    def test_wrong_manifest_sha_blocks_disk_modification(self):
        events = self.measured_events()
        with self.assertRaisesRegex(ValueError, "historical_events_sha256_pin_failed"):
            module.analytical_duckdb_history(self.db, events, "f" * 64)
        self.assertFalse(self.db.exists())

    def test_duplicate_or_unsafe_candidate_rejected(self):
        events = self.measured_events()
        events[1]["run_id"] = events[0]["run_id"]
        with self.assertRaisesRegex(ValueError, "invalid_historical_event_value"):
            module.analytical_duckdb_history(self.db, events, pinned(events))
        self.assertFalse(self.db.exists())

    def test_replay_into_same_historical_db_fails_without_partial_second_insert(self):
        events = self.measured_events()
        module.analytical_duckdb_history(self.db, events, pinned(events))
        with self.assertRaises(Exception):
            module.analytical_duckdb_history(self.db, events, pinned(events))
        with closing(self.engine.connect(str(self.db))) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM experimental_runs")
                             .fetchone()[0], 20)

    def test_real_query_timings_are_measured_each_round(self):
        events = self.measured_events()
        report = module.analytical_duckdb_history(self.db, events, pinned(events),
                                                  repeat_queries=7)
        self.assertEqual(len(report["query_timings_ms"]), 7)
        self.assertTrue(all(value > 0 for value in report["query_timings_ms"]))
        self.assertGreater(report["p95_query_ms"], 0)


class MillionCorpusIntegrityV23Tests(unittest.TestCase):
    def sample(self):
        import math
        doc = inspect.getdoc(math.sqrt)
        return {"source_uri": "cpython://stdlib/math.sqrt",
                "source_sha256": sha(doc), "document_id": "docstring-1",
                "content": doc}

    def test_missing_one_million_real_chunks_never_get_false_pass(self):
        report = module.million_corpus_preflight([self.sample()])
        self.assertEqual(report["status"],
                         "NOT_RUN_INSUFFICIENT_REPRESENTATIVE_REAL_DOC_CHUNKS")
        self.assertEqual(report["distinct_provenance_chunks"], 1)
        self.assertFalse(report["million_document_fts_measurement_executed"])

    def test_duplicate_real_chunks_do_not_pad_document_count(self):
        doc = self.sample()
        report = module.million_corpus_preflight([doc, doc, doc])
        self.assertEqual(report["raw_chunks"], 3)
        self.assertEqual(report["duplicate_chunks"], 2)
        self.assertEqual(report["distinct_provenance_chunks"], 1)

    def test_million_threshold_cannot_be_downgraded(self):
        with self.assertRaisesRegex(ValueError, "million_corpus_threshold_may_not_be_lowered"):
            module.million_corpus_preflight([self.sample()], minimum_unique=10)

    def test_forged_missing_source_provenance_refused(self):
        doc = self.sample()
        doc["source_sha256"] = "bad"
        with self.assertRaisesRegex(ValueError, "invalid_real_corpus_provenance"):
            module.million_corpus_preflight([doc])


class KnowledgeScaleCliV23Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rph-knowledge-cli-v23-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def command(self, *argv):
        return subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)] + list(argv),
                              capture_output=True, text=True, check=False, timeout=8)

    def test_default_json_capabilities_never_require_external_duckdb(self):
        result = self.command()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "KNOWLEDGE_SCALE_BOUNDED_CAPABILITIES_ONLY")
        self.assertFalse(report["unknown_code_executed"])
        self.assertFalse(report["million_document_benchmark_proven"])

    def test_cli_actual_native_exports_bounded_json_summary(self):
        result = self.command("--mode", "native")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertGreaterEqual(report["native_symbols_observed"], 150)
        self.assertNotIn("native_symbols", report)
        self.assertFalse(report["full_stdlib_complete"])

    def test_cli_exact_pinned_manifest_creates_schema_column(self):
        manifest = {"selective_feature": "x=3\n"}
        source = self.folder / "manifest.json"
        source.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        db = self.folder / "syntax.db"
        result = self.command("--mode", "syntax-migrate", "--db", str(db),
                              "--manifest", str(source), "--sha256", pinned(manifest))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["new_schema_columns"], ["selective_feature"])
        with closing(sqlite3.connect(str(db))) as conn:
            actual = [row[1] for row in conn.execute(
                "PRAGMA table_info(v23_syntax_capabilities)")]
        self.assertIn("syntax_selective_feature", actual)

    def test_cli_refuses_symlink_manifest_and_wrong_pin(self):
        manifest = {"selective_feature": "pass\n"}
        source = self.folder / "manifest.json"
        source.write_text(json.dumps(manifest), encoding="utf-8")
        alias = self.folder / "manifest-link.json"
        alias.symlink_to(source)
        db = self.folder / "syntax.db"
        base = ("--mode", "syntax-migrate", "--db", str(db), "--manifest")
        via_link = self.command(*base, str(alias), "--sha256", pinned(manifest))
        self.assertNotEqual(via_link.returncode, 0)
        self.assertFalse(db.exists())
        bad_pin = self.command(*base, str(source), "--sha256", "f" * 64)
        self.assertNotEqual(bad_pin.returncode, 0)


if __name__ == "__main__":
    unittest.main()
