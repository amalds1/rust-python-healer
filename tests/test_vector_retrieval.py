"""Exact offline cosine + FTS5 retrieval safety/partition tests on 3.9–3.15."""

from contextlib import closing
from importlib.util import module_from_spec, spec_from_file_location
import hashlib
import json
import math
from pathlib import Path
import random
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("vector_retrieval", ROOT / "python" / "vector_retrieval.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)

URI = "https://docs.python.org/3/library/ast.html"
URI2 = "https://docs.python.org/3/library/contextlib.html"
SHA = hashlib.sha256(b"declared-reference-source-1").hexdigest()
SHA2 = hashlib.sha256(b"declared-reference-source-2").hexdigest()
V = [1.0, 0.0, 0.0, 0.0]


def oracle(query, vector):
    """Separate plainly written cosine reference implementation."""
    dot = sum(a * b for a, b in zip(query, vector))
    left = math.sqrt(sum(a * a for a in query))
    right = math.sqrt(sum(b * b for b in vector))
    return dot / (left * right)


class VectorRetrievalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.db = self.folder / "vector.sqlite"
        self.conn = module.database(self.db)
        self.addCleanup(self.conn.close)
        self.partition = module.register_partition(self.conn, "3.9", "numpy", "1.26",
                                                   4, "external-fixture-v1")["partition_id"]

    def put(self, name, vector=V, content="Python abstract syntax tree parser",
            minor="3.9", version="1.26", uri=URI, sha=SHA):
        return module.record_chunk(self.conn, minor, "numpy", version, name,
                                   content, uri, sha, vector)

    def vector_search(self, vector=V, minor="3.9", version="1.26", uri=URI, sha=SHA,
                      limit=10):
        return module.search_vector(self.conn, minor, "numpy", version, uri, sha,
                                    vector, limit)

    def hybrid(self, text="parser", vector=V, minor="3.9", version="1.26", uri=URI,
               sha=SHA, limit=10):
        return module.search_hybrid(self.conn, minor, "numpy", version, uri, sha,
                                    text, vector, limit)

    def test_real_exact_cosine_matches_separate_oracle_all_rankings(self):
        fixtures = {"unit": [1.0, 0.0, 0.0, 0.0],
                    "diagonal": [1.0, 1.0, 0.0, 0.0],
                    "perpendicular": [0.0, 1.0, 0.0, 0.0],
                    "reverse": [-1.0, 0.0, 0.0, 0.0],
                    "negative": [-1.0, -1.0, 0.0, 0.0]}
        for key, vector in fixtures.items():
            self.put(key, vector)
        report = self.vector_search()
        self.assertEqual(report["candidates_checked"], len(fixtures))
        expected = {key: oracle(V, vector) for key, vector in fixtures.items()}
        for item in report["matches"]:
            self.assertAlmostEqual(item["score"], expected[item["chunk_key"]], places=12)
        self.assertEqual([row["chunk_key"] for row in report["matches"]],
                         ["unit", "diagonal", "perpendicular", "negative", "reverse"])
        self.assertFalse(report["ann_used"])
        self.assertFalse(report["semantic_embedding_computed"])

    def test_many_random_fixed_vectors_compare_to_independent_oracle(self):
        rng = random.Random(991)
        expected = {}
        query = [0.3, -0.4, 0.7, 0.2]
        for item in range(50):
            name = "part{:03}".format(item)
            vector = [rng.uniform(-10, 10) for _ in range(4)]
            self.put(name, vector)
            expected[name] = oracle(query, vector)
        report = self.vector_search(query, limit=50)
        self.assertEqual(len(report["matches"]), 50)
        for row in report["matches"]:
            self.assertAlmostEqual(row["score"], expected[row["chunk_key"]], places=12)
        scores = [item["score"] for item in report["matches"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_partition_is_hard_bound_to_python_minor_and_package_version(self):
        self.put("old", V)
        modern = module.register_partition(self.conn, "3.15", "numpy", "2.8",
                                           4, "external-fixture-v1")["partition_id"]
        self.assertNotEqual(self.partition, modern)
        self.put("new", [-1, 0, 0, 0], minor="3.15", version="2.8")
        self.assertEqual([x["chunk_key"] for x in self.vector_search()["matches"]],
                         ["old"])
        self.assertEqual([x["chunk_key"] for x in self.vector_search(
            minor="3.15", version="2.8")["matches"]], ["new"])
        with self.assertRaisesRegex(ValueError, "unregistered_versioned_vector_partition"):
            self.vector_search(minor="3.12")

    def test_source_uri_and_digest_are_both_mandatory_hard_filters(self):
        self.put("primary")
        self.put("other_url", uri=URI2)
        self.put("other_hash", sha=SHA2)
        self.assertEqual([x["chunk_key"] for x in self.vector_search()["matches"]],
                         ["primary"])
        self.assertEqual([x["chunk_key"] for x in self.hybrid()["matches"]],
                         ["primary"])
        self.assertEqual(self.hybrid(uri=URI2)["matches"][0]["chunk_key"],
                         "other_url")
        self.assertEqual(self.vector_search(sha=SHA2)["matches"][0]["chunk_key"],
                         "other_hash")

    def test_sqlite_fts5_hybrid_includes_real_text_match_in_ranking(self):
        self.put("close_no_word", [1, 0, 0, 0], "Only binary feature calculation")
        self.put("sparse_match", [0, 1, 0, 0], "Parser visitor and syntax walker")
        report = self.hybrid("parser", V)
        self.assertEqual(report["fts_matched"], 1)
        self.assertEqual(report["matches"][0]["chunk_key"], "sparse_match")
        self.assertEqual(report["matches"][0]["fts_rank"], 1)
        self.assertEqual(report["matches"][1]["chunk_key"], "close_no_word")
        self.assertIsNone(report["matches"][1]["fts_rank"])
        self.assertEqual(report["reranker"], "reciprocal_rank_fusion_k60")
        self.assertFalse(report["source_authenticated"])

    def test_hybrid_cannot_match_other_versions_even_when_text_identical(self):
        self.put("first", V, "Module visitor parser")
        module.register_partition(self.conn, "3.15", "numpy", "2.8", 4,
                                  "external-fixture-v1")
        self.put("second", V, "Module visitor parser", minor="3.15", version="2.8")
        self.assertEqual(self.hybrid("parser")["fts_matched"], 1)
        self.assertEqual(self.hybrid("parser", minor="3.15", version="2.8")
                         ["matches"][0]["chunk_key"], "second")

    def test_atomic_public_insert_delete_keep_fts_and_vector_index_in_sync(self):
        self.put("first", content="unique_keyword running")
        self.put("second", content="unique_keyword testing")
        self.assertEqual(module.inspect(self.conn)["status"],
                         "STRUCTURALLY_SYNCED_NOT_SEMANTICALLY_VALIDATED")
        self.assertEqual(self.hybrid("unique_keyword")["fts_matched"], 2)
        result = module.remove_chunk(self.conn, "3.9", "numpy", "1.26", "first")
        self.assertEqual(result["status"], "REMOVED")
        self.assertEqual(self.hybrid("unique_keyword")["fts_matched"], 1)
        self.assertEqual(module.inspect(self.conn)["vector_entries"], 1)
        self.assertEqual(module.inspect(self.conn)["fts_rows"], 1)

    def test_duplicate_replays_idempotently_without_silent_reembedding(self):
        self.put("same")
        self.assertEqual(self.put("same")["status"],
                         "ALREADY_RECORDED_NO_REEMBEDDING")
        self.assertEqual(module.inspect(self.conn)["chunks"], 1)
        with self.assertRaisesRegex(ValueError, "conflicting_immutable_vector_chunk"):
            self.put("same", [-1, 0, 0, 0])
        self.assertEqual(self.vector_search()["matches"][0]["score"], 1)

    def test_partition_dimension_and_model_cannot_silently_change(self):
        self.assertEqual(module.register_partition(self.conn, "3.9", "numpy", "1.26",
                                                   4, "external-fixture-v1")
                         ["status"], "EXISTING_PARTITION")
        for args in ((8, "external-fixture-v1"), (4, "different-model-v3")):
            with self.assertRaisesRegex(ValueError, "immutable_vector_partition_conflict"):
                module.register_partition(self.conn, "3.9", "numpy", "1.26", *args)
        self.assertEqual(module.inspect(self.conn)["partitions"], 1)

    def test_reject_nan_inf_bool_zero_wrong_dimension_and_absurd_vector(self):
        for vector in ([0.0] * 4, [float("nan"), 0, 1, 0],
                       [float("inf"), 0, 0, 1], [True, 0, 0, 0], [1, 0],
                       [1_000_001, 0, 0, 0], "[1,0,0,0]"):
            with self.subTest(vector=vector):
                with self.assertRaises(ValueError):
                    self.put("invalid", vector)
        self.assertEqual(module.inspect(self.conn)["chunks"], 0)

    def test_source_link_validation_refuses_credentials_queries_traversal_http(self):
        urls = ("http://docs.python.org/path", "https://admin:secret@docs.python.org/a",
                "https://docs.python.org/path?token=secret",
                "https://docs.python.org/a/../private",
                "https://docs.python.org/a/%2e%2e/b",
                "https://docs.python.org/path#secret")
        for uri in urls:
            with self.subTest(uri=uri):
                with self.assertRaises(ValueError):
                    self.put("x", uri=uri)
        self.assertEqual(module.inspect(self.conn)["chunks"], 0)

    def test_sql_injection_and_fts_query_syntax_are_not_executed(self):
        with self.assertRaisesRegex(ValueError, "invalid_chunk_key"):
            self.put("x'); DROP TABLE chunks; --")
        self.put("normal")
        result = self.hybrid("'); DROP TABLE chunks; --")
        self.assertEqual(result["candidates_checked"], 1)
        self.assertEqual(module.inspect(self.conn)["chunks"], 1)
        with self.assertRaises(ValueError):
            self.hybrid("\x00script")

    def test_wrong_digest_and_invalid_source_version_query_rejected(self):
        self.put("normal")
        with self.assertRaises(ValueError):
            self.vector_search(sha="x" * 64)
        with self.assertRaises(ValueError):
            self.vector_search(minor="3.7")
        with self.assertRaises(ValueError):
            self.vector_search(version="../../..")

    def test_read_only_query_and_inspect_do_not_add_vector_fts_rows(self):
        self.put("a")
        before = module.inspect(self.conn)
        for _ in range(5):
            self.vector_search()
            self.hybrid()
            self.assertEqual(module.inspect(self.conn), before)

    def test_missing_vector_row_is_reported_and_not_returned(self):
        result = self.put("a")
        self.conn.execute("DELETE FROM vector_index WHERE chunk_id=?", (result["chunk_id"],))
        check = module.inspect(self.conn)
        self.assertEqual(check["status"], "INVALID")
        self.assertEqual(check["missing_or_cross_partition_vectors"], 1)
        self.assertEqual(self.vector_search()["matches"], [])

    def test_sqlite_trigger_prevents_cross_partition_manual_insert(self):
        result = self.put("a")
        modern = module.register_partition(self.conn, "3.15", "numpy", "2.8",
                                           4, "external-fixture-v1")["partition_id"]
        self.conn.execute("DELETE FROM vector_index WHERE chunk_id=?", (result["chunk_id"],))
        with self.assertRaisesRegex(sqlite3.IntegrityError, "vector_partition_mismatch"):
            self.conn.execute("INSERT INTO vector_index VALUES(?,?,?,?)",
                              (result["chunk_id"], modern, struct.pack("<4d", *V), 1.0))

    def test_immutable_source_and_vector_rows_refuse_raw_update(self):
        result = self.put("a")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE chunks SET content='tampered'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE vector_index SET norm_sq=999")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE partitions SET declared_vector_model='bad'")
        self.assertEqual(self.vector_search()["matches"][0]["chunk_id"],
                         result["chunk_id"])

    def test_schema_future_version_partial_fts_refused_and_symlink_db(self):
        future = self.folder / "future.sqlite"
        with closing(sqlite3.connect(str(future))) as conn:
            conn.execute("PRAGMA user_version=99")
        with self.assertRaisesRegex(ValueError, "future_or_unknown_vector_schema_refused"):
            module.database(future)
        partial = self.folder / "partial.sqlite"
        with closing(sqlite3.connect(str(partial))) as conn:
            conn.execute("CREATE TABLE chunks(fake TEXT)")
            conn.execute("PRAGMA user_version=1")
        with self.assertRaisesRegex(ValueError, "invalid_vector_schema"):
            module.database(partial)
        link = self.folder / "symlink.sqlite"
        link.symlink_to(self.db)
        with self.assertRaisesRegex(ValueError, "unsafe_vector_database_path"):
            module.database(link)

    def test_simultaneous_two_connections_commit_and_rollback_independently(self):
        self.put("first")
        with closing(module.database(self.db)) as second:
            module.record_chunk(second, "3.9", "numpy", "1.26", "second",
                                "Reliable AST visitor", URI, SHA, [0, 1, 0, 0])
            self.assertEqual(module.inspect(self.conn)["chunks"], 2)
            with self.assertRaises(ValueError):
                module.record_chunk(second, "3.9", "numpy", "1.26", "second",
                                    "Altered AST visitor", URI, SHA, [0, 1, 0, 0])
        self.assertEqual(module.inspect(self.conn)["chunks"], 2)
        self.assertEqual(module.inspect(self.conn)["vector_entries"], 2)

    def test_cli_isolated_round_trip_partition_put_hybrid_remove(self):
        script = ROOT / "python" / "vector_retrieval.py"
        def invoke(*args):
            proc = subprocess.run([sys.executable, "-I", "-S", "-B", str(script),
                                   "--db", str(self.db), *args],
                                  check=True, text=True, capture_output=True)
            return json.loads(proc.stdout)
        args = ("--python-minor", "3.9", "--package", "numpy",
                "--package-version", "1.26")
        self.assertEqual(invoke("partition", *args, "--dimension", "4", "--model",
                                "external-fixture-v1")["status"], "EXISTING_PARTITION")
        self.assertEqual(invoke("put", *args, "--chunk", "cli", "--content",
                                "Cross-reference parser", "--source-uri", URI,
                                "--source-sha256", SHA, "--vector", "[1,0,0,0]")
                         ["status"], "CHUNK_VECTOR_RECORDED")
        self.assertEqual(invoke("hybrid", *args, "--source-uri", URI,
                                "--source-sha256", SHA, "--text", "parser",
                                "--vector", "[1,0,0,0]")["fts_matched"], 1)
        self.assertEqual(invoke("delete", *args, "--chunk", "cli")["status"],
                         "REMOVED")
        self.assertEqual(invoke("check")["chunks"], 0)

    def test_invalid_query_limit_and_fts_length_and_candidate_cap(self):
        self.put("a")
        for limit in (0, 51, True):
            with self.assertRaises(ValueError):
                self.vector_search(limit=limit)
            with self.assertRaises(ValueError):
                self.hybrid(limit=limit)
        with self.assertRaises(ValueError):
            self.hybrid("x" * 600)
        old = module.MAX_SCAN_CANDIDATES
        try:
            module.MAX_SCAN_CANDIDATES = 0
            with self.assertRaisesRegex(ValueError, "too_many_candidates_exact_scan_limit"):
                self.vector_search()
        finally:
            module.MAX_SCAN_CANDIDATES = old


if __name__ == "__main__":
    unittest.main()
