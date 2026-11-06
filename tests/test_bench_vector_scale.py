"""Scale measurement must never turn a small fixture into million-row proof."""

from contextlib import closing
from importlib.util import module_from_spec, spec_from_file_location
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
import vector_retrieval as vectors  # noqa: E402 -- runtime path installed above

spec = spec_from_file_location("bench_vector_scale", ROOT / "tools" / "bench_vector_scale.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)

URI = "https://docs.python.org/3/library/inspect.html"
SHA = hashlib.sha256(b"source-reference").hexdigest()


class VectorScaleBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.db = self.folder / "vector.sqlite"
        with closing(vectors.database(self.db)) as conn:
            vectors.register_partition(conn, "3.12", "inspect", "1.0", 4,
                                       "declared-fixture")
            vectors.record_chunk(conn, "3.12", "inspect", "1.0", "test",
                                 "Inspect Python library source", URI, SHA,
                                 [1, 0, 0, 0])
        self.query = {"python_minor": "3.12", "package_name": "inspect",
                      "package_version": "1.0", "source_uri": URI,
                      "source_sha256": SHA, "vector": [1, 0, 0, 0],
                      "text": "Python"}
        self.queryfile = self.folder / "queries.jsonl"
        self.queryfile.write_text(json.dumps(self.query) + "\n", encoding="utf-8")

    def test_below_million_never_reports_scale_proof(self):
        report = module.benchmark_existing(self.db, [self.query], iterations=10)
        self.assertEqual(report["status"], "BELOW_MILLION_NO_SCALE_PROOF")
        self.assertFalse(report["scale_proof"])
        self.assertEqual(report["stored_chunk_count"], 1)
        self.assertEqual(report["minimum_required_chunks"], 1_000_000)
        self.assertEqual(report["queries_measured"], 10)
        self.assertGreaterEqual(report["latency_p95_ms"], 0)
        self.assertGreaterEqual(report["rss_peak_kib"], report["rss_start_kib"])
        self.assertEqual(report["rss_basis"], module.rss_basis())
        self.assertGreater(report["rss_start_kib"], 0)
        self.assertGreater(report["rss_peak_kib"], 0)

    def test_read_only_benchmark_does_not_write_to_existing_corpus(self):
        before = (self.db.stat().st_size, self.db.stat().st_mtime_ns)
        module.benchmark_existing(self.db, [self.query], iterations=8)
        self.assertEqual((self.db.stat().st_size, self.db.stat().st_mtime_ns), before)
        with closing(vectors.database(self.db)) as conn:
            self.assertEqual(vectors.inspect(conn)["chunks"], 1)

    def test_semantic_attestation_is_never_invented(self):
        report = module.benchmark_existing(self.db, [self.query], iterations=5)
        self.assertFalse(report["corpus_representativeness_independently_verified"])
        self.assertFalse(report["full_pipeline_performance_verified"])
        self.assertFalse(report["embedded_generated"])
        self.assertFalse(report["source_executed"])

    def test_manifest_query_validations_reject_oversized_symlink_missing(self):
        self.assertEqual(module.query_specs_from_file(self.queryfile), [self.query])
        link = self.folder / "link.jsonl"
        link.symlink_to(self.queryfile)
        with self.assertRaisesRegex(ValueError, "invalid_query_manifest"):
            module.query_specs_from_file(link)
        oversized = self.folder / "large.jsonl"
        oversized.write_bytes(b"x" * (module.MAX_QUERY_FILE_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "invalid_query_manifest"):
            module.query_specs_from_file(oversized)

    def test_bad_query_spec_or_iteration_limits_never_hide_failure(self):
        for count in (0, 4, 1001, True):
            with self.assertRaises(ValueError):
                module.benchmark_existing(self.db, [self.query], iterations=count)
        with self.assertRaisesRegex(ValueError, "missing_benchmark_query_fields"):
            module.benchmark_existing(self.db, [{"vector": [1, 0, 0, 0]}], iterations=5)
        with self.assertRaisesRegex(ValueError, "invalid_benchmark_queries"):
            module.benchmark_existing(self.db, [], iterations=5)

    def test_p95_nearest_rank_is_correct_without_fabrication(self):
        self.assertEqual(module.percentile([5, 1, 7, 2, 9], 95), 9)
        self.assertEqual(module.percentile([5, 1, 7, 2, 9], 50), 5)
        with self.assertRaises(ValueError):
            module.percentile([], 95)

    def test_corrupt_index_is_refused_before_benchmark(self):
        with closing(sqlite3.connect(str(self.db))) as conn:
            with conn:
                conn.execute("DELETE FROM vector_index")
        with self.assertRaisesRegex(ValueError, "corrupt_benchmark_vector_index"):
            module.benchmark_existing(self.db, [self.query], iterations=5)

    def test_cli_live_measures_small_corpus_but_never_claims_million(self):
        script = ROOT / "tools" / "bench_vector_scale.py"
        proc = subprocess.run([sys.executable, "-I", "-S", "-B", str(script),
                               "--db", str(self.db), "--queries", str(self.queryfile),
                               "--iterations", "5"], check=True,
                              capture_output=True, text=True)
        report = json.loads(proc.stdout)
        self.assertEqual(report["status"], "BELOW_MILLION_NO_SCALE_PROOF")
        self.assertEqual(report["stored_chunk_count"], 1)
        self.assertEqual(report["queries_measured"], 5)


if __name__ == "__main__":
    unittest.main()
