"""Real CPython source docstrings; five genuinely fresh FTS5 measured rounds."""

import hashlib
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("real_docs_benchmark_v21",
                               ROOT / "python" / "real_docs_benchmark_v21.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


class RealDocsBenchmarkV21Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def test_actual_interpreter_stdlib_has_10k_unique_genuine_chunks_five_fresh_rounds(self):
        extraction = module.extract_real_docstrings()
        self.assertTrue(extraction["runtime_stdlib_root_selected"])
        self.assertGreaterEqual(extraction["distinct_genuine_chunks"],
                                module.REQUIRED_UNIQUE_CHUNKS)
        self.assertEqual(len(extraction["chunks"]),
                         len({chunk[5] for chunk in extraction["chunks"]}))
        self.assertEqual(extraction["python_minor"],
                         f"{sys.version_info.major}.{sys.version_info.minor}")
        self.assertFalse(extraction["external_official_origin_verified"])
        self.assertFalse(extraction["source_executed"])
        benchmark = module.benchmark_real_docs(extraction)
        self.assertTrue(benchmark["f115_bounded_local_benchmark_pass"])
        self.assertEqual(benchmark["five_fresh_db_rounds"], 5)
        self.assertEqual(benchmark["total_queries_measured"], 5 * 8 * 12)
        self.assertLessEqual(benchmark["latency_p95_ms"],
                             benchmark["predeclared_p95_threshold_ms"])
        self.assertTrue(benchmark["each_round_p95_passed"])
        self.assertEqual(benchmark["predeclared_p95_threshold_ms"], 50.0)
        self.assertEqual(benchmark["real_unique_chunks"],
                         extraction["distinct_genuine_chunks"])
        self.assertEqual(len({round_["index_round"] for round_ in benchmark["rounds"]}), 5)
        self.assertTrue(all(row["fresh_database_created"] for row in benchmark["rounds"]))
        self.assertTrue(all(row["stored_doc_chunks"] == extraction["distinct_genuine_chunks"]
                            for row in benchmark["rounds"]))
        self.assertGreater(benchmark["rss_peak_kib"], 0)
        self.assertTrue(benchmark["source_evidence_example"]["source_uri"]
                        .startswith("https://github.com/python/cpython/blob/"))
        self.assertEqual(len(benchmark["source_evidence_example"]["source_sha256"]), 64)
        self.assertFalse(benchmark["publisher_official_snapshot_authenticated"])
        self.assertFalse(benchmark["user_source_executed"])
        forged = dict(extraction)
        forged["chunks"] = extraction["chunks"] + [extraction["chunks"][0]]
        with self.assertRaisesRegex(ValueError,
                                    "benchmark_corpus_not_actual_runtime_stdlib"):
            module.benchmark_real_docs(forged)

    def test_static_extraction_refuses_execution_of_embedded_source(self):
        marker = self.folder / "executed.marker"
        source = self.folder / "dangerous.py"
        source.write_text("\"\"\"Genuine public module documentation explaining a function.\"\"\"\n"
                          f"open({str(marker)!r},'w').write('bad')\n",
                          encoding="utf-8")
        report = module.extract_real_docstrings(self.folder)
        self.assertEqual(report["distinct_genuine_chunks"], 1)
        self.assertFalse(report["runtime_stdlib_root_selected"])
        self.assertFalse(marker.exists())
        self.assertEqual(report["chunks"][0][6],
                         hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertFalse(report["source_executed"])

    def test_dedup_real_content_without_synthetic_inflation(self):
        for name in ("one.py", "two.py", "three.py"):
            (self.folder / name).write_text(
                "\"\"\"Authentic repeated documentation describing a public API.\"\"\"\n",
                encoding="utf-8")
        report = module.extract_real_docstrings(self.folder)
        self.assertEqual(report["distinct_genuine_chunks"], 1)
        self.assertEqual(report["duplicate_paragraphs_excluded"], 2)
        self.assertEqual(report["source_files_ast_parsed"], 3)
        self.assertTrue(report["no_synthetic_padding"])

    def test_symlinks_hardlinks_and_oversized_sources_are_excluded(self):
        source = self.folder / "safe.py"
        source.write_text("\"\"\"A unique actual source module for testing safety.\"\"\"\n",
                          encoding="utf-8")
        link = self.folder / "link.py"
        link.symlink_to(source)
        hardlink = self.folder / "hard.py"
        os.link(source, hardlink)
        large = self.folder / "oversized.py"
        large.write_bytes(b"a" * (module.MAX_SOURCE_BYTES + 1))
        report = module.extract_real_docstrings(self.folder)
        self.assertEqual(report["distinct_genuine_chunks"], 0)
        self.assertGreaterEqual(report["source_files_rejected"], 3)

    def test_required_five_fresh_rounds_and_fixed_threshold_fail_closed(self):
        fixture = module.extract_real_docstrings(self.folder)
        for rounds, threshold in ((4, 50), (6, 50), (5, 51), (5, 0)):
            with self.subTest(rounds=rounds, threshold=threshold), self.assertRaisesRegex(
                ValueError, "predeclared_five_round_benchmark_required"
            ):
                module.benchmark_real_docs(fixture, rounds=rounds,
                                           threshold_ms=threshold)

    def test_small_fixture_never_passes_ten_thousand_gate_even_five_rounds(self):
        source = self.folder / "fixture.py"
        source.write_text("\"\"\"Reliable module text describing source code symbols.\"\"\"\n"
                          "def helper():\n    \"\"\"Unique function text with an example.\"\"\"\n"
                          "    return True\n", encoding="utf-8")
        report = module.extract_real_docstrings(self.folder)
        # Query terms require hits; intentionally produce enough real terms.
        with self.assertRaisesRegex(ValueError, "real_fts_query_evidence_missing"):
            module.benchmark_real_docs(report)

    def test_sqlite_full_text_rebuild_indexes_actual_chunks(self):
        fresh = self.folder / "brand_new.sqlite"
        source = "Reliable file parsing function and module documentation"
        item = ("3.12", "module.py", 1, "parse", source,
                hashlib.sha256(source.encode()).hexdigest(),
                hashlib.sha256(b"source bytes").hexdigest(),
                "https://github.com/python/cpython/blob/3.12/Lib/module.py")
        size = module._build_fresh_index(fresh, [item])
        self.assertGreater(size, 0)
        with closing(sqlite3.connect(str(fresh))) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM docs_fts WHERE "
                                          "docs_fts MATCH 'parsing'").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT source_sha256 FROM documents")
                             .fetchone()[0], item[6])
        with self.assertRaisesRegex(ValueError, "benchmark_database_must_be_fresh"):
            module._build_fresh_index(fresh, [item])

    def test_p95_is_true_nearest_rank_statistic(self):
        self.assertEqual(module.percentile([1, 2, 3, 4, 5, 10], 95), 10)
        self.assertEqual(module.percentile([1, 2, 3, 4, 5, 10], 50), 3)
        with self.assertRaises(ValueError):
            module.percentile([], 95)


if __name__ == "__main__":
    unittest.main()
