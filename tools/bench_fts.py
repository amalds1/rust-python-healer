"""Reproducible SQLite FTS5 microbenchmark; this is NOT a Rust engine benchmark."""

import argparse
import json
from pathlib import Path
import platform
import sqlite3
import statistics
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from process_memory import peak_rss_kib, rss_basis  # noqa: E402


def bench_once(path, records, queries):
    """One independent SQLite database and warm-cache measurement round."""
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript((ROOT / "sql" / "knowledge.sql").read_text())
        start = time.perf_counter()
        with conn:
            for i in range(records):
                category = ["asyncio error", "dataframe merge", "dependency lock", "typing generics"][i % 4]
                conn.execute(
                    "INSERT INTO documents(source,uri,title,package,version,"
                    "python_constraint,content,sha256) VALUES(?,?,?,?,?,?,?,?)",
                    ("synthetic", f"doc://{i}", f"Document {i}", "example",
                     "1.0", ">=3.12", f"{category} API documentation example {i} " * 4,
                     f"synthetic-{i}"),
                )
        ingestion_s = time.perf_counter() - start
        query = ('"asyncio"* AND "error"*')
        sql = "SELECT d.id FROM documents_fts JOIN documents d ON d.id=documents_fts.rowid WHERE documents_fts MATCH ? ORDER BY bm25(documents_fts) LIMIT 10"
        # Warm the SQLite cache before timing steady-state queries.
        for _ in range(10):
            conn.execute(sql, (query,)).fetchall()
        times_ms = []
        for _ in range(queries):
            start = time.perf_counter()
            conn.execute(sql, (query,)).fetchall()
            times_ms.append((time.perf_counter() - start) * 1000)
        times_ms.sort()
        return ingestion_s, times_ms
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", type=int, default=10_000)
    parser.add_argument("--queries", type=int, default=100)
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()
    if not (1 <= args.records <= 100_000 and 5 <= args.queries <= 5_000 and 5 <= args.runs <= 20):
        parser.error("records 1..100000, queries 5..5000, independent runs 5..20")

    with tempfile.TemporaryDirectory() as folder:
        rounds = []
        all_times = []
        ingestions = []
        for number in range(args.runs):
            ingestion_s, times_ms = bench_once(Path(folder) / f"run-{number}.sqlite",
                                               args.records, args.queries)
            sorted_times = sorted(times_ms)
            ingestions.append(ingestion_s)
            all_times.extend(times_ms)
            rounds.append({
                "run": number + 1,
                "ingestion_seconds": round(ingestion_s, 4),
                "query_median_ms": round(statistics.median(sorted_times), 4),
                "query_p95_ms": round(sorted_times[int((len(sorted_times)-1) * 0.95)], 4),
            })
        all_times.sort()
        p95 = all_times[int((len(all_times)-1) * 0.95)]
        results = {
            "scope": "SQLite FTS5 only; Rust repair pipeline not measured",
            "records": args.records,
            "independent_runs": args.runs,
            "query_repeats_per_run": args.queries,
            "total_query_measurements": len(all_times),
            "ingestion_median_seconds": round(statistics.median(ingestions), 4),
            "query_median_ms": round(statistics.median(all_times), 4),
            "query_p95_ms": round(p95, 4),
            "query_max_ms": round(max(all_times), 4),
            "runs": rounds,
            "sqlite_version": sqlite3.sqlite_version,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "peak_rss_kib": peak_rss_kib(),
            "peak_rss_basis": rss_basis(),
            "peak_rss_scope": "entire benchmark process lifetime, not individual runs",
            "fts_p95_threshold_ms": 50.0,
            "fts_p95_status": "PASS" if p95 <= 50 and
            all(row["query_p95_ms"] <= 50 for row in rounds) else "FAIL",
        }
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
