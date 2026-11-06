"""Read-only measured vector/FTS benchmark against a PREEXISTING corpus.

No fixture data is synthesized as a substitute for one million real document
chunks. An under-one-million corpus gives useful diagnostics but NEVER proof of
F230. Caller-provided query vectors are fixed; no code or embeddings executed.
"""

import argparse
from contextlib import closing
import json
import math
from pathlib import Path
import sqlite3
import sys
import time
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
import vector_retrieval as retrieval  # noqa: E402 -- own bundled package path above
from process_memory import peak_rss_kib, rss_basis  # noqa: E402


MIN_SCALE_ROWS = 1_000_000
MAX_QUERY_SPECS = 256
MAX_QUERY_FILE_BYTES = 128 * 1024


def percentile(values, pct):
    if not values:
        raise ValueError("no_benchmark_measurements")
    ordered = sorted(values)
    index = math.ceil(len(ordered) * pct / 100) - 1
    return ordered[max(0, index)]


def _read_only_database(path):
    target = Path(path)
    if (target.is_symlink() or not target.is_file() or
            target.parent.is_symlink() or target.stat().st_nlink != 1):
        raise ValueError("invalid_read_only_benchmark_database")
    if target.stat().st_size > retrieval.MAX_DB_BYTES:
        raise ValueError("benchmark_database_size_limit_exceeded")
    # Quote the resolved POSIX filesystem path, never user-controlled SQL.
    uri = "file:{}?mode=ro".format(quote(str(target.resolve())))
    conn = sqlite3.connect(uri, uri=True, timeout=10.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def query_specs_from_file(path):
    target = Path(path)
    if (target.is_symlink() or not target.is_file() or
            target.stat().st_size > MAX_QUERY_FILE_BYTES or
            target.stat().st_nlink != 1):
        raise ValueError("invalid_query_manifest")
    specs = []
    with target.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            if len(specs) >= MAX_QUERY_SPECS:
                raise ValueError("too_many_benchmark_queries")
            spec = json.loads(line)
            if not isinstance(spec, dict):
                raise ValueError("invalid_benchmark_query_spec")
            specs.append(spec)
    if not specs:
        raise ValueError("no_benchmark_queries")
    return specs


def benchmark_existing(db_path, specs, iterations=100):
    if type(iterations) is not int or not 5 <= iterations <= 1000:
        raise ValueError("invalid_benchmark_iterations")
    if (not isinstance(specs, list) or not specs or
            len(specs) > MAX_QUERY_SPECS):
        raise ValueError("invalid_benchmark_queries")
    with closing(_read_only_database(db_path)) as conn:
        integrity = retrieval.inspect(conn)
        if integrity["status"] != "STRUCTURALLY_SYNCED_NOT_SEMANTICALLY_VALIDATED":
            raise ValueError("corrupt_benchmark_vector_index")
        chunk_count = integrity["chunks"]
        diversity = conn.execute("""
            SELECT COUNT(DISTINCT p.python_minor),COUNT(DISTINCT p.package_name),
                   COUNT(DISTINCT p.package_name||'@'||p.package_version),
                   COUNT(DISTINCT c.source_uri),COUNT(DISTINCT c.source_sha256)
            FROM chunks c JOIN partitions p ON p.partition_id=c.partition_id
        """).fetchone()
        baseline = peak_rss_kib()
        latencies = []
        checked = 0
        matched = 0
        for index in range(iterations):
            spec = specs[index % len(specs)]
            try:
                args = (spec["python_minor"], spec["package_name"],
                        spec["package_version"], spec["source_uri"],
                        spec["source_sha256"])
                vector = spec["vector"]
            except (TypeError, KeyError) as exc:
                raise ValueError("missing_benchmark_query_fields") from exc
            started = time.perf_counter_ns()
            if "text" in spec:
                result = retrieval.search_hybrid(conn, *args, spec["text"], vector,
                                                 limit=10)
            else:
                result = retrieval.search_vector(conn, *args, vector, limit=10)
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
            latencies.append(elapsed_ms)
            checked += result["candidates_checked"]
            matched += len(result["matches"])
        rss = peak_rss_kib()
        enough = chunk_count >= MIN_SCALE_ROWS
        return {
            "status": ("MILLION_ROWS_MEASURED_SOURCE_REPRESENTATIVENESS_UNVERIFIED"
                       if enough else "BELOW_MILLION_NO_SCALE_PROOF"),
            "scale_proof": False,
            "stored_chunk_count": chunk_count, "minimum_required_chunks": MIN_SCALE_ROWS,
            "python_minor_groups": diversity[0],
            "package_groups": diversity[1],
            "package_version_groups": diversity[2],
            "distinct_source_uris": diversity[3],
            "distinct_source_sha256": diversity[4],
            "queries_measured": iterations,
            "candidate_vectors_scored": checked,
            "matches_reported": matched,
            "latency_p50_ms": percentile(latencies, 50),
            "latency_p95_ms": percentile(latencies, 95),
            "latency_max_ms": max(latencies),
            "rss_start_kib": baseline,
            "rss_peak_kib": rss,
            "rss_growth_kib": max(0, rss - baseline),
            "rss_basis": rss_basis(),
            "rss_measurement_scope": "process lifetime high-water; start is not current RSS",
            "corpus_representativeness_independently_verified": False,
            "full_pipeline_performance_verified": False,
            "source_executed": False, "embedded_generated": False,
            "readonly_database": True,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--queries", required=True, type=Path)
    parser.add_argument("--iterations", type=int, default=100)
    args = parser.parse_args()
    report = benchmark_existing(args.db, query_specs_from_file(args.queries),
                                args.iterations)
    print(json.dumps(report, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
