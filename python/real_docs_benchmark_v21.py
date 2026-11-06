"""Real CPython stdlib docstring FTS5 benchmark, with no synthetic padding.

Only source-encoded AST docstrings from the running interpreter's local Lib
directory count. Five fresh SQLite FTS5 databases are built independently.
Source URI points to the corresponding CPython branch, but remote origin and
installed source publisher are NOT independently attested offline.
"""

import argparse
import ast
import hashlib
import io
import json
import math
import os
import importlib.util
import sqlite3
import stat
import sys
import sysconfig
import tempfile
import time
import tokenize
from contextlib import closing
from pathlib import Path

REQUIRED_UNIQUE_CHUNKS = 10_000
FRESH_DATABASE_ROUNDS = 5
MAX_P95_MS = 50.0  # Existing project FTS5 SLO in docs/ARCHITECTURE.md.


def _process_memory():
    embedded = globals().get("_RPH_PROCESS_MEMORY")
    if embedded is not None:
        return embedded
    spec = importlib.util.spec_from_file_location("rph_real_docs_process_memory",Path(__file__).resolve().with_name("process_memory.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    globals()["_RPH_PROCESS_MEMORY"] = module
    return module
MAX_FILES = 1_500
MAX_SOURCE_BYTES = 1_048_576
MAX_CONTENT_CHARS = 4_096
MAX_CHUNKS = 30_000
SKIP = frozenset(("test", "tests", "site-packages", "dist-packages",
                  "__pycache__", "idlelib", "tkinter", "venv", "ensurepip"))
TERMS = ("function", "module", "file", "class", "data", "return", "object", "value")


def _source_bytes(path):
    if path.is_symlink():
        raise ValueError("symlink_doc_source_refused")
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_size > MAX_SOURCE_BYTES):
            raise ValueError("doc_source_not_unique_bounded")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(MAX_SOURCE_BYTES + 1)
            after = os.fstat(stream.fileno())
        if (len(raw) > MAX_SOURCE_BYTES or
                (before.st_size, before.st_mtime_ns, before.st_ino, before.st_dev) !=
                (after.st_size, after.st_mtime_ns, after.st_ino, after.st_dev)):
            raise ValueError("doc_source_changed")
        return raw
    finally:
        if fd is not None:
            os.close(fd)


def _relative_sources(root):
    found = []
    for directory, folders, filenames in os.walk(str(root), followlinks=False):
        current = Path(directory)
        folders[:] = sorted(folder for folder in folders
                            if folder not in SKIP and not (current / folder).is_symlink())
        for name in sorted(filenames):
            path = current / name
            if not name.endswith(".py") or path.is_symlink():
                continue
            found.append(path)
            if len(found) > MAX_FILES:
                raise ValueError("too_many_stdlib_doc_sources")
    return sorted(found, key=lambda path: path.relative_to(root).as_posix())


def extract_real_docstrings(root=None):
    """Pure AST extraction; each chunk is unique observed genuine text."""
    runtime_root = Path(sysconfig.get_path("stdlib"))
    if root is None:
        root = runtime_root
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("unsafe_stdlib_docs_root")
    genuine_local_stdlib = root.resolve() == runtime_root.resolve()
    minor = f"{sys.version_info.major}.{sys.version_info.minor}"
    seen = set()
    results = []
    source_files = 0
    valid_ast_files = 0
    parse_rejections = 0
    docstrings = 0
    repeats_ignored = 0
    for path in _relative_sources(root):
        source_files += 1
        try:
            raw = _source_bytes(path)
            encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
            decoded = raw.decode(encoding)
            tree = ast.parse(decoded, filename="[LOCAL_STDLIB_SOURCE]", mode="exec")
        except (ValueError, SyntaxError, UnicodeError, LookupError, OSError):
            parse_rejections += 1
            continue
        valid_ast_files += 1
        source_sha = hashlib.sha256(raw).hexdigest()
        relative = path.relative_to(root).as_posix()
        source_uri = f"https://github.com/python/cpython/blob/{minor}/Lib/{relative}"
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                     ast.AsyncFunctionDef)):
                continue
            doc = ast.get_docstring(node, clean=True)
            if not doc:
                continue
            docstrings += 1
            name = getattr(node, "name", "[module]")
            line = getattr(node, "lineno", 1)
            for paragraph in doc.split("\n\n"):
                paragraph = paragraph.strip()
                if not 30 <= len(paragraph) <= MAX_CONTENT_CHARS:
                    continue
                fragment_hash = hashlib.sha256(paragraph.encode("utf-8")).hexdigest()
                if fragment_hash in seen:
                    repeats_ignored += 1
                    continue
                seen.add(fragment_hash)
                results.append((minor, relative, line, name, paragraph,
                                fragment_hash, source_sha, source_uri))
                if len(results) >= MAX_CHUNKS:
                    raise ValueError("real_doc_chunk_limit_reached")
    return {"status": "EXTRACTED_REAL_LOCAL_STDLIB_AST_DOCSTRINGS",
            "python_minor": minor,
            "stdlib_root": str(root),
            "runtime_stdlib_root_selected": genuine_local_stdlib,
            "source_files_considered": source_files,
            "source_files_ast_parsed": valid_ast_files,
            "source_files_rejected": parse_rejections,
            "docstring_declarations_seen": docstrings,
            "distinct_genuine_chunks": len(results),
            "duplicate_paragraphs_excluded": repeats_ignored,
            "chunks": results,
            "no_synthetic_padding": True,
            "local_source_sha256_recorded": True,
            "external_official_origin_verified": False,
            "source_executed": False}


def _build_fresh_index(path, chunks):
    """SQLite FTS5 index rebuilt from true content in one fresh database."""
    if Path(path).exists():
        raise ValueError("benchmark_database_must_be_fresh")
    with closing(sqlite3.connect(str(path))) as conn, conn:
        conn.executescript("""
                CREATE TABLE documents(
                  id INTEGER PRIMARY KEY, python_minor TEXT NOT NULL,
                  source_path TEXT NOT NULL, source_line INTEGER NOT NULL,
                  symbol TEXT NOT NULL, content TEXT NOT NULL,
                  content_sha256 TEXT NOT NULL, source_sha256 TEXT NOT NULL,
                  source_uri TEXT NOT NULL);
                CREATE VIRTUAL TABLE docs_fts USING fts5(
                  content, content='documents',content_rowid='id');
                CREATE INDEX idx_source_version ON documents(python_minor,source_path);
            """)
        conn.executemany("""
                INSERT INTO documents(python_minor,source_path,source_line,symbol,
                    content,content_sha256,source_sha256,source_uri)
                VALUES(?,?,?,?,?,?,?,?)
            """, chunks)
        conn.execute("INSERT INTO docs_fts(docs_fts) VALUES('rebuild')")
    return Path(path).stat().st_size


def _query_round(conn, python_minor, samples=12):
    latencies = []
    hits = 0
    evidence = None
    seen_terms = set()
    for _ in range(samples):
        for term in TERMS:
            started = time.perf_counter_ns()
            rows = conn.execute("""
                SELECT d.content_sha256,d.source_sha256,d.source_uri,
                       bm25(docs_fts) AS rank
                FROM docs_fts JOIN documents d ON d.id=docs_fts.rowid
                WHERE docs_fts MATCH ? AND d.python_minor=?
                ORDER BY rank ASC LIMIT 8
            """, (term, python_minor)).fetchall()
            latencies.append((time.perf_counter_ns() - started) / 1_000_000)
            hits += len(rows)
            if rows:
                seen_terms.add(term)
            if rows and evidence is None:
                evidence = rows[0]
    return latencies, hits, evidence, len(seen_terms)


def percentile(values, pct):
    if not values:
        raise ValueError("no_real_latency_samples")
    data = sorted(values)
    return data[max(0, math.ceil(len(data) * pct / 100) - 1)]


def benchmark_real_docs(report, rounds=FRESH_DATABASE_ROUNDS,
                        threshold_ms=MAX_P95_MS):
    """Five independent fresh indexes, actual FTS5 p95 and process high RSS."""
    if (type(rounds) is not int or rounds != FRESH_DATABASE_ROUNDS or
            type(threshold_ms) not in (int, float) or not 0 < threshold_ms <= MAX_P95_MS):
        raise ValueError("predeclared_five_round_benchmark_required")
    chunks = report.get("chunks")
    if not isinstance(chunks, list) or not chunks:
        raise ValueError("missing_real_doc_chunks")
    if report.get("runtime_stdlib_root_selected") is True:
        # A caller may hand us an arbitrary report dict. Re-read independently
        # from the actual interpreter Lib, failing closed on synthetic padding
        # or manipulated provenance/chunk content before measuring performance.
        authoritative = extract_real_docstrings()
        if (chunks != authoritative["chunks"] or
                report.get("python_minor") != authoritative["python_minor"]):
            raise ValueError("benchmark_corpus_not_actual_runtime_stdlib")
    memory = _process_memory()
    baseline_rss = memory.peak_rss_kib()
    latencies = []
    rounds_report = []
    source_proof = None
    with tempfile.TemporaryDirectory(prefix="real-stdlib-fts-") as temp:
        for index in range(rounds):
            database_file = Path(temp) / f"fresh_round_{index}.sqlite"
            started = time.perf_counter_ns()
            bytes_written = _build_fresh_index(database_file, chunks)
            ingest_ms = (time.perf_counter_ns() - started) / 1_000_000
            with closing(sqlite3.connect(str(database_file))) as conn:
                read_count = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
                if read_count != len(chunks) or conn.execute(
                        "PRAGMA quick_check(1)").fetchone()[0] != "ok":
                    raise ValueError("invalid_fresh_fts_index")
                timing, hits, evidence, matched_terms = _query_round(
                    conn, report["python_minor"])
                if evidence is not None:
                    source_proof = {"content_sha256": evidence[0],
                                    "source_sha256": evidence[1],
                                    "source_uri": evidence[2]}
            if matched_terms != len(TERMS):
                raise ValueError("real_fts_query_evidence_missing")
            latencies.extend(timing)
            rounds_report.append({"index_round": index + 1,
                                  "fresh_database_created": True,
                                  "stored_doc_chunks": read_count,
                                  "database_bytes": bytes_written,
                                  "ingest_ms": ingest_ms,
                                  "queries_measured": len(timing),
                                  "fts_hits": hits,
                                  "round_p95_ms": percentile(timing, 95),
                                  "rss_peak_kib": memory.peak_rss_kib()})
    p95 = percentile(latencies, 95)
    enough = len(chunks) >= REQUIRED_UNIQUE_CHUNKS
    real_runtime = report.get("runtime_stdlib_root_selected") is True
    each_round_passed = all(row["round_p95_ms"] <= threshold_ms for row in rounds_report)
    success = (enough and real_runtime and len(rounds_report) == 5 and
               each_round_passed and p95 <= threshold_ms)
    final_rss = memory.peak_rss_kib()
    return {"status": "REAL_LOCAL_STDLIB_P95_PASSED_REMOTE_UNATTESTED" if success
            else "INSUFFICIENT_REAL_DOC_SCALE_OR_LATENCY",
            "f115_bounded_local_benchmark_pass": success,
            "python_minor": report["python_minor"],
            "real_unique_chunks": len(chunks),
            "minimum_required_chunks": REQUIRED_UNIQUE_CHUNKS,
            "no_synthetic_padding": True,
            "five_fresh_db_rounds": len(rounds_report),
            "rounds": rounds_report,
            "total_queries_measured": len(latencies),
            "latency_p50_ms": percentile(latencies, 50),
            "latency_p95_ms": p95,
            "latency_max_ms": max(latencies),
            "predeclared_p95_threshold_ms": threshold_ms,
            "each_round_p95_passed": each_round_passed,
            "rss_start_kib": baseline_rss, "rss_peak_kib": final_rss,
            "rss_growth_kib": max(0, final_rss - baseline_rss),
            "rss_basis": memory.rss_basis(),
            "rss_scope": "same benchmark process lifetime high-water; not per-query RSS",
            "source_evidence_example": source_proof,
            "publisher_official_snapshot_authenticated": False,
            "real_corpus_other_than_local_stdlib": False,
            "user_source_executed": False,
            "source_files_ast_parsed": report.get("source_files_ast_parsed"),
            "docstring_declarations_seen": report.get("docstring_declarations_seen")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--json", type=Path,
                        help="Bewaar exact dit lokale FTS5-benchmarkbewijs")
    args = parser.parse_args()
    report = extract_real_docstrings()
    if args.benchmark:
        public = benchmark_real_docs(report)
    else:
        public = {key: value for key, value in report.items() if key != "chunks"}
    encoded = json.dumps(public, sort_keys=True, allow_nan=False)
    if args.json is not None:
        if args.json.parent.is_symlink() or not args.json.parent.is_dir() or args.json.is_symlink():
            parser.error("ongeldige begrensde bewijsbestandslocatie")
        args.json.write_text(json.dumps(public, indent=2, sort_keys=True, allow_nan=False)
                             + "\n", encoding="utf-8")
    print(encoded)


if __name__ == "__main__":
    main()
