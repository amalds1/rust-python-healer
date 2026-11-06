"""Versioned native API facts, measured retrieval quality and real DuckDB.

Never execute project examples or claim remote publisher authenticity. The
large-corpus gate rejects insufficient/duplicated source content instead of
filling a benchmark with invented documents. DuckDB is strictly optional;
no SQLite replacement is reported as a DuckDB test.
"""

import argparse
from contextlib import closing
import hashlib
import hmac
import importlib
import importlib.util
import inspect
import json
import math
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SYNTAX_ID = re.compile(r"[a-z][a-z0-9_]{0,47}\Z")
MAX_SYNTAX_FEATURES = 32
MAX_SYNTAX_SOURCE_BYTES = 65536
MAX_RELEVANCE_DOCS = 256
MAX_VECTOR_DIMENSION = 512
MAX_QUERY_COUNT = 128
MAX_EXPERIMENTS = 30000
NATIVE_ALLOWLIST = (
    "builtins", "math", "itertools", "functools", "operator", "array",
    "datetime", "unicodedata", "binascii", "_collections", "_io",
)
SYNTAX_SAMPLES = {
    "structural_pattern_matching": "match value:\n case 1: result = 'yes'\n",
    "exception_groups_except_star": "try:\n raise ValueError()\nexcept* ValueError:\n pass\n",
    "pep695_type_alias": "type Point = tuple[int, int]\n",
    "generic_type_parameters": "def identity[T](value: T) -> T:\n return value\n",
    "template_string_literals": "template = t'hello {name}'\n",
}


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def native_api_inventory():
    """Actually inspect selected CPython-built native exports, no user import."""
    symbols = []
    seen = set()
    for module_name in NATIVE_ALLOWLIST:
        module = importlib.import_module(module_name)
        # Some CPython minors lazily populate native module dictionaries.
        # Snapshot enumeration to avoid size-changing iterator failures.
        for name, value in list(vars(module).items()):
            if name.startswith("_"):
                continue
            candidates = [(name, value)]
            if inspect.isclass(value) and value.__module__ == module_name:
                candidates.extend((name + "." + child, member)
                                  for child, member in list(vars(value).items())
                                  if not child.startswith("_"))
            for qualified, member in candidates:
                if not (inspect.isbuiltin(member) or inspect.ismethoddescriptor(member)
                        or inspect.isgetsetdescriptor(member)):
                    continue
                key = module_name + "." + qualified
                if key in seen:
                    continue
                seen.add(key)
                try:
                    signature = str(inspect.signature(member))
                except (TypeError, ValueError):
                    signature = getattr(member, "__text_signature__", None)
                if type(signature) is not str or len(signature) > 400:
                    signature = None
                symbols.append({"symbol": key, "kind": type(member).__name__,
                                "signature": signature})
    symbols.sort(key=lambda row: row["symbol"])
    signed = sum(row["signature"] is not None for row in symbols)
    proof = _sha(_json_bytes(symbols))
    return {"status": "REAL_SELECTED_NATIVE_STDLIB_INTROSPECTION_PARTIAL",
            "python_minor": "{}.{}".format(*sys.version_info[:2]),
            "python_micro": "{}.{}.{}".format(*sys.version_info[:3]),
            "selected_modules": list(NATIVE_ALLOWLIST),
            "native_symbols_observed": len(symbols),
            "native_symbols_with_signature": signed,
            "native_symbols_without_signature": len(symbols) - signed,
            "native_symbols": symbols,
            "native_inventory_sha256": proof,
            "full_stdlib_complete": False,
            "dynamic_or_untrusted_code_imported": False}


def _validated_manifest(examples, pinned_sha256):
    if (type(examples) is not dict or not 1 <= len(examples) <= MAX_SYNTAX_FEATURES or
            type(pinned_sha256) is not str or not SHA256.fullmatch(pinned_sha256)):
        raise ValueError("invalid_versioned_syntax_manifest")
    if _sha(_json_bytes(examples)) != pinned_sha256:
        raise ValueError("syntax_manifest_digest_pin_mismatch")
    for name, source in examples.items():
        if (type(name) is not str or not SYNTAX_ID.fullmatch(name) or
                type(source) is not str or
                not 1 <= len(source.encode("utf-8")) <= MAX_SYNTAX_SOURCE_BYTES):
            raise ValueError("invalid_syntax_feature")
    return {name: examples[name] for name in sorted(examples)}


def migrate_syntax_schema(conn, examples, pinned_sha256, inject_failure=False):
    """Atomic DDL expansion for new compile-only syntax features and versions.

    Every new feature creates a real SQLite column. Never changes the shared
    catalog's PRAGMA user_version or claims to understand future syntax rules.
    """
    manifest = _validated_manifest(examples, pinned_sha256)
    if not isinstance(conn, sqlite3.Connection):
        raise ValueError("sqlite_connection_required")
    # Syntax compilation is read-only: no source body is executed.
    verdicts = {}
    for name, source in manifest.items():
        try:
            compile(source, "<pinned-syntax-feature>", "exec", dont_inherit=True)
        except (SyntaxError, IndentationError, ValueError, RecursionError):
            verdicts[name] = 0
        else:
            verdicts[name] = 1
    version = "{}.{}.{}".format(*sys.version_info[:3])
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS v23_syntax_meta(" 
                     "feature_name TEXT PRIMARY KEY,source_sha256 TEXT NOT NULL,"
                     "introduced_at INTEGER NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS v23_syntax_capabilities(" 
                     "python_version TEXT PRIMARY KEY,manifest_digest TEXT NOT NULL,"
                     "compile_only INTEGER NOT NULL CHECK(compile_only=1))")
        conn.execute("CREATE TABLE IF NOT EXISTS v23_syntax_events(" 
                     "event_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                     "python_version TEXT NOT NULL,action TEXT NOT NULL,"
                     "feature_name TEXT NOT NULL,source_sha256 TEXT NOT NULL)")
        existing = {name: digest for name, digest in conn.execute(
            "SELECT feature_name,source_sha256 FROM v23_syntax_meta")}
        for name, source in manifest.items():
            digest = _sha(source.encode("utf-8"))
            if name in existing and existing[name] != digest:
                raise ValueError("syntax_feature_identity_changed_new_id_required")
        additions = [name for name in manifest if name not in existing]
        if len(existing) + len(additions) > MAX_SYNTAX_FEATURES:
            raise ValueError("syntax_feature_schema_quota")
        columns = {row[1] for row in conn.execute(
            "PRAGMA table_info(v23_syntax_capabilities)")}
        for name, source in manifest.items():
            key = "syntax_" + name
            if name in existing and key not in columns:
                raise ValueError("syntax_schema_columns_corrupt")
            if name not in existing:
                conn.execute('ALTER TABLE v23_syntax_capabilities ADD COLUMN "{}" '
                             'INTEGER NOT NULL DEFAULT 0 CHECK("{}" IN (0,1))'.format(
                                 key, key))
                conn.execute("INSERT INTO v23_syntax_meta VALUES(?,?,?)",
                             (name, _sha(source.encode("utf-8")), int(time.time())))
                conn.execute("INSERT INTO v23_syntax_events(" 
                             "python_version,action,feature_name,source_sha256) "
                             "VALUES(?,?,?,?)", (version, "COLUMN_ADDED", name,
                                                 _sha(source.encode("utf-8"))))
        conn.execute("INSERT INTO v23_syntax_capabilities(" 
                     "python_version,manifest_digest,compile_only) VALUES(?,?,1) "
                     "ON CONFLICT(python_version) DO UPDATE SET "
                     "manifest_digest=excluded.manifest_digest", (version, pinned_sha256))
        for name in manifest:
            conn.execute('UPDATE v23_syntax_capabilities SET "{}"=? '
                         'WHERE python_version=?'.format("syntax_" + name),
                         (verdicts[name], version))
        if inject_failure:
            raise ValueError("injected_transaction_rollback")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    columns_after = {row[1] for row in conn.execute(
        "PRAGMA table_info(v23_syntax_capabilities)")}
    return {"status": "LOCAL_SYNTAX_AWARE_SCHEMA_MIGRATED",
            "python_version": version, "features_probed": len(manifest),
            "new_schema_columns": additions, "stored_manifest_sha256": pinned_sha256,
            "syntax_compile_verdicts": verdicts,
            "actual_columns_created": ["syntax_" + name for name in additions
                                       if "syntax_" + name in columns_after],
            "unknown_python_source_executed": False,
            "future_python_versions_fully_qualified": False}


def _verify_signed_dataset(payload, signature, key):
    if (type(payload) is not dict or type(signature) is not str or
            not SHA256.fullmatch(signature) or type(key) is not bytes or len(key) < 16):
        raise ValueError("invalid_quality_dataset_signature")
    true = hmac.new(key, _json_bytes(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(true, signature):
        raise ValueError("quality_dataset_signature_mismatch")


def _normalized_vector(raw, dimension):
    if type(raw) is not list or len(raw) != dimension:
        raise ValueError("vector_dimension_mismatch")
    if any(type(component) not in (int, float) or not math.isfinite(component)
           for component in raw):
        raise ValueError("nonfinite_embedding_component")
    norm = math.sqrt(sum(float(component) * float(component) for component in raw))
    if not 1e-12 < norm < 1e12:
        raise ValueError("invalid_embedding_norm")
    return [float(component) / norm for component in raw]


def evaluate_labeled_vectors(embeddings, labels, embedding_signature,
                             label_signature, producer_key, auditor_key,
                             top_k=3, min_recall=0.8):
    """Actual cosine/recall/nDCG/MRR vs separately signed relevance labels.

    Labels are not inferred from vectors. Distinct keys test provenance roles,
    but local possession of both keys does not establish external independence.
    """
    if producer_key == auditor_key:
        raise ValueError("auditor_key_must_differ_from_embedding_producer")
    _verify_signed_dataset(embeddings, embedding_signature, producer_key)
    _verify_signed_dataset(labels, label_signature, auditor_key)
    if (set(embeddings) != {"documents", "queries", "model", "dimension",
                            "document_source_sha256"} or
            set(labels) != {"judgments", "source", "annotation_version"}):
        raise ValueError("invalid_relevance_dataset_schema")
    documents, queries = embeddings["documents"], embeddings["queries"]
    judgments = labels["judgments"]
    dimension = embeddings["dimension"]
    if (type(documents) is not dict or type(queries) is not dict or
            type(judgments) is not dict or type(dimension) is not int or
            not 1 <= dimension <= MAX_VECTOR_DIMENSION or
            not 2 <= len(documents) <= MAX_RELEVANCE_DOCS or
            not 1 <= len(queries) <= MAX_QUERY_COUNT or
            set(queries) != set(judgments) or
            type(top_k) is not int or not 1 <= top_k <= len(documents) or
            type(min_recall) not in (int, float) or not 0 < min_recall <= 1):
        raise ValueError("invalid_retrieval_quality_budget")
    if type(embeddings["model"]) is not str or not embeddings["model"]:
        raise ValueError("model_identity_required")
    sources = embeddings["document_source_sha256"]
    if (type(sources) is not dict or set(sources) != set(documents) or
            any(type(value) is not str or not SHA256.fullmatch(value)
                for value in sources.values())):
        raise ValueError("source_provenance_sha256_required")
    docvec = {name: _normalized_vector(vec, dimension)
              for name, vec in documents.items()}
    queryvec = {name: _normalized_vector(vec, dimension)
                for name, vec in queries.items()}
    per_query = {}
    for name in sorted(queries):
        relevant = judgments[name]
        if (type(relevant) is not list or not relevant or
                len(set(relevant)) != len(relevant) or
                any(item not in docvec for item in relevant)):
            raise ValueError("invalid_independent_relevance_labels")
        scores = sorted(((sum(a*b for a, b in zip(queryvec[name], vector)), doc)
                         for doc, vector in docvec.items()),
                        key=lambda pair: (-pair[0], pair[1]))
        found = [doc for _, doc in scores[:top_k]]
        truth = set(relevant)
        hits = sum(doc in truth for doc in found)
        recall = hits / len(truth)
        rank_first = next((i+1 for i, doc in enumerate(found) if doc in truth), None)
        dcg = sum(1.0 / math.log2(i+2) for i, doc in enumerate(found)
                  if doc in truth)
        ideal = sum(1.0 / math.log2(i+2) for i in range(min(len(truth), top_k)))
        per_query[name] = {"recall_at_k": recall,
                           "reciprocal_rank": 1/rank_first if rank_first else 0.0,
                           "ndcg_at_k": dcg/ideal,
                           "ranked_doc_ids": found}
    macro_recall = sum(row["recall_at_k"] for row in per_query.values()) / len(per_query)
    macro_mrr = sum(row["reciprocal_rank"] for row in per_query.values()) / len(per_query)
    macro_ndcg = sum(row["ndcg_at_k"] for row in per_query.values()) / len(per_query)
    passing = macro_recall >= min_recall and macro_mrr >= min_recall
    return {"status": "LOCAL_SIGNED_RELEVANCE_GATE_PASS" if passing
            else "LOCAL_SIGNED_RELEVANCE_GATE_FAIL",
            "model_identifier": embeddings["model"],
            "genuine_source_digest_count": len(sources),
            "top_k": top_k, "minimum_recall": min_recall,
            "real_cosine_queries": len(queries), "document_vectors": len(documents),
            "macro_recall_at_k": macro_recall, "macro_mrr": macro_mrr,
            "macro_ndcg_at_k": macro_ndcg, "per_query": per_query,
            "separate_local_annotation_key": True,
            "externally_independent_labels_attested": False,
            "model_semantic_generalization_proven": False,
            "source_code_executed": False}


def real_duckdb_module():
    """Require the actual native DuckDB engine; never fake with SQLite."""
    try:
        engine = importlib.import_module("duckdb")
        native_spec = importlib.util.find_spec("_duckdb")
    except (ImportError, ValueError):
        return None
    if (native_spec is None or not native_spec.origin or
            not native_spec.origin.endswith((".so", ".pyd")) or
            not hasattr(engine, "connect") or not hasattr(engine, "__version__")):
        return None
    return engine


def _historical_events(events):
    if type(events) is not list or not 1 <= len(events) <= MAX_EXPERIMENTS:
        raise ValueError("invalid_historical_event_count")
    validated = []
    seen = set()
    for item in events:
        if (type(item) is not dict or set(item) != {"run_id", "python_minor",
                                                  "candidate_id", "duration_ms",
                                                  "rss_kib", "status", "sha256"}):
            raise ValueError("invalid_historical_event_schema")
        if (type(item["run_id"]) is not str or not item["run_id"] or
                len(item["run_id"]) > 80 or item["run_id"] in seen or
                type(item["python_minor"]) is not str or
                not re.fullmatch(r"3\.(?:9|1[0-9]|[2-9][0-9])", item["python_minor"]) or
                type(item["candidate_id"]) is not str or
                not SYNTAX_ID.fullmatch(item["candidate_id"]) or
                type(item["duration_ms"]) not in (int, float) or
                not math.isfinite(item["duration_ms"]) or
                not 0 <= item["duration_ms"] <= 60_000 or
                type(item["rss_kib"]) is not int or
                not 0 <= item["rss_kib"] <= 1_000_000_000 or
                item["status"] not in ("PASS", "FAIL", "NOT_RUN") or
                type(item["sha256"]) is not str or
                not SHA256.fullmatch(item["sha256"])):
            raise ValueError("invalid_historical_event_value")
        seen.add(item["run_id"])
        validated.append((item["run_id"], item["python_minor"],
                          item["candidate_id"], float(item["duration_ms"]),
                          item["rss_kib"], item["status"], item["sha256"]))
    return validated


def analytical_duckdb_history(path, events, expected_sha256, repeat_queries=5):
    """Real DuckDB SQL group-by, quantile, persistence and independent checks."""
    engine = real_duckdb_module()
    if engine is None:
        return {"status": "NOT_RUN_NATIVE_DUCKDB_UNAVAILABLE",
                "actual_duckdb_sql_executed": False}
    if (type(expected_sha256) is not str or not SHA256.fullmatch(expected_sha256)
            or _sha(_json_bytes(events)) != expected_sha256):
        raise ValueError("historical_events_sha256_pin_failed")
    rows = _historical_events(events)
    if type(repeat_queries) is not int or not 1 <= repeat_queries <= 9:
        raise ValueError("invalid_analytical_benchmark_repeat_count")
    path = Path(path)
    if (path.is_symlink() or not path.parent.is_dir() or
            (path.exists() and not path.is_file())):
        raise ValueError("unsafe_analytical_db_path")
    connection = engine.connect(str(path))
    measurements = []
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS experimental_runs(" 
                           "run_id VARCHAR PRIMARY KEY,python_minor VARCHAR,"
                           "candidate_id VARCHAR,duration_ms DOUBLE,rss_kib BIGINT,"
                           "status VARCHAR,source_sha256 VARCHAR)")
        connection.execute("BEGIN TRANSACTION")
        try:
            connection.executemany("INSERT INTO experimental_runs VALUES(?,?,?,?,?,?,?)",
                                   rows)
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
        query = ("SELECT python_minor,candidate_id,count(*) AS runs,"
                 "sum(CASE WHEN status='PASS' THEN 1 ELSE 0 END) AS passed,"
                 "max(rss_kib) AS peak_rss,"
                 "quantile_cont(duration_ms,0.95) AS p95_ms "
                 "FROM experimental_runs GROUP BY python_minor,candidate_id "
                 "ORDER BY python_minor,candidate_id")
        for _ in range(repeat_queries):
            start = time.perf_counter_ns()
            result = connection.execute(query).fetchall()
            measurements.append((time.perf_counter_ns()-start) / 1e6)
        count = connection.execute("SELECT count(*) FROM experimental_runs").fetchone()[0]
        if count != len(rows):
            raise ValueError("duckdb_persisted_row_count_mismatch")
        return {"status": "REAL_NATIVE_DUCKDB_ANALYTICS_MEASURED",
                "duckdb_version": engine.__version__,
                "actual_duckdb_sql_executed": True,
                "historical_rows": count, "historical_groups": len(result),
                "aggregate_rows": [{"python_minor": r[0], "candidate_id": r[1],
                                    "runs": r[2], "passed": r[3],
                                    "rss_peak_kib": r[4], "latency_p95_ms": r[5]}
                                   for r in result],
                "independent_query_rounds": len(measurements),
                "query_timings_ms": measurements,
                "p95_query_ms": sorted(measurements)[math.ceil(.95*len(measurements))-1],
                "event_pin_sha256": expected_sha256,
                "database_file_exists": path.is_file(),
                "unknown_code_executed": False}
    finally:
        connection.close()


def million_corpus_preflight(source_chunks, minimum_unique=1_000_000):
    """Reject fake million-document claims when source proof is insufficient."""
    if type(minimum_unique) is not int or minimum_unique < 1_000_000:
        raise ValueError("million_corpus_threshold_may_not_be_lowered")
    if type(source_chunks) is not list or len(source_chunks) > 1_500_000:
        raise ValueError("invalid_document_corpus")
    seen = set()
    duplicates = 0
    for item in source_chunks:
        if (type(item) is not dict or set(item) != {"source_uri", "source_sha256",
                                                  "document_id", "content"} or
                type(item["source_uri"]) is not str or not item["source_uri"] or
                type(item["document_id"]) is not str or not item["document_id"] or
                type(item["content"]) is not str or
                not 15 <= len(item["content"]) <= 1024 or
                type(item["source_sha256"]) is not str or
                not SHA256.fullmatch(item["source_sha256"])):
            raise ValueError("invalid_real_corpus_provenance")
        key = (item["source_uri"], item["source_sha256"],
               item["document_id"], item["content"])
        if key in seen:
            duplicates += 1
        else:
            seen.add(key)
    verified_scale = len(seen) >= minimum_unique
    return {"status": "REAL_MILLION_SCALE_INPUT_READY" if verified_scale else
            "NOT_RUN_INSUFFICIENT_REPRESENTATIVE_REAL_DOC_CHUNKS",
            "raw_chunks": len(source_chunks), "distinct_provenance_chunks": len(seen),
            "duplicate_chunks": duplicates, "required_minimum": minimum_unique,
            "million_document_fts_measurement_executed": False,
            "real_source_publisher_attested": False}


def _safe_manifest_file(path):
    target = Path(path)
    meta = target.lstat()
    if (target.is_symlink() or not stat.S_ISREG(meta.st_mode) or
            meta.st_nlink != 1 or not 1 <= meta.st_size <= 131072):
        raise ValueError("invalid_pinned_manifest_file")
    raw = target.read_bytes()
    after = target.stat()
    if (len(raw) != meta.st_size or meta.st_ino != after.st_ino or
            meta.st_size != after.st_size or meta.st_mtime_ns != after.st_mtime_ns):
        raise ValueError("pinned_manifest_changed_during_read")
    try:
        decoded = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("pinned_manifest_is_not_json") from exc
    return decoded


def main(argv=None):
    """Read-only JSON capabilities; explicit manifest-pinned SQLite mutation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "native", "syntax-migrate", "million-benchmark"),
                        default="capabilities")
    parser.add_argument("--db")
    parser.add_argument("--manifest")
    parser.add_argument("--sha256")
    parser.add_argument("--iterations", type=int, default=100)
    args = parser.parse_args(argv)
    if args.mode == "capabilities":
        engine = real_duckdb_module()
        report = {"status": "KNOWLEDGE_SCALE_BOUNDED_CAPABILITIES_ONLY",
                  "python_minor": "{}.{}".format(*sys.version_info[:2]),
                  "native_duckdb_available": engine is not None,
                  "native_duckdb_version": getattr(engine, "__version__", None),
                  "available_modes": ["native", "syntax-migrate", "million-benchmark"],
                  "unknown_code_executed": False,
                  "external_network_called": False,
                  "million_document_benchmark_proven": False}
    elif args.mode == "native":
        report = native_api_inventory()
        report.pop("native_symbols")  # Bounded CLI response; full data API remains.
    elif args.mode == "million-benchmark":
        if not args.db or not args.manifest or not args.sha256:
            parser.error("million-benchmark requires --db --manifest --sha256")
        helper = globals().get("_RPH_CORPUS_SCALE")
        if helper is None:
            location = Path(__file__).with_name("corpus_scale_v031.py")
            spec = importlib.util.spec_from_file_location("rph_fixed_corpus_scale", location)
            helper = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(helper)
        report = helper.benchmark_existing(args.db, args.manifest, args.sha256,
                                           iterations=args.iterations)
    else:
        if not args.db or not args.manifest or not args.sha256:
            parser.error("syntax-migrate requires --db --manifest --sha256")
        target = Path(args.db)
        if (target.is_symlink() or target.parent.is_symlink() or
                not target.parent.is_dir() or
                (target.exists() and (not target.is_file() or
                                      target.stat().st_nlink != 1 or
                                      target.stat().st_size > 128 * 1024 * 1024))):
            parser.error("unsafe_syntax_database_path")
        examples = _safe_manifest_file(args.manifest)
        with closing(sqlite3.connect(str(target), isolation_level=None, timeout=3)) as conn:
            report = migrate_syntax_schema(conn, examples, args.sha256)
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
