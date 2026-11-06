"""Offline, exact-cosine vector and SQLite FTS5 hybrid retrieval.

Vectors MUST be supplied by a trusted caller; this module neither computes
semantic embeddings nor executes/imports user code. Source URLs/hashes are
declared provenance, never publisher-authenticated. No ANN index is claimed.
"""

import argparse
from contextlib import closing
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import stat
import struct
from urllib.parse import unquote, urlsplit


SCHEMA_VERSION = 1
MAX_DB_BYTES = 1024 * 1024 * 1024
MAX_CHUNKS = 1_200_000
MAX_SCAN_CANDIDATES = 15_000
SAFE_PACKAGE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,95}\Z")
SAFE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+!~-]{0,79}\Z")
SAFE_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z")
SAFE_CHUNK = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z")
PY_MINOR = re.compile(r"3\.(?:9|1[0-9]|[2-9][0-9])\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HOST = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\Z")
TERM = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,47}")


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def require_match(value, pattern, name):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError("invalid_" + name)
    return value


def source_uri(value):
    if not isinstance(value, str) or len(value) > 768 or "\x00" in value:
        raise ValueError("invalid_source_uri")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname or ""
    except ValueError as exc:
        raise ValueError("invalid_source_uri") from exc
    if (parsed.scheme != "https" or not HOST.fullmatch(hostname) or
            parsed.username is not None or parsed.password is not None or
            parsed.netloc != hostname or parsed.query or parsed.fragment or
            parsed.port is not None or
            any(piece == ".." for piece in unquote(parsed.path).split("/")) or
            any(char in value for char in " \r\n\t<>\"'\\")):
        raise ValueError("unsafe_source_uri")
    return value


def partition_record(python_minor, package_name, package_version, dimension, model):
    require_match(python_minor, PY_MINOR, "python_minor")
    require_match(package_name, SAFE_PACKAGE, "package_name")
    require_match(package_version, SAFE_VERSION, "package_version")
    require_match(model, SAFE_MODEL, "model")
    if type(dimension) is not int or not 2 <= dimension <= 1024:
        raise ValueError("invalid_vector_dimension")
    identity = [python_minor, package_name, package_version]
    return {"partition_id": digest(identity), "python_minor": python_minor,
            "package_name": package_name, "package_version": package_version,
            "vector_dimension": dimension, "declared_vector_model": model}


def validated_vector(values, dimension):
    if not isinstance(values, (tuple, list)) or len(values) != dimension:
        raise ValueError("invalid_vector_dimension")
    if any(type(value) not in (int, float) or not math.isfinite(value) or
           abs(value) > 1_000_000 for value in values):
        raise ValueError("invalid_vector_coordinate")
    numeric = tuple(float(value) for value in values)
    norm = math.fsum(value * value for value in numeric)
    if norm <= 0 or not math.isfinite(norm):
        raise ValueError("zero_or_unbounded_vector")
    return struct.pack("<{}d".format(dimension), *numeric), norm


def unpack_vector(raw, dimension):
    if not isinstance(raw, bytes) or len(raw) != 8 * dimension:
        raise ValueError("corrupt_vector_binary")
    return struct.unpack("<{}d".format(dimension), raw)


def cosine(query_vector, other_vector, query_norm, other_norm):
    return max(-1.0, min(1.0, math.fsum(
        a * b for a, b in zip(query_vector, other_vector)) /
        math.sqrt(query_norm * other_norm)))


def database(path):
    """Open bounded SQLite file, validate schema/FTS, reject future migrations."""
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink() or not path.parent.is_dir():
        raise ValueError("unsafe_vector_database_path")
    try:
        info = path.stat()
    except FileNotFoundError:
        info = None
    if info is not None and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                            info.st_size > MAX_DB_BYTES):
        raise ValueError("vector_database_not_unique_bounded_file")
    conn = sqlite3.connect(str(path), timeout=5.0, isolation_level=None)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version != 0 and version != SCHEMA_VERSION:
            raise ValueError("future_or_unknown_vector_schema_refused")
        conn.execute("PRAGMA journal_mode=WAL")
        if version == 0:
            try:
                conn.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE partitions(
                      partition_id TEXT PRIMARY KEY, python_minor TEXT NOT NULL,
                      package_name TEXT NOT NULL, package_version TEXT NOT NULL,
                      vector_dimension INTEGER NOT NULL,
                      declared_vector_model TEXT NOT NULL,
                      UNIQUE(python_minor,package_name,package_version)
                    );
                    CREATE TABLE chunks(
                      rowid INTEGER PRIMARY KEY AUTOINCREMENT,
                      chunk_id TEXT NOT NULL UNIQUE,
                      partition_id TEXT NOT NULL REFERENCES partitions(partition_id),
                      chunk_key TEXT NOT NULL, content TEXT NOT NULL,
                      content_sha256 TEXT NOT NULL, source_uri TEXT NOT NULL,
                      source_sha256 TEXT NOT NULL,
                      UNIQUE(partition_id,chunk_key)
                    );
                    CREATE TABLE vector_index(
                      chunk_id TEXT PRIMARY KEY REFERENCES chunks(chunk_id) ON DELETE CASCADE,
                      partition_id TEXT NOT NULL REFERENCES partitions(partition_id),
                      vector BLOB NOT NULL, norm_sq REAL NOT NULL
                    );
                    CREATE INDEX chunks_partition_source ON chunks(
                      partition_id,source_uri,source_sha256,chunk_id);
                    CREATE INDEX vectors_partition ON vector_index(partition_id,chunk_id);
                    CREATE VIRTUAL TABLE chunks_fts USING fts5(
                      content,content='chunks',content_rowid='rowid');
                    CREATE TRIGGER chunks_ai AFTER INSERT ON chunks BEGIN
                      INSERT INTO chunks_fts(rowid,content) VALUES(new.rowid,new.content);
                    END;
                    CREATE TRIGGER chunks_ad AFTER DELETE ON chunks BEGIN
                      INSERT INTO chunks_fts(chunks_fts,rowid,content)
                      VALUES('delete',old.rowid,old.content);
                    END;
                    CREATE TRIGGER chunks_immutable_update BEFORE UPDATE ON chunks BEGIN
                      SELECT RAISE(ABORT,'immutable_source_chunk');
                    END;
                    CREATE TRIGGER partitions_immutable_update BEFORE UPDATE ON partitions BEGIN
                      SELECT RAISE(ABORT,'immutable_partition');
                    END;
                    CREATE TRIGGER vector_immutable_update BEFORE UPDATE ON vector_index BEGIN
                      SELECT RAISE(ABORT,'immutable_vector');
                    END;
                    CREATE TRIGGER vector_correct_partition BEFORE INSERT ON vector_index
                    BEGIN SELECT RAISE(ABORT,'vector_partition_mismatch') WHERE
                      (SELECT partition_id FROM chunks WHERE chunk_id=new.chunk_id)
                      != new.partition_id OR
                      length(new.vector) != 8*(SELECT vector_dimension FROM partitions
                      WHERE partition_id=new.partition_id); END;
                    PRAGMA user_version=1;
                    COMMIT;
                """)
            except Exception:
                conn.rollback()
                raise
        expected = {
            "partitions": ("partition_id", "python_minor", "package_name",
                           "package_version", "vector_dimension", "declared_vector_model"),
            "chunks": ("rowid", "chunk_id", "partition_id", "chunk_key", "content",
                       "content_sha256", "source_uri", "source_sha256"),
            "vector_index": ("chunk_id", "partition_id", "vector", "norm_sq"),
        }
        for table, columns in expected.items():
            found = tuple(row[1] for row in conn.execute(
                "PRAGMA table_info({})".format(table)))
            if found != columns:
                raise ValueError("invalid_vector_schema")
        fks = {table: {(row[3], row[2], row[4], row[6]) for row in conn.execute(
            "PRAGMA foreign_key_list({})".format(table))}
            for table in ("chunks", "vector_index")}
        if (fks["chunks"] != {("partition_id", "partitions", "partition_id", "NO ACTION")} or
                fks["vector_index"] != {
                    ("partition_id", "partitions", "partition_id", "NO ACTION"),
                    ("chunk_id", "chunks", "chunk_id", "CASCADE")}):
            raise ValueError("invalid_vector_foreign_keys")
        required = {"chunks_ai", "chunks_ad", "chunks_immutable_update",
                    "partitions_immutable_update", "vector_immutable_update",
                    "vector_correct_partition"}
        installed = {row[0]: row[1] for row in conn.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger'")}
        if not required.issubset(installed):
            raise ValueError("missing_fts_or_vector_triggers")
        for name in required:
            if not installed[name] or "BEGIN" not in installed[name].upper():
                raise ValueError("corrupted_fts_or_vector_trigger")
        fts = conn.execute("SELECT sql FROM sqlite_master WHERE name='chunks_fts' "
                           "AND type='table'").fetchone()
        if not fts or "USING fts5" not in fts[0]:
            raise ValueError("missing_fts5_virtual_table")
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        conn.close()
        raise


def register_partition(conn, python_minor, package_name, package_version,
                       dimension, model):
    record = partition_record(python_minor, package_name, package_version,
                              dimension, model)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        old = conn.execute("SELECT * FROM partitions WHERE partition_id=?",
                           (record["partition_id"],)).fetchone()
        if old is not None:
            if any(old[key] != value for key, value in record.items()):
                raise ValueError("immutable_vector_partition_conflict")
            status = "EXISTING_PARTITION"
        else:
            conn.execute("INSERT INTO partitions VALUES(?,?,?,?,?,?)",
                         tuple(record.values()))
            status = "PARTITION_REGISTERED"
    return {"status": status, "partition_id": record["partition_id"],
            "source_executed": False, "embedding_computed": False}


def _partition(conn, python_minor, package_name, package_version):
    canonical = partition_record(python_minor, package_name, package_version, 2, "probe")
    row = conn.execute("SELECT * FROM partitions WHERE partition_id=?",
                       (canonical["partition_id"],)).fetchone()
    if row is None:
        raise ValueError("unregistered_versioned_vector_partition")
    return row


def record_chunk(conn, python_minor, package_name, package_version, chunk_key,
                 content, source_url, source_sha256, vector):
    partition = _partition(conn, python_minor, package_name, package_version)
    require_match(chunk_key, SAFE_CHUNK, "chunk_key")
    source_uri(source_url)
    require_match(source_sha256, HEX64, "source_sha256")
    if (not isinstance(content, str) or not content or len(content) > 4096 or
            "\x00" in content or any(ord(ch) < 32 and ch not in "\n\r\t"
                                          for ch in content)):
        raise ValueError("invalid_chunk_content")
    vector_blob, norm_sq = validated_vector(vector, partition["vector_dimension"])
    chunk_id = digest([partition["partition_id"], chunk_key])
    record = (chunk_id, partition["partition_id"], chunk_key, content,
              hashlib.sha256(content.encode("utf-8")).hexdigest(),
              source_url, source_sha256)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        old = conn.execute("SELECT c.*,v.vector,v.norm_sq FROM chunks c LEFT JOIN "
                           "vector_index v ON v.chunk_id=c.chunk_id WHERE c.chunk_id=?",
                           (chunk_id,)).fetchone()
        if old is not None:
            checks = (("chunk_id", chunk_id), ("partition_id", partition["partition_id"]),
                      ("chunk_key", chunk_key), ("content", content),
                      ("content_sha256", record[4]), ("source_uri", source_url),
                      ("source_sha256", source_sha256), ("vector", vector_blob),
                      ("norm_sq", norm_sq))
            if any(old[key] != value for key, value in checks):
                raise ValueError("conflicting_immutable_vector_chunk")
            status = "ALREADY_RECORDED_NO_REEMBEDDING"
        else:
            if conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0] >= MAX_CHUNKS:
                raise ValueError("vector_chunk_capacity_exceeded")
            conn.execute("INSERT INTO chunks(chunk_id,partition_id,chunk_key,content,"
                         "content_sha256,source_uri,source_sha256) VALUES(?,?,?,?,?,?,?)",
                         record)
            conn.execute("INSERT INTO vector_index VALUES(?,?,?,?)",
                         (chunk_id, partition["partition_id"], vector_blob, norm_sq))
            status = "CHUNK_VECTOR_RECORDED"
    return {"status": status, "chunk_id": chunk_id,
            "source_executed": False, "embedding_computed": False,
            "declared_source_not_authenticated": True}


def remove_chunk(conn, python_minor, package_name, package_version, chunk_key):
    partition = _partition(conn, python_minor, package_name, package_version)
    require_match(chunk_key, SAFE_CHUNK, "chunk_key")
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        deleted = conn.execute("DELETE FROM chunks WHERE partition_id=? AND chunk_key=?",
                               (partition["partition_id"], chunk_key)).rowcount
    return {"status": "REMOVED" if deleted else "NOT_FOUND",
            "source_executed": False, "vector_fts_synced_transactionally": True}


def _candidates(conn, partition, source_url, source_sha256):
    source_uri(source_url)
    require_match(source_sha256, HEX64, "source_sha256")
    found = conn.execute("""
        SELECT c.chunk_id,c.chunk_key,c.content,c.content_sha256,
               c.source_uri,c.source_sha256,v.vector,v.norm_sq
        FROM chunks c JOIN vector_index v ON v.chunk_id=c.chunk_id
        WHERE c.partition_id=? AND v.partition_id=? AND c.source_uri=?
          AND c.source_sha256=? ORDER BY c.chunk_id LIMIT ?
    """, (partition["partition_id"], partition["partition_id"],
          source_url, source_sha256, MAX_SCAN_CANDIDATES + 1)).fetchall()
    if len(found) > MAX_SCAN_CANDIDATES:
        raise ValueError("too_many_candidates_exact_scan_limit")
    return found


def _ranked_vectors(partition, vector, rows):
    raw, norm = validated_vector(vector, partition["vector_dimension"])
    query = unpack_vector(raw, partition["vector_dimension"])
    ranked = []
    for row in rows:
        other = unpack_vector(row["vector"], partition["vector_dimension"])
        expected_norm = math.fsum(value * value for value in other)
        if (not math.isfinite(row["norm_sq"]) or
                abs(expected_norm - row["norm_sq"]) > 1e-10 * expected_norm):
            raise ValueError("corrupted_vector_norm")
        similarity = cosine(query, other, norm, expected_norm)
        ranked.append((row, similarity))
    ranked.sort(key=lambda item: (-item[1], item[0]["chunk_id"]))
    return ranked


def _public_result(row, score, dense_rank, sparse_rank=None):
    return {"chunk_id": row["chunk_id"], "chunk_key": row["chunk_key"],
            "content": row["content"], "source_uri": row["source_uri"],
            "source_sha256": row["source_sha256"],
            "content_sha256": row["content_sha256"],
            "score": score, "vector_rank": dense_rank,
            "fts_rank": sparse_rank,
            "source_authenticated": False, "semantic_embedding_model_verified": False}


def search_vector(conn, python_minor, package_name, package_version,
                  source_url, source_sha256, query_vector, limit=10):
    if type(limit) is not int or not 1 <= limit <= 50:
        raise ValueError("invalid_vector_query_limit")
    partition = _partition(conn, python_minor, package_name, package_version)
    ranked = _ranked_vectors(partition, query_vector,
                             _candidates(conn, partition, source_url, source_sha256))
    return {"status": "EXACT_COSINE_WITH_HARD_SOURCE_VERSION_FILTERS_NO_ANN",
            "partition_id": partition["partition_id"],
            "declared_embedding_model": partition["declared_vector_model"],
            "matches": [_public_result(row, score, i + 1)
                        for i, (row, score) in enumerate(ranked[:limit])],
            "candidates_checked": len(ranked), "source_executed": False,
            "semantic_embedding_computed": False,
            "source_authenticated": False, "ann_used": False}


def _fts_terms(text):
    if not isinstance(text, str) or len(text) > 512 or "\x00" in text:
        raise ValueError("invalid_fts_query")
    tokens = TERM.findall(text)
    if not tokens or len(tokens) > 16:
        raise ValueError("invalid_fts_query_terms")
    # Phrase-quoted tokens passed through a SQL parameter, never FTS5 syntax.
    return " OR ".join('"{}"'.format(token) for token in tokens)


def search_hybrid(conn, python_minor, package_name, package_version,
                  source_url, source_sha256, query_text, query_vector, limit=10):
    if type(limit) is not int or not 1 <= limit <= 50:
        raise ValueError("invalid_hybrid_query_limit")
    partition = _partition(conn, python_minor, package_name, package_version)
    rows = _candidates(conn, partition, source_url, source_sha256)
    ranked = _ranked_vectors(partition, query_vector, rows)
    expression = _fts_terms(query_text)
    fts_rows = conn.execute("""
        SELECT c.chunk_id,bm25(chunks_fts) AS relevance
        FROM chunks_fts JOIN chunks c ON c.rowid=chunks_fts.rowid
        WHERE chunks_fts MATCH ? AND c.partition_id=?
          AND c.source_uri=? AND c.source_sha256=?
        ORDER BY relevance ASC,c.chunk_id ASC LIMIT ?
    """, (expression, partition["partition_id"], source_url,
          source_sha256, MAX_SCAN_CANDIDATES)).fetchall()
    sparse_ranks = {row["chunk_id"]: position + 1
                    for position, row in enumerate(fts_rows)}
    fused = []
    for index, (row, similarity) in enumerate(ranked):
        sparse_rank = sparse_ranks.get(row["chunk_id"])
        score = 1.0 / (60 + index + 1)
        if sparse_rank is not None:
            score += 1.0 / (60 + sparse_rank)
        fused.append((_public_result(row, score, index + 1, sparse_rank), similarity))
    fused.sort(key=lambda item: (-item[0]["score"], -item[1],
                                item[0]["chunk_id"]))
    return {"status": "HYBRID_FTS5_VECTOR_RRF_HARD_FILTERS_NOT_SEMANTIC_ATTESTATION",
            "partition_id": partition["partition_id"],
            "matches": [item[0] for item in fused[:limit]],
            "candidates_checked": len(ranked),
            "fts_matched": len(fts_rows), "source_executed": False,
            "semantic_embedding_computed": False,
            "source_authenticated": False, "ann_used": False,
            "reranker": "reciprocal_rank_fusion_k60"}


def inspect(conn):
    """Read-only structural and separation/sync integrity checks."""
    quick = conn.execute("PRAGMA quick_check(1)").fetchone()[0]
    foreign = conn.execute("PRAGMA foreign_key_check").fetchall()
    partitions = conn.execute("SELECT COUNT(*) FROM partitions").fetchone()[0]
    chunks = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
    vectors = conn.execute("SELECT COUNT(*) FROM vector_index").fetchone()[0]
    broken = conn.execute("""
        SELECT COUNT(*) FROM chunks c LEFT JOIN vector_index v ON v.chunk_id=c.chunk_id
          LEFT JOIN partitions p ON p.partition_id=c.partition_id
        WHERE v.chunk_id IS NULL OR v.partition_id != c.partition_id
          OR length(v.vector) != 8*p.vector_dimension
    """).fetchone()[0]
    # FTS5 integrity-check is a mutation; use a read-only count instead.
    fts_documents = conn.execute("SELECT COUNT(*) FROM chunks_fts").fetchone()[0]
    good = quick == "ok" and not foreign and not broken and chunks == vectors == fts_documents
    return {"status": "STRUCTURALLY_SYNCED_NOT_SEMANTICALLY_VALIDATED" if good
            else "INVALID", "partitions": partitions, "chunks": chunks,
            "vector_entries": vectors, "fts_rows": fts_documents,
            "missing_or_cross_partition_vectors": broken,
            "foreign_key_violations": len(foreign),
            "sqlite_quick_check": quick,
            "source_executed": False, "semantic_embeddings_generated": False,
            "publisher_sources_authenticated": False, "ann_available": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path)
    subs = parser.add_subparsers(dest="action", required=True)
    subs.add_parser("init")
    subs.add_parser("check")
    for name in ("partition", "put", "delete", "vector", "hybrid"):
        p = subs.add_parser(name)
        p.add_argument("--python-minor", required=True)
        p.add_argument("--package", required=True)
        p.add_argument("--package-version", required=True)
        if name == "partition":
            p.add_argument("--dimension", required=True, type=int)
            p.add_argument("--model", required=True)
        if name in ("put", "delete"):
            p.add_argument("--chunk", required=True)
        if name in ("put", "vector", "hybrid"):
            p.add_argument("--source-uri", required=True)
            p.add_argument("--source-sha256", required=True)
            p.add_argument("--vector", required=True,
                           help="JSON array of caller-supplied finite coordinates")
        if name == "put":
            p.add_argument("--content", required=True)
        if name == "hybrid":
            p.add_argument("--text", required=True)
        if name in ("vector", "hybrid"):
            p.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()
    with closing(database(args.db)) as conn:
        if args.action in ("init", "check"):
            report = inspect(conn)
        else:
            identity = (args.python_minor, args.package, args.package_version)
            if args.action == "partition":
                report = register_partition(conn, *identity, args.dimension, args.model)
            elif args.action == "delete":
                report = remove_chunk(conn, *identity, args.chunk)
            else:
                vector = json.loads(args.vector)
                if args.action == "put":
                    report = record_chunk(conn, *identity, args.chunk, args.content,
                                          args.source_uri, args.source_sha256, vector)
                elif args.action == "vector":
                    report = search_vector(conn, *identity, args.source_uri,
                                           args.source_sha256, vector, args.limit)
                else:
                    report = search_hybrid(conn, *identity, args.source_uri,
                                           args.source_sha256, args.text, vector, args.limit)
    print(json.dumps(report, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
