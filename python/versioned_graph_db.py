"""Version-bound, read-only-in-source SQLite dependency/callgraph registry.

This registry stores *declared* or *possible static* relationships. It never
imports a package, executes user source or attests that an edge is true.
All retrieved links and hashes are unverified source data, not instructions.
"""

import argparse
from collections import deque
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import stat
from urllib.parse import urlsplit, unquote


SCHEMA_VERSION = 1
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_NODES = 5000
MAX_EDGES = 20000
MAX_TRAVERSAL = 128
MAX_DEPTH = 8
SAFE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]{0,159}\Z")
SAFE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+!~-]{0,99}\Z")
PY_MINOR = re.compile(r"3\.(?:9|1[0-9]|[2-9][0-9])\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
IDENT = re.compile(r"[0-9a-f]{64}\Z")
HOST = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\Z")
NODE_KINDS = frozenset(("FUNCTION", "MODULE", "PACKAGE", "API"))
RELATIONS = frozenset(("CALLS", "IMPORTS", "DEPENDS_ON", "USES_API"))
CONFIDENCE = frozenset(("POSSIBLE_STATIC_NOT_VERIFIED", "DECLARED_NOT_VERIFIED"))


def source_uri(uri):
    """Only leak-free HTTPS reference links; no remote fetch is performed."""
    if not isinstance(uri, str) or not uri or len(uri) > 768 or "\x00" in uri:
        raise ValueError("invalid_source_uri")
    parsed = urlsplit(uri)
    host = parsed.hostname or ""
    if (parsed.scheme != "https" or not HOST.fullmatch(host) or
            parsed.username is not None or parsed.password is not None or
            parsed.port is not None or parsed.query or parsed.fragment or
            parsed.netloc != host or
            any(part == ".." for part in unquote(parsed.path).split("/")) or
            any(char in uri for char in " \r\n\t<>\"'\\")):
        raise ValueError("unsafe_source_uri")
    return uri


def node_record(kind, name, version, python_minor, uri, source_sha256):
    """Validate normalized node identity and untrusted source metadata."""
    if kind not in NODE_KINDS:
        raise ValueError("invalid_node_kind")
    if not isinstance(name, str) or not SAFE_NAME.fullmatch(name):
        raise ValueError("invalid_node_name")
    if not isinstance(version, str) or not SAFE_VERSION.fullmatch(version):
        raise ValueError("invalid_node_version")
    if not isinstance(python_minor, str) or not PY_MINOR.fullmatch(python_minor):
        raise ValueError("invalid_python_minor")
    if not isinstance(source_sha256, str) or not SHA256.fullmatch(source_sha256):
        raise ValueError("invalid_source_sha256")
    uri = source_uri(uri)
    identity = json.dumps([kind, name, version, python_minor],
                          separators=(",", ":"), ensure_ascii=True)
    return {"node_id": hashlib.sha256(identity.encode("ascii")).hexdigest(),
            "kind": kind, "name": name, "version": version,
            "python_minor": python_minor, "source_uri": uri,
            "source_sha256": source_sha256,
            "provenance": "DECLARED_SOURCE_NOT_VERIFIED"}


def edge_record(from_id, to_id, relation, python_minor, evidence_uri,
                evidence_sha256, confidence):
    if any(not isinstance(value, str) or not IDENT.fullmatch(value)
           for value in (from_id, to_id)):
        raise ValueError("invalid_node_id")
    if relation not in RELATIONS or confidence not in CONFIDENCE:
        raise ValueError("unsupported_relation_or_confidence")
    if not isinstance(python_minor, str) or not PY_MINOR.fullmatch(python_minor):
        raise ValueError("invalid_python_minor")
    if not isinstance(evidence_sha256, str) or not SHA256.fullmatch(evidence_sha256):
        raise ValueError("invalid_evidence_sha256")
    evidence_uri = source_uri(evidence_uri)
    identity = json.dumps([from_id, to_id, relation, python_minor,
                           evidence_uri, evidence_sha256, confidence],
                          separators=(",", ":"))
    return {"edge_id": hashlib.sha256(identity.encode("ascii")).hexdigest(),
            "from_id": from_id, "to_id": to_id,
            "relation": relation, "python_minor": python_minor,
            "evidence_uri": evidence_uri, "evidence_sha256": evidence_sha256,
            "confidence": confidence}


def database(path):
    """Reject suspicious DB files; still no OS sandbox/TOCTOU guarantee."""
    path = Path(path)
    if (path.is_symlink() or not path.parent.is_dir() or
            path.parent.is_symlink()):
        raise ValueError("unsafe_graph_database_path")
    try:
        info = path.stat()
    except FileNotFoundError:
        info = None
    if info is not None and (
            not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_size > MAX_FILE_BYTES):
        raise ValueError("graph_database_not_regular_unique_bounded_file")
    conn = sqlite3.connect(str(path), timeout=3.0, isolation_level=None)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 3000")
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise ValueError("unknown_future_graph_schema")
        if version not in (0, SCHEMA_VERSION):
            raise ValueError("unsupported_graph_schema_migration")
        conn.execute("PRAGMA journal_mode = WAL")
        if version == 0:
            try:
                conn.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE IF NOT EXISTS graph_nodes(
                        node_id TEXT PRIMARY KEY, kind TEXT NOT NULL,
                        name TEXT NOT NULL, version TEXT NOT NULL,
                        python_minor TEXT NOT NULL, source_uri TEXT NOT NULL,
                        source_sha256 TEXT NOT NULL, provenance TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS graph_edges(
                        edge_id TEXT PRIMARY KEY,
                        from_id TEXT NOT NULL REFERENCES graph_nodes(node_id) ON DELETE CASCADE,
                        to_id TEXT NOT NULL REFERENCES graph_nodes(node_id) ON DELETE CASCADE,
                        relation TEXT NOT NULL, python_minor TEXT NOT NULL,
                        evidence_uri TEXT NOT NULL, evidence_sha256 TEXT NOT NULL,
                        confidence TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_graph_source_version
                        ON graph_edges(from_id, python_minor, relation, to_id);
                    CREATE INDEX IF NOT EXISTS idx_graph_names_version
                        ON graph_nodes(name, python_minor, version);
                    CREATE TRIGGER IF NOT EXISTS graph_restrict_version BEFORE INSERT
                        ON graph_edges BEGIN
                        SELECT RAISE(ABORT, 'node_version_mismatch')
                        WHERE (SELECT python_minor FROM graph_nodes WHERE node_id=NEW.from_id)
                           != NEW.python_minor
                           OR (SELECT python_minor FROM graph_nodes WHERE node_id=NEW.to_id)
                           != NEW.python_minor;
                    END;
                    PRAGMA user_version = 1;
                    COMMIT;
                """)
            except Exception:
                conn.rollback()
                raise
        expected = {
            "graph_nodes": ("node_id", "kind", "name", "version", "python_minor",
                            "source_uri", "source_sha256", "provenance"),
            "graph_edges": ("edge_id", "from_id", "to_id", "relation",
                            "python_minor", "evidence_uri", "evidence_sha256", "confidence"),
        }
        for table, names in expected.items():
            columns = tuple(row[1] for row in conn.execute("PRAGMA table_info({})".format(table)))
            if columns != names:
                raise ValueError("invalid_graph_schema")
        foreign_keys = conn.execute("PRAGMA foreign_key_list(graph_edges)").fetchall()
        relationships = {(row[3], row[2], row[4], row[6]) for row in foreign_keys}
        if relationships != {
                ("from_id", "graph_nodes", "node_id", "CASCADE"),
                ("to_id", "graph_nodes", "node_id", "CASCADE")}:
            raise ValueError("invalid_graph_foreign_key_schema")
        trigger = conn.execute("SELECT sql FROM sqlite_master WHERE type='trigger' "
                               "AND name='graph_restrict_version'").fetchone()
        if (trigger is None or not isinstance(trigger[0], str) or
                not all(term in trigger[0].lower() for term in (
                    "new.from_id", "new.to_id", "new.python_minor",
                    "raise(abort", "node_version_mismatch"))):
            raise ValueError("missing_graph_version_trigger")
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        conn.close()
        raise


def store_node(conn, kind, name, version, python_minor, uri, source_sha256):
    record = node_record(kind, name, version, python_minor, uri, source_sha256)
    columns = tuple(record)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        old = conn.execute("SELECT * FROM graph_nodes WHERE node_id=?",
                           (record["node_id"],)).fetchone()
        if old is not None:
            if any(old[col] != record[col] for col in columns):
                raise ValueError("conflicting_node_identity")
            status = "ALREADY_RECORDED_NOT_VERIFIED"
        else:
            count = conn.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0]
            if count >= MAX_NODES:
                raise ValueError("graph_node_capacity_limit")
            conn.execute("INSERT INTO graph_nodes VALUES (?,?,?,?,?,?,?,?)",
                         tuple(record.values()))
            status = "RECORDED_NOT_VERIFIED"
    return {"status": status, "node_id": record["node_id"],
            "python_minor": python_minor, "source_executed": False}


def store_edge(conn, from_id, to_id, relation, python_minor,
               evidence_uri, evidence_sha256, confidence):
    record = edge_record(from_id, to_id, relation, python_minor,
                         evidence_uri, evidence_sha256, confidence)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        old = conn.execute("SELECT * FROM graph_edges WHERE edge_id=?",
                           (record["edge_id"],)).fetchone()
        associated = conn.execute(
            "SELECT node_id, python_minor FROM graph_nodes WHERE node_id IN (?,?)",
            (from_id, to_id)).fetchall()
        if (len({row["node_id"] for row in associated}) != len({from_id, to_id}) or
                any(row["python_minor"] != python_minor for row in associated)):
            raise ValueError("invalid_edge_foreign_key_or_version")
        if old is not None:
            if any(old[col] != record[col] for col in record):
                raise ValueError("conflicting_edge_identity")
            status = "ALREADY_RECORDED_NOT_VERIFIED"
        else:
            count = conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0]
            if count >= MAX_EDGES:
                raise ValueError("graph_edge_capacity_limit")
            try:
                conn.execute("INSERT INTO graph_edges VALUES (?,?,?,?,?,?,?,?)",
                             tuple(record.values()))
            except sqlite3.IntegrityError as exc:
                raise ValueError("invalid_edge_foreign_key_or_version") from exc
            status = "RECORDED_NOT_VERIFIED"
    return {"status": status, "edge_id": record["edge_id"],
            "python_minor": python_minor, "edge_verified": False,
            "source_executed": False}


def remove_node(conn, node_id):
    if not isinstance(node_id, str) or not IDENT.fullmatch(node_id):
        raise ValueError("invalid_node_id")
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        count = conn.execute("DELETE FROM graph_nodes WHERE node_id=?", (node_id,)).rowcount
    return {"status": "REMOVED" if count else "NOT_FOUND", "node_id": node_id,
            "source_executed": False}


def remove_edge(conn, edge_id):
    if not isinstance(edge_id, str) or not IDENT.fullmatch(edge_id):
        raise ValueError("invalid_edge_id")
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        count = conn.execute("DELETE FROM graph_edges WHERE edge_id=?", (edge_id,)).rowcount
    return {"status": "REMOVED" if count else "NOT_FOUND", "edge_id": edge_id,
            "source_executed": False}


def inspect(conn):
    """Audit foreign keys and structural integrity, not link authenticity."""
    problems = conn.execute("PRAGMA foreign_key_check").fetchall()
    integrity = conn.execute("PRAGMA quick_check(1)").fetchone()[0]
    mismatches = conn.execute("""
        SELECT COUNT(*) FROM graph_edges e JOIN graph_nodes a ON a.node_id=e.from_id
        JOIN graph_nodes b ON b.node_id=e.to_id
        WHERE a.python_minor != e.python_minor OR b.python_minor != e.python_minor
    """).fetchone()[0]
    nodes = conn.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0]
    edges = conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0]
    bad_identifiers = 0
    for row in conn.execute("SELECT * FROM graph_nodes"):
        try:
            expected = node_record(row["kind"], row["name"], row["version"],
                                   row["python_minor"], row["source_uri"],
                                   row["source_sha256"])
            if (row["node_id"] != expected["node_id"] or
                    row["provenance"] != expected["provenance"]):
                bad_identifiers += 1
        except (ValueError, TypeError):
            bad_identifiers += 1
    for row in conn.execute("SELECT * FROM graph_edges"):
        try:
            expected = edge_record(row["from_id"], row["to_id"], row["relation"],
                                   row["python_minor"], row["evidence_uri"],
                                   row["evidence_sha256"], row["confidence"])
            if row["edge_id"] != expected["edge_id"]:
                bad_identifiers += 1
        except (ValueError, TypeError):
            bad_identifiers += 1
    good = not problems and integrity == "ok" and not mismatches and not bad_identifiers
    return {"status": "STRUCTURALLY_INTACT_UNVERIFIED" if good else "INVALID",
            "schema_version": SCHEMA_VERSION, "nodes": nodes, "edges": edges,
            "foreign_key_violations": len(problems), "version_mismatches": mismatches,
            "invalid_identity_records": bad_identifiers,
            "sqlite_integrity": "PASS" if integrity == "ok" else "FAIL",
            "edge_claims_verified": False, "publisher_verified": False,
            "source_executed": False}


def traverse(conn, start_id, python_minor, relation=None, max_depth=4, limit=64):
    """Bounded cycle-aware graph traversal filtered by the exact CPython minor."""
    if not isinstance(start_id, str) or not IDENT.fullmatch(start_id):
        raise ValueError("invalid_node_id")
    if not isinstance(python_minor, str) or not PY_MINOR.fullmatch(python_minor):
        raise ValueError("invalid_python_minor")
    if relation is not None and relation not in RELATIONS:
        raise ValueError("invalid_relation_filter")
    if (type(max_depth) is not int or not 0 <= max_depth <= MAX_DEPTH or
            type(limit) is not int or not 1 <= limit <= MAX_TRAVERSAL):
        raise ValueError("invalid_graph_traversal_budget")
    start = conn.execute("SELECT * FROM graph_nodes WHERE node_id=? AND python_minor=?",
                         (start_id, python_minor)).fetchone()
    if start is None:
        return {"status": "NOT_FOUND", "nodes": [], "edges": [],
                "edge_claims_verified": False, "source_executed": False}
    nodes = {start_id: dict(start)}
    edges = []
    queue = deque([(start_id, (start_id,), 0)])
    visited = {start_id}
    cycle_edges = 0
    truncated = False
    while queue:
        current, path, depth = queue.popleft()
        parameters = [current, python_minor]
        sql = ("SELECT e.*, n.kind, n.name, n.version, n.source_uri, "
               "n.source_sha256, n.provenance FROM graph_edges e "
               "JOIN graph_nodes n ON n.node_id=e.to_id "
               "WHERE e.from_id=? AND e.python_minor=?")
        if relation is not None:
            sql += " AND e.relation=?"
            parameters.append(relation)
        sql += " ORDER BY e.relation, e.to_id, e.edge_id"
        for row in conn.execute(sql, parameters):
            if depth == max_depth or len(edges) >= limit:
                truncated = True
                continue
            edge = dict(row)
            nodes[edge["to_id"]] = {
                "node_id": edge["to_id"], "kind": edge["kind"],
                "name": edge["name"], "version": edge["version"],
                "python_minor": python_minor, "source_uri": edge["source_uri"],
                "source_sha256": edge["source_sha256"],
                "provenance": edge["provenance"]}
            edges.append({key: edge[key] for key in (
                "edge_id", "from_id", "to_id", "relation", "python_minor",
                "evidence_uri", "evidence_sha256", "confidence")})
            if edge["to_id"] in path:
                cycle_edges += 1
            if edge["to_id"] not in visited:
                visited.add(edge["to_id"])
                queue.append((edge["to_id"], path + (edge["to_id"],), depth + 1))
    return {"status": "TRUNCATED_UNVERIFIED" if truncated else "INSPECTED_UNVERIFIED",
            "python_minor": python_minor, "start_id": start_id,
            "nodes": sorted(nodes.values(), key=lambda item: item["node_id"]),
            "edges": edges, "cycle_edges_seen": cycle_edges,
            "edge_claims_verified": False, "source_links_authenticated": False,
            "source_executed": False, "limits": {"depth": max_depth, "edges": limit}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path)
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("init")
    node = subparsers.add_parser("add-node")
    node.add_argument("--kind", required=True)
    node.add_argument("--name", required=True)
    node.add_argument("--version", required=True)
    node.add_argument("--python-minor", required=True)
    node.add_argument("--source-uri", required=True)
    node.add_argument("--source-sha256", required=True)
    edge = subparsers.add_parser("add-edge")
    edge.add_argument("--from-id", required=True)
    edge.add_argument("--to-id", required=True)
    edge.add_argument("--relation", required=True)
    edge.add_argument("--python-minor", required=True)
    edge.add_argument("--evidence-uri", required=True)
    edge.add_argument("--evidence-sha256", required=True)
    edge.add_argument("--confidence", required=True)
    query = subparsers.add_parser("query")
    query.add_argument("--start-id", required=True)
    query.add_argument("--python-minor", required=True)
    query.add_argument("--relation")
    query.add_argument("--max-depth", type=int, default=4)
    query.add_argument("--limit", type=int, default=64)
    remove = subparsers.add_parser("remove-node")
    remove.add_argument("--node-id", required=True)
    remove = subparsers.add_parser("remove-edge")
    remove.add_argument("--edge-id", required=True)
    subparsers.add_parser("check")
    args = parser.parse_args()
    with closing(database(args.db)) as conn, conn:
        if args.action == "init" or args.action == "check":
            report = inspect(conn)
        elif args.action == "add-node":
            report = store_node(conn, args.kind, args.name, args.version, args.python_minor,
                                args.source_uri, args.source_sha256)
        elif args.action == "add-edge":
            report = store_edge(conn, args.from_id, args.to_id, args.relation,
                                args.python_minor, args.evidence_uri, args.evidence_sha256,
                                args.confidence)
        elif args.action == "query":
            report = traverse(conn, args.start_id, args.python_minor,
                              args.relation, args.max_depth, args.limit)
        elif args.action == "remove-node":
            report = remove_node(conn, args.node_id)
        elif args.action == "remove-edge":
            report = remove_edge(conn, args.edge_id)
        else:
            raise ValueError("unexpected_action")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
