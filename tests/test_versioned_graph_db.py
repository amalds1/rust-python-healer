"""Graph edge/version integrity fixtures; no package or user-code execution."""

from importlib.util import module_from_spec, spec_from_file_location
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("versioned_graph_db", ROOT / "python" / "versioned_graph_db.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)

SOURCE = "https://docs.python.org/3/library/ast.html"
SOURCE_HASH = hashlib.sha256(b"trusted-fixture-text").hexdigest()


class VersionedGraphDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "graph.sqlite"
        self.conn = module.database(self.db)
        self.addCleanup(self.conn.close)

    def node(self, name, minor="3.12", version="1.0"):
        return module.store_node(self.conn, "FUNCTION", name, version, minor,
                                 SOURCE, SOURCE_HASH)["node_id"]

    def edge(self, source, target, minor="3.12", relation="CALLS", confidence=None):
        return module.store_edge(self.conn, source, target, relation, minor, SOURCE,
                                 SOURCE_HASH, confidence or
                                 "POSSIBLE_STATIC_NOT_VERIFIED")

    def test_can_create_query_and_reopen_versioned_source_edges_without_executing_code(self):
        source = self.node("pkg.function")
        target = self.node("pkg.helper")
        edge = self.edge(source, target)
        report = module.traverse(self.conn, source, "3.12")
        self.assertEqual(report["status"], "INSPECTED_UNVERIFIED")
        self.assertEqual(len(report["nodes"]), 2)
        self.assertEqual(len(report["edges"]), 1)
        self.assertEqual(report["edges"][0]["edge_id"], edge["edge_id"])
        self.assertEqual(report["edges"][0]["confidence"],
                         "POSSIBLE_STATIC_NOT_VERIFIED")
        self.assertFalse(report["edge_claims_verified"])
        self.assertFalse(report["source_executed"])
        self.assertEqual(report["nodes"][0]["provenance"],
                         "DECLARED_SOURCE_NOT_VERIFIED")
        with closing(module.database(self.db)) as reopened:
            self.assertEqual(module.inspect(reopened)["nodes"], 2)
            self.assertEqual(module.inspect(reopened)["edges"], 1)
            self.assertEqual(module.traverse(reopened, source, "3.12")["edges"],
                             report["edges"])
        with self.assertRaises(sqlite3.ProgrammingError):
            reopened.execute("SELECT 1")
        self.conn.close()
        renamed = self.db.with_name("reopened-and-movable.sqlite")
        self.db.rename(renamed)
        with closing(module.database(renamed)) as verified:
            self.assertEqual(module.inspect(verified)["nodes"], 2)
            self.assertEqual(module.inspect(verified)["edges"], 1)
        renamed.rename(self.db)

    def test_versions_are_distinct_and_cross_version_edges_are_refused(self):
        old = self.node("pkg.function", minor="3.9")
        new = self.node("pkg.function", minor="3.12")
        self.assertNotEqual(old, new)
        self.assertEqual(module.traverse(self.conn, old, "3.12")["status"], "NOT_FOUND")
        with self.assertRaisesRegex(ValueError, "invalid_edge_foreign_key_or_version"):
            self.edge(old, new, minor="3.12")
        self.assertEqual(module.inspect(self.conn)["edges"], 0)
        self.assertEqual(module.inspect(self.conn)["sqlite_integrity"], "PASS")

    def test_idempotent_replay_is_not_retest_and_conflicting_identity_is_refused(self):
        self.node("pkg.function")
        replay = module.store_node(self.conn, "FUNCTION", "pkg.function", "1.0", "3.12",
                                   SOURCE, SOURCE_HASH)
        self.assertEqual(replay["status"], "ALREADY_RECORDED_NOT_VERIFIED")
        with self.assertRaisesRegex(ValueError, "conflicting_node_identity"):
            module.store_node(self.conn, "FUNCTION", "pkg.function", "1.0", "3.12",
                              SOURCE, hashlib.sha256(b"different").hexdigest())
        self.assertEqual(module.inspect(self.conn)["nodes"], 1)

    def test_edges_are_idempotent_but_conflicting_evidence_is_not_silent(self):
        source, target = self.node("pkg.source"), self.node("pkg.target")
        recorded = self.edge(source, target)
        self.assertEqual(self.edge(source, target)["status"],
                         "ALREADY_RECORDED_NOT_VERIFIED")
        changed_hash = hashlib.sha256(b"another-evidence").hexdigest()
        module.store_edge(self.conn, source, target, "CALLS", "3.12", SOURCE,
                          changed_hash, "POSSIBLE_STATIC_NOT_VERIFIED")
        self.assertEqual(module.inspect(self.conn)["edges"], 2)
        self.assertNotEqual(recorded["edge_id"],
                            module.edge_record(source, target, "CALLS", "3.12", SOURCE,
                                               changed_hash,
                                               "POSSIBLE_STATIC_NOT_VERIFIED")["edge_id"])

    def test_cycle_aware_bounded_traversal_never_loops_forever(self):
        a, b, c = [self.node("pkg." + suffix) for suffix in ("a", "b", "c")]
        self.edge(a, b)
        self.edge(b, c)
        self.edge(c, a)
        report = module.traverse(self.conn, a, "3.12", max_depth=4, limit=8)
        self.assertEqual(report["status"], "INSPECTED_UNVERIFIED")
        self.assertEqual(report["cycle_edges_seen"], 1)
        self.assertEqual(len(report["edges"]), 3)
        short = module.traverse(self.conn, a, "3.12", max_depth=1)
        self.assertEqual(short["status"], "TRUNCATED_UNVERIFIED")
        self.assertEqual(len(short["edges"]), 1)
        capped = module.traverse(self.conn, a, "3.12", limit=1)
        self.assertEqual(capped["status"], "TRUNCATED_UNVERIFIED")

    def test_relation_filter_is_explicit_and_unverified(self):
        a, b, c = [self.node("pkg." + suffix) for suffix in ("a", "b", "c")]
        self.edge(a, b, relation="CALLS")
        self.edge(a, c, relation="IMPORTS")
        selected = module.traverse(self.conn, a, "3.12", relation="CALLS")
        self.assertEqual(len(selected["edges"]), 1)
        self.assertEqual(selected["edges"][0]["relation"], "CALLS")
        self.assertFalse(selected["source_links_authenticated"])

    def test_versioned_api_provenance_graph_has_exact_source_links_and_hashes(self):
        function = self.node("pkg.call_api", minor="3.14", version="2.1")
        api = module.store_node(self.conn, "API", "library.JSONEncoder", "3.14",
                                "3.14", SOURCE, SOURCE_HASH)["node_id"]
        edge = module.store_edge(self.conn, function, api, "USES_API", "3.14",
                                 SOURCE, SOURCE_HASH, "DECLARED_NOT_VERIFIED")
        report = module.traverse(self.conn, function, "3.14", relation="USES_API")
        self.assertEqual(report["status"], "INSPECTED_UNVERIFIED")
        self.assertEqual(len(report["edges"]), 1)
        self.assertEqual(report["edges"][0]["edge_id"], edge["edge_id"])
        self.assertEqual(report["edges"][0]["evidence_sha256"], SOURCE_HASH)
        self.assertEqual(report["edges"][0]["evidence_uri"], SOURCE)
        referenced = [x for x in report["nodes"] if x["kind"] == "API"]
        self.assertEqual(len(referenced), 1)
        self.assertEqual(referenced[0]["source_uri"], SOURCE)
        self.assertEqual(referenced[0]["source_sha256"], SOURCE_HASH)
        self.assertFalse(report["source_links_authenticated"])
        self.assertFalse(report["edge_claims_verified"])
        self.assertEqual(module.traverse(self.conn, function, "3.13")["status"],
                         "NOT_FOUND")

    def test_sql_injection_and_private_source_url_are_rejected(self):
        for malicious_name in ("x'); DROP TABLE graph_nodes;--", "pkg.\x00danger", "../pkg"):
            with self.assertRaises(ValueError):
                self.node(malicious_name)
        for malicious_uri in (
            "https://user:secret@docs.python.org/private",
            "https://docs.python.org/path?token=secret",
            "https://docs.python.org/a/%2e%2e/private",
            "http://docs.python.org/unsafe",
        ):
            with self.assertRaises(ValueError):
                module.store_node(self.conn, "FUNCTION", "pkg.name", "1.0", "3.12",
                                  malicious_uri, SOURCE_HASH)
        self.assertEqual(module.inspect(self.conn)["status"],
                         "STRUCTURALLY_INTACT_UNVERIFIED")
        self.assertEqual(module.inspect(self.conn)["nodes"], 0)

    def test_deleting_nodes_cascades_edges_without_touching_unrelated_nodes(self):
        a, b, c = [self.node("pkg." + suffix) for suffix in ("a", "b", "c")]
        self.edge(a, b)
        self.edge(b, c)
        result = module.remove_node(self.conn, b)
        self.assertEqual(result["status"], "REMOVED")
        self.assertEqual(module.inspect(self.conn)["nodes"], 2)
        self.assertEqual(module.inspect(self.conn)["edges"], 0)
        self.assertEqual(module.remove_node(self.conn, b)["status"], "NOT_FOUND")
        self.assertEqual(module.traverse(self.conn, a, "3.12")["status"],
                         "INSPECTED_UNVERIFIED")

    def test_edge_delete_and_missing_rows_are_explicit(self):
        a, b = self.node("pkg.a"), self.node("pkg.b")
        edge_id = self.edge(a, b)["edge_id"]
        self.assertEqual(module.remove_edge(self.conn, edge_id)["status"], "REMOVED")
        self.assertEqual(module.remove_edge(self.conn, edge_id)["status"], "NOT_FOUND")
        self.assertEqual(module.inspect(self.conn)["edges"], 0)

    def test_foreign_key_failure_rolls_back_and_future_writes_can_proceed(self):
        a = self.node("pkg.a")
        unknown = "a" * 64
        with self.assertRaisesRegex(ValueError, "invalid_edge_foreign_key_or_version"):
            self.edge(a, unknown)
        b = self.node("pkg.b")
        self.edge(a, b)
        self.assertEqual(module.inspect(self.conn)["edges"], 1)
        self.assertEqual(module.inspect(self.conn)["sqlite_integrity"], "PASS")

    def test_future_schema_and_malformed_schema_never_get_inspected_pass(self):
        future_path = Path(self.temp.name) / "future.sqlite"
        future_conn = sqlite3.connect(str(future_path))
        future_conn.execute("PRAGMA user_version=99")
        future_conn.close()
        with self.assertRaisesRegex(ValueError, "unknown_future_graph_schema"):
            module.database(future_path)
        check = sqlite3.connect(str(future_path))
        self.assertEqual(check.execute("PRAGMA user_version").fetchone()[0], 99)
        check.close()
        malformed_path = Path(self.temp.name) / "malformed.sqlite"
        malformed = sqlite3.connect(str(malformed_path))
        malformed.execute("CREATE TABLE graph_nodes(fake_col TEXT)")
        malformed.execute("PRAGMA user_version=1")
        malformed.close()
        with self.assertRaisesRegex(ValueError, "invalid_graph_schema"):
            module.database(malformed_path)
        weak_schema = Path(self.temp.name) / "weak.sqlite"
        fake = sqlite3.connect(str(weak_schema))
        fake.execute("CREATE TABLE graph_nodes(node_id TEXT, kind TEXT, name TEXT, "
                     "version TEXT, python_minor TEXT, source_uri TEXT, "
                     "source_sha256 TEXT, provenance TEXT)")
        fake.execute("CREATE TABLE graph_edges(edge_id TEXT, from_id TEXT, to_id TEXT, "
                     "relation TEXT, python_minor TEXT, evidence_uri TEXT, "
                     "evidence_sha256 TEXT, confidence TEXT)")
        fake.execute("PRAGMA user_version=1")
        fake.close()
        with self.assertRaisesRegex(ValueError, "invalid_graph_foreign_key_schema"):
            module.database(weak_schema)

    def test_tampered_sqlite_node_or_edge_metadata_never_gets_integrity_pass(self):
        a, b = self.node("pkg.a"), self.node("pkg.b")
        edge = self.edge(a, b)["edge_id"]
        self.assertEqual(module.inspect(self.conn)["invalid_identity_records"], 0)
        self.conn.execute("UPDATE graph_nodes SET name=? WHERE node_id=?",
                          ("tampered_without_rehash", b))
        report = module.inspect(self.conn)
        self.assertEqual(report["status"], "INVALID")
        self.assertEqual(report["invalid_identity_records"], 1)
        self.conn.execute("UPDATE graph_nodes SET name=? WHERE node_id=?", ("pkg.b", b))
        self.conn.execute("UPDATE graph_edges SET evidence_uri=? WHERE edge_id=?",
                          ("https://docs.python.org/3/other.html", edge))
        report = module.inspect(self.conn)
        self.assertEqual(report["status"], "INVALID")
        self.assertEqual(report["invalid_identity_records"], 1)
        # Even a self-consistent URI/hash pair would be unverified source data;
        # a local graph digest is not an external publisher attestation.
        self.assertFalse(report["publisher_verified"])

    def test_symlinks_and_hardlinks_to_database_are_refused(self):
        private = Path(self.temp.name) / "private.sqlite"
        sqlite3.connect(str(private)).close()
        symlink = Path(self.temp.name) / "symlink.sqlite"
        symlink.symlink_to(private)
        with self.assertRaisesRegex(ValueError, "unsafe_graph_database_path"):
            module.database(symlink)
        other = Path(self.temp.name) / "hardlink.sqlite"
        import os
        os.link(str(private), str(other))
        with self.assertRaisesRegex(ValueError, "graph_database_not_regular_unique_bounded_file"):
            module.database(private)

    def test_node_quota_has_no_false_pass_and_does_not_break_transaction(self):
        prior = module.MAX_NODES
        try:
            module.MAX_NODES = 2
            self.node("pkg.a")
            self.node("pkg.b")
            with self.assertRaisesRegex(ValueError, "graph_node_capacity_limit"):
                self.node("pkg.c")
        finally:
            module.MAX_NODES = prior
        self.assertEqual(module.inspect(self.conn)["nodes"], 2)

    def test_wal_two_connections_report_committed_graph_changes(self):
        secondary = module.database(self.db)
        self.addCleanup(secondary.close)
        a = self.node("pkg.first")
        self.assertEqual(module.inspect(secondary)["nodes"], 1)
        b = module.store_node(secondary, "FUNCTION", "pkg.second", "1.0", "3.12",
                              SOURCE, SOURCE_HASH)["node_id"]
        self.edge(a, b)
        self.assertEqual(module.inspect(secondary)["edges"], 1)
        self.assertEqual(module.traverse(secondary, a, "3.12")["edges"][0]["to_id"], b)

    def test_cli_roundtrip_readonly_no_source_execution(self):
        cli_db = Path(self.temp.name) / "cli.sqlite"
        helper = ROOT / "python" / "versioned_graph_db.py"
        init = subprocess.run([sys.executable, "-I", "-S", "-B", str(helper),
                               "--db", str(cli_db), "init"],
                              capture_output=True, text=True, check=False)
        self.assertEqual(init.returncode, 0, init.stderr)
        self.assertEqual(json.loads(init.stdout)["nodes"], 0)
        add = subprocess.run([sys.executable, "-I", "-S", "-B", str(helper),
                              "--db", str(cli_db), "add-node", "--kind", "MODULE",
                              "--name", "pkg.core", "--version", "1.0",
                              "--python-minor", "3.12", "--source-uri", SOURCE,
                              "--source-sha256", SOURCE_HASH],
                             capture_output=True, text=True, check=False)
        self.assertEqual(add.returncode, 0, add.stderr)
        self.assertEqual(json.loads(add.stdout)["status"], "RECORDED_NOT_VERIFIED")
        self.assertFalse(json.loads(add.stdout)["source_executed"])


if __name__ == "__main__":
    unittest.main()
