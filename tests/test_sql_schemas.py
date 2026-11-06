"""Schema tests run against the exact SQL embedded in the Rust application."""

from pathlib import Path
import sqlite3
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SQLiteTests(unittest.TestCase):
    def test_fts_insert_update_delete(self):
        with tempfile.TemporaryDirectory() as folder:
            conn = sqlite3.connect(str(Path(folder) / "knowledge.sqlite"))
            conn.executescript((ROOT / "sql" / "knowledge.sql").read_text())
            conn.execute(
                "INSERT INTO documents(source,uri,title,package,version,"
                "python_constraint,content,sha256) VALUES(?,?,?,?,?,?,?,?)",
                ("python", "https://example.invalid", "Mapping", "stdlib", "3.12",
                 ">=3.12", "specialized mapping protocol", "abc"),
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM documents_fts WHERE documents_fts MATCH 'mapping'").fetchone()[0],
                1,
            )
            conn.execute("UPDATE documents SET content='fast sequence' WHERE id=1")
            self.assertEqual(
                conn.execute("SELECT count(*) FROM documents_fts WHERE documents_fts MATCH 'specialized'").fetchone()[0],
                0,
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM documents_fts WHERE documents_fts MATCH 'sequence'").fetchone()[0],
                1,
            )
            conn.execute("DELETE FROM documents WHERE id=1")
            self.assertEqual(
                conn.execute("SELECT count(*) FROM documents_fts WHERE documents_fts MATCH 'sequence'").fetchone()[0],
                0,
            )
            conn.close()

    def test_versioned_documents_are_distinct(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.executescript((ROOT / "sql" / "knowledge.sql").read_text())
        for version in ("1.0", "2.0"):
            conn.execute(
                "INSERT INTO documents(source,uri,title,package,version,"
                "python_constraint,content,sha256) VALUES(?,?,?,?,?,?,?,?)",
                ("pypi", "pkg://example", "Example", "example", version,
                 ">=3.9", "dependency information", version),
            )
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0], 2)

    def test_variant_deduplication(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.executescript((ROOT / "sql" / "ledger.sql").read_text())
        conn.execute(
            "INSERT INTO variants(id,code_sha256,config_sha256,engine) VALUES(?,?,?,?)",
            ("V-1", "sha1", "cfg1", "ruff-safe"),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO variants(id,code_sha256,config_sha256,engine) VALUES(?,?,?,?)",
                ("V-2", "sha1", "cfg1", "ruff-safe"),
            )


if __name__ == "__main__":
    unittest.main()
