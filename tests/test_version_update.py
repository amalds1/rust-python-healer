"""Tests of the actual 100-case suite, compatibility matrix and updater."""

from importlib.util import module_from_spec, spec_from_file_location
from contextlib import contextmanager
from io import BytesIO
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def open_db(path):
    conn = sqlite3.connect(str(path))
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def load_module(name, path):
    spec = spec_from_file_location(name, path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


suite = load_module("version_suite", ROOT / "python" / "version_suite.py")
matrix_mod = load_module("compat_matrix", ROOT / "python" / "compat_matrix.py")
updater = load_module("knowledge_updater", ROOT / "python" / "knowledge_updater.py")


class VersionSuiteTests(unittest.TestCase):
    def test_exactly_100_distinct_cases(self):
        cases = suite.build_cases()
        self.assertEqual(len(cases), 100)
        self.assertEqual(len(set(x["id"] for x in cases)), 100)
        categories = {x["category"] for x in cases}
        self.assertEqual(len(categories), 5)

    def test_100_current_interpreter(self):
        result = suite.run_suite()
        self.assertEqual(result["cases"], 100)
        self.assertEqual(result["pass"], 100)
        self.assertEqual(result["fail"], 0)

    def test_matrix_no_false_pass_for_missing_interpreters(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest = Path(folder) / "versions.json"
            manifest.write_text(json.dumps({"minimum_python": "3.9",
                                            "latest_stable": "3.15.2"}))
            version = f"3.{sys.version_info.minor}"
            result = matrix_mod.matrix(ROOT / "python" / "verify.py", manifest,
                                       overrides={version: sys.executable},
                                       suite_path=ROOT / "python" / "version_suite.py")
            self.assertEqual(result["tests_planned"], 700)
            self.assertGreaterEqual(result["tests_pass"], 100)
            self.assertEqual(result["tests_executed"], result["tests_pass"] + result["tests_fail"])
            self.assertEqual(result["full_compatibility"], "NOT_VERIFIED")

    def test_version_labels_reject_invalid(self):
        for bad in ("3.8", "2.7", "3.15rc1", "abc", "3.100"):
            with self.assertRaises(ValueError):
                matrix_mod.parse_version(bad)

    def test_future_minor_requires_a_real_interpreter(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest = Path(folder) / "versions.json"
            manifest.write_text(json.dumps({"minimum_python": "3.9",
                                            "latest_stable": "3.16.0"}))
            label = f"3.{sys.version_info.minor}"
            result = matrix_mod.matrix(ROOT / "python" / "verify.py", manifest,
                                       overrides={label: sys.executable},
                                       suite_path=ROOT / "python" / "version_suite.py")
            self.assertEqual(result["tests_planned"], 800)
            future = next(row for row in result["results"] if row["version"] == "3.16")
            self.assertEqual(future["status"], "NOT_RUN")
            self.assertEqual(future["tests_pass"], 0)
            self.assertFalse(result["all_version_suites_pass"])


class UpdaterTests(unittest.TestCase):
    def prepare(self, folder):
        manifest = Path(folder) / "versions.json"
        manifest.write_text(json.dumps({"minimum_python": "3.9",
                                        "latest_stable": "3.15.2",
                                        "watch_packages": ["example"],
                                        "auto_check_hours": 24}))
        return manifest, ROOT / "sql" / "knowledge.sql", Path(folder) / "knowledge.sqlite"

    @staticmethod
    def fake_download(url, etag=None, timeout=30, next_version="3.15.2"):
        if url == "https://www.python.org/downloads/":
            return f'<a>Download Python {next_version}</a>'.encode(), None, False
        if etag:
            return None, etag, True
        if url.startswith("https://docs.python.org/"):
            body = "<html><body>" + ("Versioned official changes for Python. " * 7) + "</body></html>"
            return body.encode(), '"doc123"', False
        if url.startswith("https://pypi.org/"):
            return json.dumps({"info": {"version": "2.1.0", "summary": "Example library",
                                         "requires_python": ">=3.9",
                                         "requires_dist": ["typing-extensions>=4"]}}).encode(), '"pkg123"', False
        raise AssertionError("onverwachte bron " + url)

    def test_release_parser_excludes_pre_releases(self):
        self.assertEqual(updater.latest_stable(b'Download Python 3.15.2'), "3.15.2")
        with self.assertRaises(ValueError):
            updater.latest_stable(b'Download Python 3.16.0a1')

    def test_non_https_or_unknown_host_fails(self):
        for url in ("http://pypi.org/a", "https://malicious.example/a", "https://user@pypi.org/a"):
            with self.assertRaises(ValueError):
                updater.checked_url(url)

    def test_invalid_package_name_fails(self):
        with self.assertRaises(ValueError):
            updater.safe_packages(["../bad"])
        self.assertEqual(updater.safe_packages(["Foo_Bar", "foo.bar"]), ["foo-bar"])

    def test_check_has_no_file_side_effects(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest, schema, db = self.prepare(folder)
            old = manifest.read_bytes()
            with patch.object(updater, "download", side_effect=self.fake_download):
                value = updater.update(manifest, schema, db, mode="check")
            self.assertEqual(value["status"], "UP_TO_DATE")
            self.assertFalse(db.exists())
            self.assertEqual(old, manifest.read_bytes())

    def test_apply_indexes_seven_versions_and_one_package(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest, schema, db = self.prepare(folder)
            with patch.object(updater, "download", side_effect=self.fake_download):
                result = updater.update(manifest, schema, db, mode="apply")
            self.assertEqual(result["status"], "UPDATED")
            self.assertEqual(result["documents_updated"], 8)
            conn = sqlite3.connect(str(db))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0], 8)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM documents_fts WHERE documents_fts MATCH 'changes'").fetchone()[0], 7)
            conn.close()
            # Automatic check respects TTL, without making a network request.
            with patch.object(updater, "download", side_effect=AssertionError("network not needed")):
                skipped = updater.update(manifest, schema, db, mode="apply", auto=True)
            self.assertEqual(skipped["status"], "SKIPPED_FRESH")

    def test_future_version_adds_eighth_document(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest, schema, db = self.prepare(folder)
            def next_release(url, etag=None, timeout=30):
                return self.fake_download(url, etag, timeout, next_version="3.16.0")
            with patch.object(updater, "download", side_effect=next_release):
                result = updater.update(manifest, schema, db, mode="apply")
            self.assertEqual(result["latest_stable"], "3.16.0")
            self.assertEqual(result["documents_updated"], 9)
            self.assertEqual(json.loads(manifest.read_text())["latest_stable"], "3.16.0")

    def test_expired_auto_ttl_refreshes_again(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest, schema, db = self.prepare(folder)
            with patch.object(updater, "download", side_effect=self.fake_download):
                updater.update(manifest, schema, db, mode="apply")
            with open_db(db) as conn:
                conn.execute("UPDATE update_state SET value=? WHERE key='last_success'",
                             (str(time.time() - 25 * 3600),))
            with patch.object(updater, "download", side_effect=self.fake_download) as mocked:
                result = updater.update(manifest, schema, db, mode="apply", auto=True)
            self.assertEqual(result["status"], "UPDATED")
            self.assertEqual(result["sources_unchanged"], 8)
            self.assertGreater(mocked.call_count, 0)

    def test_failure_does_not_advance_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest, schema, db = self.prepare(folder)
            before = manifest.read_bytes()
            def broken(url, etag=None, timeout=30):
                if "3.12.html" in url:
                    raise ValueError("unverified docs")
                return self.fake_download(url, etag, timeout, next_version="3.16.0")
            with patch.object(updater, "download", side_effect=broken):
                with self.assertRaises(ValueError):
                    updater.update(manifest, schema, db, mode="apply")
            self.assertEqual(manifest.read_bytes(), before)
            conn = sqlite3.connect(str(db))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0], 0)
            conn.close()

    def test_deleted_watch_source_tombstoned_and_readded(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest, schema, db = self.prepare(folder)
            with patch.object(updater, "download", side_effect=self.fake_download):
                updater.update(manifest, schema, db, mode="apply")
            url = "https://pypi.org/pypi/example/json"
            with open_db(db) as conn:
                # A user-added document may deliberately reuse a tracked URI;
                # a watchlist tombstone must never delete that separate source.
                conn.execute(
                    "INSERT INTO documents(source,uri,title,package,version,python_constraint,content,sha256) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    ("manual", url, "Private local note", "custom", "1.0", ">=3.9",
                     "locally owned note", "manual-hash"),
                )
            config = json.loads(manifest.read_text())
            config["watch_packages"] = []
            manifest.write_text(json.dumps(config))
            with patch.object(updater, "download", side_effect=self.fake_download):
                result = updater.update(manifest, schema, db, mode="apply")
            self.assertEqual(result["documents_deleted"], 1)
            self.assertEqual(result["tombstoned_sources"], 1)
            with open_db(db) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM documents WHERE uri=?", (url,)).fetchone()[0], 1)
                self.assertEqual(conn.execute("SELECT source FROM documents WHERE uri=?", (url,)).fetchone()[0], "manual")
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM documents_fts WHERE documents_fts MATCH 'example'").fetchone()[0], 0)
                self.assertIsNotNone(updater.read_state(conn, "tombstone:" + url))
                self.assertIsNone(updater.read_state(conn, "etag:" + url))
            config["watch_packages"] = ["example"]
            manifest.write_text(json.dumps(config))
            with patch.object(updater, "download", side_effect=self.fake_download):
                restored = updater.update(manifest, schema, db, mode="apply")
            self.assertEqual(restored["documents_updated"], 1)
            with open_db(db) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM documents WHERE uri=?", (url,)).fetchone()[0], 2)
                self.assertGreater(conn.execute("SELECT COUNT(*) FROM documents_fts WHERE documents_fts MATCH 'example'").fetchone()[0], 0)
                self.assertIsNone(updater.read_state(conn, "tombstone:" + url))

    def test_legacy_etag_sources_are_migrated_before_tombstoning(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest, schema, db = self.prepare(folder)
            with patch.object(updater, "download", side_effect=self.fake_download):
                updater.update(manifest, schema, db, mode="apply")
            url = "https://pypi.org/pypi/example/json"
            with open_db(db) as conn:
                # Simulate a pre-v0.12 updater database without source_active.
                conn.execute("DELETE FROM update_state WHERE key=?", ("source_active:" + url,))
            config = json.loads(manifest.read_text())
            config["watch_packages"] = []
            manifest.write_text(json.dumps(config))
            with patch.object(updater, "download", side_effect=self.fake_download):
                result = updater.update(manifest, schema, db, mode="apply")
            self.assertEqual(result["documents_deleted"], 1)
            self.assertEqual(result["tombstoned_sources"], 1)
            with open_db(db) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM documents WHERE uri=?", (url,)).fetchone()[0], 0)
                self.assertIsNotNone(updater.read_state(conn, "tombstone:" + url))

    def test_corrupt_historic_package_row_is_pruned_after_verified_fetch(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest, schema, db = self.prepare(folder)
            with patch.object(updater, "download", side_effect=self.fake_download):
                updater.update(manifest, schema, db, mode="apply")
            url = "https://pypi.org/pypi/example/json"
            old = {"source": "pypi-metadata", "uri": url, "title": "example 1.0.0",
                   "package": "example", "version": "1.0.0", "python_constraint": ">=3.9",
                   "content": "historic package rules"}
            with open_db(db) as conn:
                updater.index_document(conn, old)
                conn.execute("UPDATE documents SET content='damaged' WHERE uri=? AND version='1.0.0'", (url,))
                self.assertFalse(updater.verified_copy(conn, url))
            with patch.object(updater, "download", side_effect=self.fake_download) as mocked:
                result = updater.update(manifest, schema, db, mode="apply")
            self.assertEqual(result["corrupt_documents_removed"], 1)
            self.assertEqual(result["documents_updated"], 1)
            package_calls = [call for call in mocked.call_args_list if call.args[0] == url]
            self.assertEqual(len(package_calls), 1)
            self.assertIsNone(package_calls[0].args[1])
            with open_db(db) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM documents WHERE uri=?", (url,)).fetchone()[0], 1)
                self.assertTrue(updater.verified_copy(conn, url))

    def test_corrupt_local_cache_forces_refetch_instead_of_trusting_304(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest, schema, db = self.prepare(folder)
            with patch.object(updater, "download", side_effect=self.fake_download):
                updater.update(manifest, schema, db, mode="apply")
            url = "https://pypi.org/pypi/example/json"
            with open_db(db) as conn:
                conn.execute("UPDATE documents SET content='CORRUPTED' WHERE uri=?", (url,))
            with patch.object(updater, "download", side_effect=self.fake_download) as mocked:
                result = updater.update(manifest, schema, db, mode="apply")
            self.assertEqual(result["documents_updated"], 1)
            self.assertEqual(result["sources_unchanged"], 7)
            package_calls = [call for call in mocked.call_args_list if call.args[0] == url]
            self.assertEqual(len(package_calls), 1)
            self.assertIsNone(package_calls[0].args[1])
            with open_db(db) as conn:
                self.assertTrue(updater.verified_copy(conn, url))

    def test_http_304_without_prior_etag_is_rejected(self):
        error = HTTPError("https://pypi.org/pypi/example/json", 304, "Not Modified", None, BytesIO())
        try:
            with patch.object(updater, "urlopen", side_effect=error):
                with self.assertRaises(ValueError):
                    updater.download("https://pypi.org/pypi/example/json", etag=None)
        finally:
            error.close()

    def test_failed_manifest_replacement_does_not_get_auto_ttl_skip(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest, schema, db = self.prepare(folder)
            before = manifest.read_bytes()

            def newest(url, etag=None, timeout=30):
                return self.fake_download(url, etag, timeout, next_version="3.16.0")

            with patch.object(updater, "download", side_effect=newest), \
                    patch.object(updater, "atomic_json", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    updater.update(manifest, schema, db, mode="apply")
            self.assertEqual(manifest.read_bytes(), before)
            with open_db(db) as conn:
                self.assertEqual(updater.read_state(conn, "committed_latest_stable"), "3.16.0")
            with patch.object(updater, "download", side_effect=newest):
                fixed = updater.update(manifest, schema, db, mode="apply", auto=True)
            self.assertEqual(fixed["status"], "UPDATED")
            self.assertEqual(json.loads(manifest.read_text())["latest_stable"], "3.16.0")

    def test_sqlite_failure_rolls_back_tombstones_and_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest, schema, db = self.prepare(folder)
            with patch.object(updater, "download", side_effect=self.fake_download):
                updater.update(manifest, schema, db, mode="apply")
            config = json.loads(manifest.read_text())
            config["watch_packages"] = []
            manifest.write_text(json.dumps(config))
            before = manifest.read_bytes()

            def newest(url, etag=None, timeout=30):
                return self.fake_download(url, etag, timeout, next_version="3.16.0")

            with patch.object(updater, "download", side_effect=newest), \
                    patch.object(updater, "index_document", side_effect=sqlite3.OperationalError("disk full")):
                with self.assertRaises(sqlite3.OperationalError):
                    updater.update(manifest, schema, db, mode="apply")
            self.assertEqual(manifest.read_bytes(), before)
            url = "https://pypi.org/pypi/example/json"
            with open_db(db) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM documents WHERE uri=?", (url,)).fetchone()[0], 1)
                self.assertEqual(updater.read_state(conn, "source_active:" + url), "1")
                self.assertIsNone(updater.read_state(conn, "tombstone:" + url))


if __name__ == "__main__":
    unittest.main()
