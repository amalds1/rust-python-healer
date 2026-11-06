"""Controlled ETag/Python-release update state; no actual outbound HTTP."""

from contextlib import closing
from importlib.util import module_from_spec, spec_from_file_location
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("watched_updater_v21",
                               ROOT / "python" / "watched_updater_v21.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)
URL = "https://updates.python.org/release/metadata.json"


def fixture(minor="3.15"):
    return json.dumps({"schema_version": 1, "python_minor": minor,
                       "metadata_sha256": hashlib.sha256(minor.encode()).hexdigest()},
                      sort_keys=True).encode("ascii")


class WatchedUpdaterV21Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.db = self.folder / "watched.sqlite"
        self.conn = module.database(self.db)
        self.addCleanup(self.conn.close)
        self.body = fixture()
        self.expected = hashlib.sha256(self.body).hexdigest()

    def once(self, response=None, expected=None, restart=None):
        if response is None:
            response = {"status": 200, "etag": '"release-3.15-a"',
                        "body": self.body}
        return module.watch_once(self.conn, URL, lambda url, etag: response,
                                 self.expected if expected is None else expected,
                                 restart=restart)

    def test_first_pinned_metadata_staging_and_restart_callback(self):
        observed = []
        def restart(url, revision):
            observed.append((url, revision))
        report = self.once(restart=restart)
        self.assertEqual(report["status"], "PINNED_METADATA_STAGED_RESTART_ACKNOWLEDGED")
        self.assertEqual(observed, [(URL, 1)])
        self.assertTrue(report["pinned_sha256_checked"])
        self.assertFalse(report["external_publisher_authenticated"])
        self.assertFalse(report["production_process_restarted_verified"])
        self.assertFalse(report["source_code_executed"])
        self.assertFalse(report["network_called"])
        self.assertEqual(module.inspect(self.conn)["events"], 2)

    def test_etag_304_uses_prior_etag_and_never_stages_replay(self):
        self.once(restart=lambda *_: None)
        requests = []
        def fetch(url, etag):
            requests.append((url, etag))
            return {"status": 304}
        report = module.watch_once(self.conn, URL, fetch, self.expected)
        self.assertEqual(report["status"], "NOT_MODIFIED_ETAG_HIT")
        self.assertEqual(requests, [(URL, '"release-3.15-a"')])
        self.assertEqual(module.inspect(self.conn)["events"], 2)

    def test_restart_failure_persists_pending_and_304_can_retry(self):
        def broken(*_):
            raise RuntimeError("restart adapter failed")
        self.assertEqual(self.once(restart=broken)["status"],
                         "PINNED_METADATA_STAGED_RESTART_PENDING")
        assert_pending = self.conn.execute("SELECT restart_pending FROM update_state").fetchone()[0]
        self.assertEqual(assert_pending, 1)
        retried = module.watch_once(self.conn, URL, lambda *_: {"status": 304},
                                    self.expected, restart=lambda *_: None)
        self.assertEqual(retried["status"], "RESTART_ACKNOWLEDGED")
        self.assertEqual(self.conn.execute("SELECT restart_pending FROM update_state")
                         .fetchone()[0], 0)

    def test_revision_increments_for_future_minor_and_refuses_rollback(self):
        self.once()
        newer = fixture("3.16")
        digest = hashlib.sha256(newer).hexdigest()
        changed = self.once({"status": 200, "etag": '"release-3.16-b"',
                             "body": newer}, expected=digest)
        self.assertEqual(changed["revision"], 2)
        self.assertEqual(changed["python_minor"], "3.16")
        with self.assertRaisesRegex(ValueError, "python_version_rollback_refused"):
            self.once()
        self.assertEqual(self.conn.execute("SELECT revision FROM update_state")
                         .fetchone()[0], 2)

    def test_sha256_mismatch_blocks_update_and_restarts(self):
        called = []
        with self.assertRaisesRegex(ValueError, "pinned_update_sha256_mismatch"):
            self.once(expected="0" * 64, restart=lambda *_: called.append("bad"))
        self.assertEqual(called, [])
        self.assertEqual(module.inspect(self.conn)["records"], 0)

    def test_no_pinned_digest_fails_closed_without_contacting_fetcher(self):
        called = []
        def fake(url, etag):
            called.append((url, etag))
            return {"status": 200, "body": self.body, "etag": '"a"'}
        result = module.watch_once(self.conn, URL, fake, "not-a-sha")
        self.assertEqual(result["status"], "AUTHENTICATED_DIGEST_REQUIRED")
        self.assertFalse(result["network_called"])
        self.assertEqual(called, [])

    def test_304_without_prior_version_or_wrong_expected_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, "unexpected_304_without_prior_etag"):
            self.once({"status": 304})
        self.once()
        with self.assertRaisesRegex(ValueError, "stale_expected_digest_for_304"):
            self.once({"status": 304}, expected="0" * 64)

    def test_invalid_etag_weak_etag_and_untrusted_status_refused(self):
        for etag in ("W/\"weak\"", "unquoted", '"bad\nvalue"', '"../../"'):
            with self.subTest(etag=etag):
                with self.assertRaisesRegex(ValueError, "invalid_strong_etag"):
                    self.once({"status": 200, "etag": etag, "body": self.body})
        with self.assertRaisesRegex(ValueError, "unsupported_http_stub_status"):
            self.once({"status": 503})
        self.assertEqual(module.inspect(self.conn)["records"], 0)

    def test_etag_can_never_change_for_identical_content_silently(self):
        self.once()
        with self.assertRaisesRegex(ValueError, "etag_content_identity_conflict"):
            self.once({"status": 200, "etag": '"changed-without-new-bytes"',
                       "body": self.body})
        self.assertEqual(module.inspect(self.conn)["events"], 1)

    def test_same_etag_cannot_claim_changed_body_identity(self):
        self.once()
        changed = fixture("3.16")
        with self.assertRaisesRegex(ValueError,
                                    "etag_same_identity_different_content_refused"):
            self.once({"status": 200, "etag": '"release-3.15-a"', "body": changed},
                      expected=hashlib.sha256(changed).hexdigest())
        self.assertEqual(module.inspect(self.conn)["records"], 1)

    def test_versioned_manifest_rejects_sneaky_extra_or_code_like_content(self):
        data = json.dumps({"schema_version": 1, "python_minor": "3.16",
                           "metadata_sha256": "0" * 64,
                           "execute": "__import__('os').system('touch marker')"}).encode()
        digest = hashlib.sha256(data).hexdigest()
        with self.assertRaisesRegex(ValueError, "invalid_update_manifest_schema"):
            self.once({"status": 200, "etag": '"poison"', "body": data},
                      expected=digest)
        self.assertEqual(module.inspect(self.conn)["records"], 0)

    def test_concurrent_update_detects_database_revision_conflict(self):
        self.once()
        newer = fixture("3.16")
        digest = hashlib.sha256(newer).hexdigest()
        def concurrent_fetch(url, etag):
            module.watch_once(self.conn, URL,
                              lambda *_: {"status": 200, "etag": '"inner-3.16"',
                                          "body": newer}, digest)
            return {"status": 200, "etag": '"outer-3.16"', "body": newer}
        with self.assertRaisesRegex(ValueError, "concurrent_watched_update_conflict"):
            module.watch_once(self.conn, URL, concurrent_fetch, digest)
        self.assertEqual(self.conn.execute("SELECT revision FROM update_state")
                         .fetchone()[0], 2)

    def test_immutable_event_history_cannot_be_rewritten_or_deleted(self):
        self.once(restart=lambda *_: None)
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE update_events SET action='forged'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("DELETE FROM update_events")
        self.assertEqual(module.inspect(self.conn)["events"], 2)

    def test_db_future_schema_partial_and_symlink_refused(self):
        future = self.folder / "future.sqlite"
        with closing(sqlite3.connect(str(future))) as conn:
            conn.execute("PRAGMA user_version=3")
        with self.assertRaisesRegex(ValueError, "unsupported_future_watched_update_schema"):
            module.database(future)
        partial = self.folder / "partial.sqlite"
        with closing(sqlite3.connect(str(partial))) as conn:
            conn.execute("CREATE TABLE update_state(fake TEXT)")
            conn.execute("PRAGMA user_version=1")
        with self.assertRaisesRegex(ValueError, "invalid_watched_update_database_schema"):
            module.database(partial)
        link = self.folder / "link.sqlite"
        link.symlink_to(self.db)
        with self.assertRaisesRegex(ValueError, "unsafe_watched_update_database_path"):
            module.database(link)

    def test_unsafe_update_url_userinfo_http_query_fragment_rejected(self):
        for url in ("http://updates.python.org/x", "https://user:pass@updates.python.org/x",
                    "https://updates.python.org/x?secret=1",
                    "https://updates.python.org/x#token"):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    module.watch_once(self.conn, url, lambda *_: {"status": 304},
                                      self.expected)

    def test_corrupt_db_content_inspect_does_not_falsely_claim_integrity(self):
        self.once()
        self.conn.execute("UPDATE update_state SET metadata=?", (b"altered",))
        self.assertEqual(module.inspect(self.conn)["status"], "INVALID")

    def test_cli_inspect_has_no_http_or_restart_side_effects(self):
        script = ROOT / "python" / "watched_updater_v21.py"
        call = subprocess.run([sys.executable, "-I", "-S", "-B", str(script),
                               "--db", str(self.db), "check"],
                              capture_output=True, text=True, check=True)
        report = json.loads(call.stdout)
        self.assertFalse(report["network_called"])
        self.assertFalse(report["binary_deployed"])
        self.assertFalse(report["actual_process_restart_verified"])


if __name__ == "__main__":
    unittest.main()
