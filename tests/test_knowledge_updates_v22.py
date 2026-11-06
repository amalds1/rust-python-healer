"""Real offline watch / cache repair / compile-only evidence on each CPython."""

from contextlib import closing
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "knowledge_updates_v22.py"
spec = spec_from_file_location("knowledge_updates_v22", SCRIPT)
module = module_from_spec(spec)
spec.loader.exec_module(module)

PY_URL = "https://docs.python.org/3.9/whatsnew/3.9.html"
PKG_URL = "https://pypi.org/pypi/gecpackage/json"
OTHER_URL = "https://pypi.org/pypi/older/json"


def digest(content):
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def pins(*pairs):
    result = {}
    for url, value in pairs:
        result[url] = {"sha256": digest(value), "version": "3.9" if url == PY_URL
                       else "4.1.0", "title": "Trusted local source"}
    return result


class _PinnedHTTP(BaseHTTPRequestHandler):
    counters = None

    def do_GET(self):
        state = self.counters
        state["requests"] += 1
        state["paths"].append(self.path)
        state["if_none_match"].append(self.headers.get("If-None-Match"))
        if self.path != "/fixture/data":
            self.send_error(404)
            return
        if state.get("redirect"):
            self.send_response(302)
            self.send_header("Location", "https://somewhere.invalid/")
            self.end_headers()
            return
        tag = state["etag"]
        if self.headers.get("If-None-Match") == tag:
            self.send_response(304)
            self.send_header("ETag", tag)
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("ETag", tag)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(state["body"])

    def log_message(self, format_string, *args):
        pass


class KnowledgeV22Tests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="rph-knowledge-v22-")
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.path = self.root / "knowledge.sqlite"
        with closing(sqlite3.connect(str(self.path))) as conn:
            conn.executescript((ROOT / "sql" / "knowledge.sql").read_text(encoding="utf-8"))
            conn.commit()
        self.conn = module.checked_catalog(self.path)
        self.addCleanup(self.conn.close)
        self.body = "Real trusted package metadata, with bounded Unicode – ok"

    def source_response(self, body=None, tag='"rev1"'):
        return lambda _url, _etag: {"status": 200, "body": (body or self.body).encode(),
                                    "etag": tag}

    def stage(self, url=PKG_URL, body=None):
        text = body or self.body
        return module.apply_pinned_cycle(self.conn, pins((url, text)),
                                         self.source_response(text))

    def seeded(self, url, version, content, stored_hash=None, etag=None):
        source = module.namespace(url)
        package = "cpython" if source == "python-official-whatsnew" else url.split("/")[4]
        self.conn.execute("INSERT INTO documents(" 
                          "source,uri,title,package,version,python_constraint,content,sha256) "
                          "VALUES(?,?,?,?,?,?,?,?)",
                          (source, url, "Old", package, version, "", content,
                           stored_hash if stored_hash is not None else digest(content)))
        if etag:
            self.conn.execute("INSERT OR REPLACE INTO update_state VALUES(?,?)",
                              ("etag:" + url, etag))

    def local_server(self, body=None):
        state = {"body": (body or self.body).encode(), "etag": '"network-1"',
                 "requests": 0, "paths": [], "if_none_match": []}
        handler = type("OwnPinnedHTTP", (_PinnedHTTP,), {"counters": state})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 1)
        self.addCleanup(server.shutdown)
        return server, state

    def test_new_pinned_document_inserted_with_real_fts_trigger(self):
        report = self.stage()
        self.assertEqual(report["updated"], 1)
        self.assertEqual(report["status"], "PINNED_OFFLINE_INCREMENTAL_CYCLE_PASS")
        self.assertFalse(report["untrusted_code_executed"])
        rows = self.conn.execute("SELECT content,sha256 FROM documents").fetchall()
        self.assertEqual(rows, [(self.body, digest(self.body))])
        hit = self.conn.execute("SELECT count(*) FROM documents_fts WHERE documents_fts MATCH 'Unicode'")
        self.assertEqual(hit.fetchone()[0], 1)

    def test_legacy_etag_304_accepted_only_with_intact_pinned_versions(self):
        self.seeded(PKG_URL, "4.1.0", self.body, etag='"legacy-etag"')
        observed = []

        def reply(_url, etag):
            observed.append(etag)
            return {"status": 304}

        report = module.apply_pinned_cycle(self.conn, pins((PKG_URL, self.body)), reply)
        self.assertEqual(observed, ['"legacy-etag"'])
        self.assertEqual(report["unchanged"], 1)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM documents").fetchone()[0], 1)

    def test_304_without_valid_etag_or_cache_is_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "304_without_validated_cache_refused"):
            module.apply_pinned_cycle(self.conn, pins((PKG_URL, self.body)),
                                      lambda *_: {"status": 304})
        self.assertEqual(self.conn.execute("SELECT count(*) FROM documents").fetchone()[0], 0)

    def test_bad_sha256_old_gecpackage_version_repaired_after_fresh_pin(self):
        self.seeded(PKG_URL, "1.0.0", "CORRUPTED_OLD", stored_hash="f" * 64,
                    etag='"old-sha"')
        self.seeded(PKG_URL, "2.0.0", "intact older")
        etags = []

        def reply(_url, etag):
            etags.append(etag)
            return {"status": 200, "body": self.body.encode(), "etag": '"new"'}

        report = module.apply_pinned_cycle(self.conn, pins((PKG_URL, self.body)), reply)
        self.assertEqual(etags, [None])
        self.assertEqual(report["corrupt_historical_versions_removed"], 1)
        self.assertEqual([r[0] for r in self.conn.execute(
            "SELECT version FROM documents ORDER BY version")], ["2.0.0", "4.1.0"])

    def test_legacy_docs_without_registered_etag_are_tombstoned(self):
        self.seeded(OTHER_URL, "1.0.0", "ancient unregistered source")
        report = self.stage()
        self.assertEqual(report["tombstoned_sources"], 1)
        self.assertEqual(report["removed_documents"], 1)
        self.assertEqual(self.conn.execute("SELECT value FROM update_state "
                                           "WHERE key=?", ("tombstone:" + OTHER_URL,))
                         .fetchone()[0], "1")

    def test_legacy_etag_with_no_documents_still_tombstoned(self):
        self.conn.execute("INSERT INTO update_state VALUES(?,?)",
                          ("etag:" + OTHER_URL, '"previous"'))
        report = self.stage()
        self.assertEqual(report["tombstoned_sources"], 1)
        self.assertIsNone(self.conn.execute("SELECT value FROM update_state WHERE key=?",
                                            ("etag:" + OTHER_URL,)).fetchone())

    def test_invalid_second_response_cannot_partially_install_first(self):
        plans = pins((PKG_URL, self.body), (PY_URL, "Python docs"))
        def fetch(url, _etag):
            if url == PKG_URL:
                return {"status": 200, "body": self.body.encode(), "etag": '"ok"'}
            return {"status": 200, "body": b"other", "etag": '"also-ok"'}
        with self.assertRaisesRegex(ValueError, "out_of_band_sha256_pin_failed"):
            module.apply_pinned_cycle(self.conn, plans, fetch)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM documents").fetchone()[0], 0)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM v22_watch_events").fetchone()[0], 0)

    def test_invalid_updater_owned_legacy_namespace_blocks_deletion(self):
        self.conn.execute("INSERT INTO documents(" 
                          "source,uri,title,package,version,python_constraint,content,sha256) "
                          "VALUES(?,?,?,?,?,?,?,?)",
                          ("pypi-metadata", "https://attacker.invalid/", "X", "x", "1", "", "x", digest("x")))
        with self.assertRaisesRegex(ValueError, "not_updater_owned_namespace"):
            self.stage()
        self.assertEqual(self.conn.execute("SELECT count(*) FROM documents").fetchone()[0], 1)

    def test_sha_corrupt_cache_never_gets_304_reused(self):
        self.seeded(PKG_URL, "4.1.0", "wrong", stored_hash=digest(self.body),
                    etag='"legacy"')
        etags = []
        def return_304(_url, etag):
            etags.append(etag)
            return {"status": 304}
        with self.assertRaisesRegex(ValueError, "304_without_validated_cache_refused"):
            module.apply_pinned_cycle(self.conn, pins((PKG_URL, self.body)), return_304)
        self.assertEqual(etags, [None])

    def test_wrong_pin_or_etag_injection_fails(self):
        bad = pins((PKG_URL, self.body))
        bad[PKG_URL]["sha256"] = "d" * 64
        with self.assertRaisesRegex(ValueError, "out_of_band_sha256_pin_failed"):
            module.apply_pinned_cycle(self.conn, bad, self.source_response())
        with self.assertRaisesRegex(ValueError, "untrusted_etag"):
            module.apply_pinned_cycle(self.conn, pins((PKG_URL, self.body)),
                                      self.source_response(tag='"bad\r\ninjection"'))

    def test_tombstone_reverses_when_source_comes_back_pinned(self):
        self.seeded(PKG_URL, "1.0.0", "old")
        first = module.apply_pinned_cycle(self.conn, {}, lambda *_: None)
        self.assertEqual(first["tombstoned_sources"], 1)
        second = self.stage()
        self.assertEqual(second["updated"], 1)
        self.assertIsNone(self.conn.execute("SELECT value FROM update_state WHERE key=?",
                                            ("tombstone:" + PKG_URL,)).fetchone())

    def test_unsafe_catalog_path_rejects_symlink_and_hardlink(self):
        symlink = self.root / "link.db"
        symlink.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError, "unsafe_catalog_directory"):
            module.checked_catalog(symlink)
        hardlink = self.root / "other.db"
        import os
        os.link(self.path, hardlink)
        with self.assertRaisesRegex(ValueError, "unsafe_catalog_inode"):
            module.checked_catalog(hardlink)

    def test_real_loopback_http_200_then_conditional_304(self):
        server, state = self.local_server()
        fetch = module.local_http_fixture_fetch(server.server_port,
                                                {PKG_URL: "/fixture/data"})
        plan = pins((PKG_URL, self.body))
        self.assertEqual(module.apply_pinned_cycle(self.conn, plan, fetch)["updated"], 1)
        self.assertEqual(module.apply_pinned_cycle(self.conn, plan, fetch)["unchanged"], 1)
        self.assertEqual(state["if_none_match"], [None, '"network-1"'])
        self.assertEqual(state["requests"], 2)

    def test_http_redirects_never_followed(self):
        server, state = self.local_server()
        state["redirect"] = True
        fetch = module.local_http_fixture_fetch(server.server_port,
                                                {PKG_URL: "/fixture/data"})
        with self.assertRaisesRegex(ValueError, "fixture_http_response_not_approved"):
            module.apply_pinned_cycle(self.conn, pins((PKG_URL, self.body)), fetch)
        self.assertEqual(state["requests"], 1)

    def test_real_supervised_subprocess_restarted_on_update_not_304(self):
        server, state = self.local_server()
        fetch = module.local_http_fixture_fetch(server.server_port,
                                                {PKG_URL: "/fixture/data"})
        supervisor = module.TrustedWorkerSupervisor(sys.executable)
        result = module.watch_cycles(self.conn, pins((PKG_URL, self.body)), fetch,
                                     cycles=2, pause_ms=10, supervisor=supervisor)
        self.assertEqual(result["successful_cycles"], 2)
        self.assertEqual(result["actual_subprocess_worker_starts"], 2)
        self.assertTrue(result["real_restart_supervision_used"])
        self.assertIsNone(supervisor.child)
        self.assertEqual(state["requests"], 2)

    def test_injected_transient_network_failure_retries_next_watch_cycle(self):
        calls = []
        def fetch(_url, _etag):
            calls.append(True)
            if len(calls) == 1:
                raise OSError("test-injected transport drop")
            return {"status": 200, "body": self.body.encode(), "etag": '"second"'}
        result = module.watch_cycles(self.conn, pins((PKG_URL, self.body)), fetch,
                                     cycles=2, pause_ms=0)
        self.assertEqual(result["successful_cycles"], 1)
        self.assertEqual(result["failed_cycles"], 1)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM documents").fetchone()[0], 1)

    def test_watch_cycle_quota_and_callback_validation(self):
        for cycles in (0, -1, 17, True):
            with self.assertRaisesRegex(ValueError, "unsafe_watch_quota"):
                module.watch_cycles(self.conn, {}, lambda *_: None, cycles=cycles)
        with self.assertRaisesRegex(ValueError, "untrusted_restart_callback"):
            module.watch_cycles(self.conn, {}, lambda *_: None, supervisor=object())

    def test_watch_fixture_cli_works_via_real_isolated_interpreter(self):
        fixture = self.root / "pinned.json"
        fixture.write_text(json.dumps({
            "plans": pins((PKG_URL, self.body)),
            "responses": {PKG_URL: [{"status": 200, "etag": '"first"',
                                    "body": self.body}, {"status": 304}]}},
            sort_keys=True), encoding="utf-8")
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "watch-fixture", "--watch", "--db", str(self.path),
                              "--fixture-json", str(fixture), "--cycles", "2"],
                             capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["successful_cycles"], 2)
        self.assertEqual(report["cycle_reports"][1]["unchanged"], 1)

    def test_capability_cli_is_machine_readable_and_no_fetch(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)],
                             capture_output=True, timeout=6, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertFalse(report["network_accessed"])
        self.assertEqual(len(report["features"]), 3)

    def test_compile_downloaded_example_runs_separate_interpreter_without_exec(self):
        marker = self.root / "MUST_NOT_EXIST"
        code = ("open({!r}, 'w').write('leaked')\n".format(str(marker))).encode()
        report = module.compile_pinned_example(code, digest(code), sys.executable)
        self.assertEqual(report["status"], "COMPILE_ONLY_PASS")
        self.assertFalse(report["downloaded_code_executed"])
        self.assertFalse(marker.exists())
        self.assertEqual(report["python_minor"],
                         "{}.{}".format(sys.version_info.major, sys.version_info.minor))

    def test_compile_syntax_error_recorded_without_source_contents(self):
        source = b"def broken(:\n  return 1\n"
        report = module.compile_pinned_example(source, digest(source), sys.executable)
        self.assertEqual(report["status"], "SYNTAX_REJECTED")
        self.assertNotIn("broken", json.dumps(report))

    def test_version_specific_match_case_compile_gate(self):
        source = (b"match 2:\n  case 2: value = True\n")
        report = module.compile_pinned_example(source, digest(source), sys.executable)
        self.assertEqual(report["status"], "SYNTAX_REJECTED" if sys.version_info.minor == 9
                         else "COMPILE_ONLY_PASS")

    def test_version_specific_exception_group_gate(self):
        source = (b"try:\n  raise ValueError()\nexcept* ValueError:\n  pass\n")
        report = module.compile_pinned_example(source, digest(source), sys.executable)
        self.assertEqual(report["status"], "SYNTAX_REJECTED"
                         if sys.version_info.minor <= 10 else "COMPILE_ONLY_PASS")

    def test_pin_and_size_fail_before_separate_compile_subprocess(self):
        with self.assertRaisesRegex(ValueError, "pinned_example_sha256_mismatch"):
            module.compile_pinned_example(b"pass\n", "f" * 64, sys.executable)
        with self.assertRaisesRegex(ValueError, "invalid_downloaded_source_size"):
            module.compile_pinned_example(b"x" * 65537, digest(b"x" * 65537), sys.executable)

    def test_downloaded_fixture_bytes_and_compile_decoupled(self):
        server, _ = self.local_server("x = 42\n")
        transport = module.local_http_fixture_fetch(server.server_port,
                                                    {PKG_URL: "/fixture/data"})
        response = transport(PKG_URL, None)
        self.assertEqual(response["status"], 200)
        result = module.compile_pinned_example(response["body"], digest(b"x = 42\n"),
                                               sys.executable)
        self.assertEqual(result["status"], "COMPILE_ONLY_PASS")

    def test_source_compile_cli_and_wrong_pin(self):
        source = self.root / "example.py"
        source.write_text("value = 1\n", encoding="utf-8")
        base = [sys.executable, "-I", "-S", "-B", str(SCRIPT), "--mode", "compile",
                "--python", sys.executable, "--source", str(source), "--sha256"]
        run = subprocess.run(base + [digest(source.read_bytes())], capture_output=True,
                             timeout=5, check=False)
        self.assertEqual(json.loads(run.stdout)["status"], "COMPILE_ONLY_PASS")
        wrong = subprocess.run(base + ["f" * 64], capture_output=True,
                               timeout=5, check=False)
        self.assertNotEqual(wrong.returncode, 0)


if __name__ == "__main__":
    unittest.main()
