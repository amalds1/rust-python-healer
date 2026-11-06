"""Offline-qualified incremental knowledge watch and compile-only examples.

This module never downloads arbitrary internet URLs, executes downloaded code,
or updates the Rust executable.  Network probes are restricted to a caller-
configured 127.0.0.1 fixture service; publication metadata is independently
pinned by the operator.  A real online updater is NOT qualified by this work.
"""

import argparse
from contextlib import closing
import hashlib
from http.client import HTTPConnection
import json
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ETAG = re.compile(r'"[A-Za-z0-9._:-]{1,96}"\Z')
PACKAGE = re.compile(r"[a-z0-9][a-z0-9-]{0,98}\Z")
VERSION = re.compile(r"[0-9][0-9A-Za-z._+-]{0,80}\Z")
MAX_DOCUMENT_BYTES = 1_048_576
MAX_EXAMPLE_BYTES = 65_536
MAX_SOURCES = 24
MAX_CYCLES = 16
TRUSTED_WORKER = ("import time\n"
                  "print('TRUSTED_WORKER_READY', flush=True)\n"
                  "time.sleep(30)\n")
COMPILE_CHECK = (
    "import json,sys\n"
    "raw=sys.stdin.buffer.read(65537)\n"
    "if len(raw)>65536: print(json.dumps({'status':'TOO_LARGE'}));sys.exit(3)\n"
    "try:\n"
    " compile(raw,'<pinned-downloaded-example>','exec',dont_inherit=True)\n"
    "except (SyntaxError,IndentationError,TabError,ValueError,RecursionError):\n"
    " print(json.dumps({'status':'SYNTAX_REJECTED'}));sys.exit(2)\n"
    "print(json.dumps({'status':'COMPILE_ONLY_PASS',"
    "'python_minor':'%s.%s'%sys.version_info[:2]}))\n"
)


def namespace(url):
    """Recognize only the updater-owned, canonical official URL namespace."""
    if type(url) is not str or len(url) > 500 or any(c in url for c in " \t\r\n\\\x00<>\""):
        raise ValueError("invalid_managed_url")
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.query or parsed.fragment or
            parsed.username or parsed.password or parsed.port is not None or
            parsed.netloc != parsed.hostname):
        raise ValueError("untrusted_source_url")
    if re.fullmatch(r"/3\.(?:9|1[0-9]|[2-9][0-9])/whatsnew/3\.(?:9|1[0-9]|[2-9][0-9])\.html",
                    parsed.path) and parsed.hostname == "docs.python.org":
        parts = re.findall(r"3\.\d+", parsed.path)
        if parts[0] == parts[1]:
            return "python-official-whatsnew"
    if parsed.hostname == "pypi.org":
        match = re.fullmatch(r"/pypi/([a-z0-9][a-z0-9-]{0,98})/json", parsed.path)
        if match and PACKAGE.fullmatch(match.group(1)):
            return "pypi-metadata"
    raise ValueError("not_updater_owned_namespace")


def approved_plans(raw):
    """Validate separately operator-pinned expectations before contacting a stub."""
    if type(raw) is not dict or not 0 <= len(raw) <= MAX_SOURCES:
        raise ValueError("invalid_source_plan")
    plans = {}
    for url, item in raw.items():
        source = namespace(url)
        if (type(item) is not dict or set(item) != {"sha256", "version", "title"} or
                type(item["sha256"]) is not str or
                not SHA256.fullmatch(item["sha256"]) or
                type(item["version"]) is not str or
                not VERSION.fullmatch(item["version"]) or
                type(item["title"]) is not str or
                not 1 <= len(item["title"]) <= 120 or "\x00" in item["title"]):
            raise ValueError("invalid_pinned_source_plan")
        package = (urlsplit(url).path.split("/")[2] if source == "pypi-metadata"
                   else "cpython")
        plans[url] = dict(item, source=source, package=package)
    return plans


def checked_catalog(path):
    """Use an existing SQLite knowledge catalog, rejecting unsafe path aliases."""
    target = Path(path)
    if (target.is_symlink() or target.parent.is_symlink() or
            not target.parent.is_dir()):
        raise ValueError("unsafe_catalog_directory")
    try:
        details = target.stat()
    except FileNotFoundError:
        raise ValueError("catalog_must_preexist") from None
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_size > 128*1024*1024:
        raise ValueError("unsafe_catalog_inode")
    conn = sqlite3.connect(str(target), timeout=3.0, isolation_level=None)
    try:
        conn.execute("PRAGMA busy_timeout=3000")
        conn.execute("PRAGMA foreign_keys=ON")
        columns = {row[1] for row in conn.execute("PRAGMA table_info(documents)")}
        if not {"id", "source", "uri", "title", "package", "version",
                "python_constraint", "content", "sha256"}.issubset(columns):
            raise ValueError("not_a_knowledge_catalog")
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("CREATE TABLE IF NOT EXISTS update_state(" 
                     "key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS v22_watch_events(" 
                     "event_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                     "action TEXT NOT NULL,source_url TEXT NOT NULL,"
                     "revision INTEGER NOT NULL,digest TEXT NOT NULL)")
        conn.commit()
        return conn
    except Exception:
        conn.rollback()
        conn.close()
        raise


def _state(conn, key):
    row = conn.execute("SELECT value FROM update_state WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def _set_state(conn, key, value):
    conn.execute("INSERT INTO update_state(key,value) VALUES(?,?) ON CONFLICT(key) "
                 "DO UPDATE SET value=excluded.value", (key, value))


def _cache(conn, url, source):
    rows = conn.execute("SELECT content,sha256,version FROM documents "
                        "WHERE source=? AND uri=? ORDER BY version", (source, url)).fetchall()
    good = bool(rows) and all(
        type(content) is str and type(digest) is str and
        hashlib.sha256(content.encode("utf-8")).hexdigest() == digest
        for content, digest, _ in rows)
    return rows, good


def _existing_sources(conn):
    """Discover legacy managed documents even if no ETag was recorded."""
    found = set()
    for source, url in conn.execute(
            "SELECT DISTINCT source,uri FROM documents "
            "WHERE source IN ('python-official-whatsnew','pypi-metadata')"):
        if namespace(url) != source:
            raise ValueError("legacy_owned_document_namespace_mismatch")
        found.add(url)
    for (key,) in conn.execute("SELECT key FROM update_state WHERE key LIKE 'etag:https://%'"):
        url = key[5:]
        namespace(url)
        found.add(url)
    for (key,) in conn.execute("SELECT key FROM update_state WHERE key LIKE 'source_active:https://%'"):
        url = key[len("source_active:"):]
        namespace(url)
        found.add(url)
    return found


def apply_pinned_cycle(conn, planned_sources, fetch):
    """Atomic 200/304/tombstone reconciliation with real legacy recovery.

    All expected SHA256 values must be pinned before the fetch call; the
    trusted fetch receives an ETag only when every historical cached row is
    intact. A malformed cache forces unconditional refetch; 304 then fails.
    Neither a failed source nor invalid bytes can partially update the DB.
    """
    plans = approved_plans(planned_sources)
    if not callable(fetch):
        raise ValueError("trusted_fetch_adapter_required")
    before_data_version = conn.execute("PRAGMA data_version").fetchone()[0]
    received = {}
    for url, plan in sorted(plans.items()):
        rows, intact = _cache(conn, url, plan["source"])
        old_etag = _state(conn, "etag:" + url)
        etag = old_etag if old_etag and ETAG.fullmatch(old_etag) and intact else None
        response = fetch(url, etag)
        if type(response) is not dict or type(response.get("status")) is not int:
            raise ValueError("untrusted_fetch_response_shape")
        status = response["status"]
        if status == 304:
            if not etag or not rows:
                raise ValueError("304_without_validated_cache_refused")
            expected_rows = [r for r in rows if r[2] == plan["version"] and
                             r[1] == plan["sha256"]]
            if not expected_rows:
                raise ValueError("304_stale_pin_or_version_refused")
            received[url] = {"status": 304, "etag": etag}
        elif status == 200:
            body, new_etag = response.get("body"), response.get("etag")
            if type(body) is not bytes or not 1 <= len(body) <= MAX_DOCUMENT_BYTES:
                raise ValueError("invalid_fetch_body")
            if type(new_etag) is not str or not ETAG.fullmatch(new_etag):
                raise ValueError("untrusted_etag")
            if hashlib.sha256(body).hexdigest() != plan["sha256"]:
                raise ValueError("out_of_band_sha256_pin_failed")
            try:
                content = body.decode("utf-8")
            except UnicodeError as exc:
                raise ValueError("invalid_utf8_document") from exc
            if etag == new_etag and rows and not any(
                    digest == plan["sha256"] for _, digest, _ in rows):
                raise ValueError("conflicting_etag_identity")
            received[url] = {"status": 200, "etag": new_etag, "content": content}
        else:
            raise ValueError("unapproved_http_status")
    if conn.execute("PRAGMA data_version").fetchone()[0] != before_data_version:
        raise ValueError("concurrent_catalog_write_detected")
    deleted = 0
    repaired = 0
    tombstoned = 0
    updated = 0
    unchanged = 0
    conn.execute("BEGIN IMMEDIATE")
    try:
        # Sources absent from the operator-pinned watch list are explicitly
        # tombstoned even when an ancient DB never registered any ETag.
        old_sources = _existing_sources(conn)
        for url in sorted(old_sources - set(plans)):
            source = namespace(url)
            deleted += conn.execute("DELETE FROM documents WHERE source=? AND uri=?",
                                    (source, url)).rowcount
            conn.execute("DELETE FROM update_state WHERE key=?", ("etag:" + url,))
            _set_state(conn, "source_active:" + url, "0")
            _set_state(conn, "tombstone:" + url, "1")
            conn.execute("INSERT INTO v22_watch_events(action,source_url,revision,digest) "
                         "VALUES('TOMBSTONED',?,0,?)", (url, "0" * 64))
            tombstoned += 1
        for url, plan in sorted(plans.items()):
            reply = received[url]
            source = plan["source"]
            if reply["status"] == 200:
                # Remove every historical tampered version *only after* a
                # pinned, successful fresh response for this same source.
                old = conn.execute("SELECT id,content,sha256 FROM documents "
                                   "WHERE source=? AND uri=?", (source, url)).fetchall()
                for row_id, content, digest in old:
                    if (type(content) is not str or type(digest) is not str or
                            hashlib.sha256(content.encode("utf-8")).hexdigest() != digest):
                        repaired += conn.execute("DELETE FROM documents WHERE id=?",
                                                 (row_id,)).rowcount
                conn.execute("INSERT INTO documents(" 
                             "source,uri,title,package,version,python_constraint,content,sha256) "
                             "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(source,uri,version) "
                             "DO UPDATE SET title=excluded.title,content=excluded.content,"
                             "sha256=excluded.sha256,indexed_at=CURRENT_TIMESTAMP",
                             (source, url, plan["title"], plan["package"], plan["version"],
                              "", reply["content"], plan["sha256"]))
                _set_state(conn, "etag:" + url, reply["etag"])
                updated += 1
                action = "PINNED_200_STAGED"
            else:
                unchanged += 1
                action = "VALIDATED_304_UNCHANGED"
            _set_state(conn, "source_active:" + url, "1")
            conn.execute("DELETE FROM update_state WHERE key=?", ("tombstone:" + url,))
            revision = int(_state(conn, "v22_revision:" + url) or "0") + 1
            _set_state(conn, "v22_revision:" + url, str(revision))
            conn.execute("INSERT INTO v22_watch_events(action,source_url,revision,digest) "
                         "VALUES(?,?,?,?)", (action, url, revision, plan["sha256"]))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"status": "PINNED_OFFLINE_INCREMENTAL_CYCLE_PASS",
            "legacy_recovery_actions_performed": repaired + tombstoned,
            "updated": updated, "unchanged": unchanged,
            "tombstoned_sources": tombstoned, "removed_documents": deleted,
            "corrupt_historical_versions_removed": repaired,
            "publisher_identity_authenticated": False,
            "untrusted_code_executed": False, "external_network_used": False}


def local_http_fixture_fetch(port, url_paths):
    """Return a real loopback HTTP fetcher; redirects and other hosts refused."""
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid_fixture_port")
    if type(url_paths) is not dict or len(url_paths) > MAX_SOURCES:
        raise ValueError("invalid_fixture_paths")
    for url, path in url_paths.items():
        namespace(url)
        if type(path) is not str or not re.fullmatch(r"/[a-zA-Z0-9_/-]{1,120}", path):
            raise ValueError("unsafe_fixture_path")

    def fetch(url, etag):
        if url not in url_paths:
            raise ValueError("nonallowlisted_fixture_source")
        connection = HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            headers = {"Accept": "application/octet-stream"}
            if etag:
                if not ETAG.fullmatch(etag):
                    raise ValueError("invalid_conditional_etag")
                headers["If-None-Match"] = etag
            connection.request("GET", url_paths[url], headers=headers)
            response = connection.getresponse()
            status = response.status
            if status not in (200, 304):
                raise ValueError("fixture_http_response_not_approved")
            body = response.read(MAX_DOCUMENT_BYTES + 1)
            if len(body) > MAX_DOCUMENT_BYTES:
                raise ValueError("fixture_http_body_too_large")
            return {"status": status, "etag": response.getheader("ETag"),
                    "body": body}
        finally:
            connection.close()
    return fetch


def compile_pinned_example(body, expected_sha256, interpreter):
    """Compile *downloaded* bytes in a separate interpreter; never exec them."""
    if type(body) is not bytes or not 1 <= len(body) <= MAX_EXAMPLE_BYTES:
        raise ValueError("invalid_downloaded_source_size")
    if type(expected_sha256) is not str or not SHA256.fullmatch(expected_sha256):
        raise ValueError("external_sha256_pin_required")
    if hashlib.sha256(body).hexdigest() != expected_sha256:
        raise ValueError("pinned_example_sha256_mismatch")
    if type(interpreter) is not str or not Path(interpreter).is_file():
        raise ValueError("interpreter_not_verified")
    try:
        run = subprocess.run([interpreter, "-I", "-S", "-B", "-c", COMPILE_CHECK],
                             input=body, capture_output=True, timeout=4, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("interpreter_compile_probe_failed") from exc
    if run.returncode not in (0, 2, 3) or len(run.stdout) > 2048:
        raise ValueError("compile_subprocess_protocol_failed")
    try:
        result = json.loads(run.stdout)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("invalid_compile_subprocess_json") from exc
    if type(result) is not dict or result.get("status") not in (
            "COMPILE_ONLY_PASS", "SYNTAX_REJECTED", "TOO_LARGE"):
        raise ValueError("invalid_compile_result")
    expected = {0: "COMPILE_ONLY_PASS", 2: "SYNTAX_REJECTED", 3: "TOO_LARGE"}
    if result["status"] != expected[run.returncode]:
        raise ValueError("compile_result_conflict")
    return {"status": result["status"],
            "python_minor": result.get("python_minor", "unknown"),
            "sha256": expected_sha256, "fixture_bytes": len(body),
            "downloaded_code_executed": False,
            "source_leaked_in_report": False,
            "separate_python_interpreter_process": True}


class TrustedWorkerSupervisor:
    """Actual restartable subprocess ONLY for one fixed hardcoded safe worker."""

    def __init__(self, interpreter):
        if type(interpreter) is not str or not Path(interpreter).is_file():
            raise ValueError("trusted_worker_python_required")
        self.interpreter = interpreter
        self.child = None
        self.starts = 0

    def restart(self):
        self.close()
        self.child = subprocess.Popen(
            [self.interpreter, "-I", "-S", "-B", "-c", TRUSTED_WORKER],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        self.starts += 1
        time.sleep(0.025)
        if self.child.poll() is not None:
            self.close()
            raise ValueError("trusted_worker_failed_startup")
        return self.child.pid

    def close(self):
        if self.child is None:
            return
        if self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=0.8)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=0.8)
        self.child = None


def watch_cycles(conn, plans, fetch, cycles=2, pause_ms=10, supervisor=None,
                 on_cycle=None):
    """Bounded actual watch loop with retry, persisted state and child restart."""
    if (type(cycles) is not int or not 1 <= cycles <= MAX_CYCLES or
            type(pause_ms) is not int or not 0 <= pause_ms <= 1000):
        raise ValueError("unsafe_watch_quota")
    if supervisor is not None and not isinstance(supervisor, TrustedWorkerSupervisor):
        raise ValueError("untrusted_restart_callback")
    if on_cycle is not None and not callable(on_cycle):
        raise ValueError("invalid_trusted_cycle_hook")
    reports = []
    if supervisor is not None:
        supervisor.restart()
    try:
        for index in range(cycles):
            if on_cycle:
                on_cycle(index)
            try:
                result = apply_pinned_cycle(conn, plans, fetch)
                if supervisor is not None and result["updated"]:
                    supervisor.restart()
            except (OSError, ValueError, sqlite3.Error) as exc:
                result = {"status": "WATCH_RETRYABLE_OR_FAIL_CLOSED",
                          "reason_code": type(exc).__name__,
                          "untrusted_code_executed": False}
            reports.append(result)
            if index + 1 < cycles and pause_ms:
                time.sleep(pause_ms / 1000)
    finally:
        if supervisor is not None:
            supervisor.close()
    good = sum(report["status"] == "PINNED_OFFLINE_INCREMENTAL_CYCLE_PASS"
               for report in reports)
    return {"status": ("LOCAL_WATCH_ALL_CYCLES_PASS_NOT_OFFICIAL_UPDATER"
                       if good == cycles else "LOCAL_WATCH_INCOMPLETE"),
            "cycles": cycles, "successful_cycles": good,
            "failed_cycles": cycles-good, "cycle_reports": reports,
            "actual_subprocess_worker_starts": supervisor.starts if supervisor else 0,
            "real_restart_supervision_used": supervisor is not None,
            "unknown_project_code_executed": False,
            "official_internet_update_qualified": False}


def _fixture_cli_fetch(responses):
    replies = {url: list(rows) for url, rows in responses.items()}

    def adapter(url, _etag):
        queue = replies.get(url)
        if not queue:
            raise ValueError("fixture_response_missing")
        row = queue.pop(0)
        if type(row) is not dict:
            raise ValueError("invalid_fixture_response")
        if row.get("status") == 200 and type(row.get("body")) is str:
            return {"status": 200, "etag": row.get("etag"),
                    "body": row["body"].encode("utf-8")}
        return row
    return adapter


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "watch-fixture", "compile"),
                        default="capabilities")
    parser.add_argument("--db")
    parser.add_argument("--fixture-json")
    parser.add_argument("--watch", action="store_true",
                        help="Run only explicitly pinned local fixture cycles")
    parser.add_argument("--cycles", type=int, default=2)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--source")
    parser.add_argument("--sha256")
    args = parser.parse_args(argv)
    if args.watch != (args.mode == "watch-fixture"):
        parser.error("--watch is restricted to --mode watch-fixture")
    if args.mode == "capabilities":
        answer = {"status": "LOCAL_PINNED_KNOWLEDGE_CAPABILITIES_ONLY",
                  "features": ["F089_LOCAL_WATCH", "F214_COMPILE_ONLY", "F219_LEGACY_REPAIR"],
                  "network_accessed": False, "unknown_code_executed": False}
    elif args.mode == "compile":
        if not args.source or not args.sha256:
            parser.error("compile requires --source and --sha256")
        target = Path(args.source)
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_EXAMPLE_BYTES:
            parser.error("unsafe_source_file")
        answer = compile_pinned_example(target.read_bytes(), args.sha256, args.python)
    else:
        if not args.db or not args.fixture_json:
            parser.error("watch-fixture requires --db and --fixture-json")
        spec = json.loads(Path(args.fixture_json).read_text(encoding="utf-8"))
        if type(spec) is not dict or set(spec) != {"plans", "responses"}:
            parser.error("invalid_offline_fixture")
        with closing(checked_catalog(args.db)) as conn:
            answer = watch_cycles(conn, spec["plans"],
                                  _fixture_cli_fetch(spec["responses"]), args.cycles)
    print(json.dumps(answer, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
