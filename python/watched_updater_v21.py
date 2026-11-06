"""Watched update *metadata* with conditional ETags and trusted HTTP stubs.

No network client or updater binary deployment is implemented. Fetch callbacks
are trusted test/integration adapters; response bodies are JSON data only and
must match a separately pinned SHA256 before storage/restart notification.
"""

import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import stat
import time
from urllib.parse import urlsplit


SCHEMA_VERSION = 1
MAX_BODY_BYTES = 1_048_576
SHA = re.compile(r"[0-9a-f]{64}\Z")
STRONG_ETAG = re.compile(r'"[A-Za-z0-9._:-]{1,96}"\Z')
PY_MINOR = re.compile(r"3\.(?:9|1[0-9]|[2-9][0-9])\Z")


def trusted_manifest(raw):
    """Validate versioned metadata layout, NOT publisher authenticity."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BODY_BYTES:
        raise ValueError("invalid_update_body_length")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("invalid_update_manifest_json") from exc
    if (type(obj) is not dict or set(obj) != {"schema_version", "python_minor",
                                           "metadata_sha256"} or
            obj["schema_version"] != 1 or
            type(obj["python_minor"]) is not str or
            not PY_MINOR.fullmatch(obj["python_minor"]) or
            type(obj["metadata_sha256"]) is not str or
            not SHA.fullmatch(obj["metadata_sha256"])):
        raise ValueError("invalid_update_manifest_schema")
    return obj


def _safe_https(url):
    if not isinstance(url, str) or len(url) > 768 or "\x00" in url:
        raise ValueError("invalid_update_url")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid_update_url") from exc
    if (parsed.scheme != "https" or not hostname or parsed.netloc != hostname or
            parsed.username is not None or parsed.password is not None or
            port is not None or parsed.query or parsed.fragment or
            any(c in url for c in " \t\r\n<>'\"\\")):
        raise ValueError("unsafe_update_url")
    return url


def database(path):
    target = Path(path)
    if target.is_symlink() or target.parent.is_symlink() or not target.parent.is_dir():
        raise ValueError("unsafe_watched_update_database_path")
    try:
        old = target.stat()
    except FileNotFoundError:
        old = None
    if old is not None and (not stat.S_ISREG(old.st_mode) or old.st_nlink != 1 or
                            old.st_size > 128 * 1024 * 1024):
        raise ValueError("watched_update_db_not_unique_bounded")
    conn = sqlite3.connect(str(target), isolation_level=None, timeout=4.0)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        v = conn.execute("PRAGMA user_version").fetchone()[0]
        if v not in (0, SCHEMA_VERSION):
            raise ValueError("unsupported_future_watched_update_schema")
        conn.execute("PRAGMA journal_mode=WAL")
        if v == 0:
            try:
                conn.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE update_state(
                      source_url TEXT PRIMARY KEY, etag TEXT NOT NULL,
                      content_sha256 TEXT NOT NULL, python_minor TEXT NOT NULL,
                      metadata BLOB NOT NULL, revision INTEGER NOT NULL,
                      restart_pending INTEGER NOT NULL,
                      installed_at INTEGER NOT NULL
                    );
                    CREATE TABLE update_events(
                      event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                      source_url TEXT NOT NULL REFERENCES update_state(source_url),
                      action TEXT NOT NULL, revision INTEGER NOT NULL,
                      event_at INTEGER NOT NULL
                    );
                    CREATE TRIGGER immutable_update_event BEFORE UPDATE ON update_events
                    BEGIN SELECT RAISE(ABORT,'immutable_update_event'); END;
                    CREATE TRIGGER forbid_update_event_delete BEFORE DELETE ON update_events
                    BEGIN SELECT RAISE(ABORT,'immutable_update_event'); END;
                    PRAGMA user_version=1;
                    COMMIT;
                """)
            except Exception:
                conn.rollback()
                raise
        expected = {
            "update_state": ("source_url", "etag", "content_sha256", "python_minor",
                             "metadata", "revision", "restart_pending", "installed_at"),
            "update_events": ("event_id", "source_url", "action", "revision",
                              "event_at"),
        }
        for table, cols in expected.items():
            actual = tuple(r[1] for r in conn.execute(
                "PRAGMA table_info({})".format(table)))
            if actual != cols:
                raise ValueError("invalid_watched_update_database_schema")
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        conn.close()
        raise


def _event(conn, url, action, revision):
    conn.execute("INSERT INTO update_events(source_url,action,revision,event_at) "
                 "VALUES(?,?,?,?)", (url, action, revision, int(time.time())))


def _mark_restart(conn, url, revision, restart):
    if restart is None or not callable(restart):
        return False
    try:
        restart(url, revision)
    except Exception:
        return False
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        state = conn.execute("SELECT revision,restart_pending FROM update_state "
                             "WHERE source_url=?", (url,)).fetchone()
        if (state is None or state["revision"] != revision or
                state["restart_pending"] != 1):
            return False
        conn.execute("UPDATE update_state SET restart_pending=0 WHERE source_url=?",
                     (url,))
        _event(conn, url, "RESTART_NOTIFICATION_ACCEPTED", revision)
    return True


def watch_once(conn, url, fetch, expected_sha256, restart=None):
    """Conditional GET from caller-provided trusted stub, SHA pin, restart.

    Never initiates HTTP itself, executes manifest code or restarts a process.
    Callback notification is not proof that the production process restarted.
    """
    _safe_https(url)
    if not isinstance(expected_sha256, str) or not SHA.fullmatch(expected_sha256):
        return {"status": "AUTHENTICATED_DIGEST_REQUIRED",
                "network_called": False, "restart_executed": False,
                "source_code_executed": False}
    if not callable(fetch):
        raise ValueError("trusted_fetch_adapter_required")
    prior = conn.execute("SELECT * FROM update_state WHERE source_url=?",
                         (url,)).fetchone()
    etag = prior["etag"] if prior else None
    answer = fetch(url, etag)
    if type(answer) is not dict or type(answer.get("status")) is not int:
        raise ValueError("invalid_http_stub_response")
    if answer["status"] == 304:
        if prior is None:
            raise ValueError("unexpected_304_without_prior_etag")
        if prior["content_sha256"] != expected_sha256:
            raise ValueError("stale_expected_digest_for_304")
        if prior["restart_pending"]:
            accepted = _mark_restart(conn, url, prior["revision"], restart)
            return {"status": "RESTART_ACKNOWLEDGED" if accepted else
                    "RESTART_PENDING", "source_code_executed": False,
                    "network_called": False, "restart_notification_accepted": accepted}
        return {"status": "NOT_MODIFIED_ETAG_HIT", "source_code_executed": False,
                "network_called": False, "restart_notification_accepted": False}
    if answer["status"] != 200:
        raise ValueError("unsupported_http_stub_status")
    new_etag, raw = answer.get("etag"), answer.get("body")
    if type(new_etag) is not str or not STRONG_ETAG.fullmatch(new_etag):
        raise ValueError("invalid_strong_etag")
    metadata = trusted_manifest(raw)
    body_sha = hashlib.sha256(raw).hexdigest()
    if body_sha != expected_sha256:
        raise ValueError("pinned_update_sha256_mismatch")
    if (prior is not None and prior["etag"] == new_etag and
            prior["content_sha256"] != body_sha):
        raise ValueError("etag_same_identity_different_content_refused")
    if (prior is not None and
            int(metadata["python_minor"].split(".")[1]) <
            int(prior["python_minor"].split(".")[1])):
        raise ValueError("python_version_rollback_refused")
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute("SELECT * FROM update_state WHERE source_url=?",
                               (url,)).fetchone()
        if ((prior is None) != (current is None) or
                prior is not None and (current["etag"] != prior["etag"] or
                                       current["revision"] != prior["revision"])):
            raise ValueError("concurrent_watched_update_conflict")
        if current is not None and current["content_sha256"] == body_sha:
            if current["etag"] != new_etag:
                raise ValueError("etag_content_identity_conflict")
            revision = current["revision"]
            unchanged = True
        else:
            revision = current["revision"] + 1 if current is not None else 1
            if current is None:
                conn.execute("INSERT INTO update_state VALUES(?,?,?,?,?,?,?,?)",
                             (url, new_etag, body_sha, metadata["python_minor"],
                              raw, revision, 1, int(time.time())))
            else:
                conn.execute("UPDATE update_state SET etag=?,content_sha256=?,"
                             "python_minor=?,metadata=?,revision=?,restart_pending=1,"
                             "installed_at=? WHERE source_url=?",
                             (new_etag, body_sha, metadata["python_minor"], raw,
                              revision, int(time.time()), url))
            _event(conn, url, "PINNED_METADATA_STAGED", revision)
            unchanged = False
    acknowledged = _mark_restart(conn, url, revision, restart)
    return {"status": ("ALREADY_STAGED_RESTART_ACKNOWLEDGED" if acknowledged else
                       "ALREADY_STAGED_RESTART_PENDING") if unchanged else
                       ("PINNED_METADATA_STAGED_RESTART_ACKNOWLEDGED" if acknowledged
                        else "PINNED_METADATA_STAGED_RESTART_PENDING"),
            "source_url": url, "revision": revision, "etag": new_etag,
            "python_minor": metadata["python_minor"],
            "pinned_sha256_checked": True,
            "external_publisher_authenticated": False,
            "source_code_executed": False,
            "network_called": False,
            "production_process_restarted_verified": False,
            "restart_notification_accepted": acknowledged}


def inspect(conn):
    rows = conn.execute("SELECT * FROM update_state ORDER BY source_url").fetchall()
    anomalies = 0
    for row in rows:
        try:
            if (hashlib.sha256(row["metadata"]).hexdigest() != row["content_sha256"] or
                    trusted_manifest(row["metadata"])["python_minor"] != row["python_minor"] or
                    row["restart_pending"] not in (0, 1) or
                    not STRONG_ETAG.fullmatch(row["etag"])):
                anomalies += 1
        except (ValueError, TypeError):
            anomalies += 1
    return {"status": "LOCAL_WATCHED_METADATA_INTACT_NOT_PUBLISHER_AUTHENTICATED"
            if anomalies == 0 else "INVALID", "records": len(rows),
            "events": conn.execute("SELECT COUNT(*) FROM update_events").fetchone()[0],
            "anomalies": anomalies, "publisher_authenticated": False,
            "network_called": False, "binary_deployed": False,
            "actual_process_restart_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("action", choices=("init", "check"))
    args = parser.parse_args()
    with closing(database(args.db)) as conn:
        report = inspect(conn)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
