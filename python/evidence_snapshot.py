"""Append-only experiment snapshots, minimum retention and archival copies.

Source bytes are never executed. HMAC signatures authenticate submitted
metadata only against a separately managed operator key; this is NOT a
publisher attestation or a defense against a malicious database administrator.
"""

import argparse
from contextlib import closing
import hashlib
import hmac
import importlib.util
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time


SCHEMA_VERSION = 1
MAX_SOURCE_BYTES = 1_048_576
MAX_EXPERIMENTS = 1_000
MAX_SNAPSHOTS = 10_000
MAX_EVENTS = 50_000
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=True).encode("ascii")


def hash_value(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def validate_identity(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError("invalid_snapshot_identity")
    return value


def validate_hex(value):
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise ValueError("invalid_sha_or_key")
    return value


@lru_cache(maxsize=2)
def _windows_helper(kind):
    injection, filename = {
        "privacy": ("_RPH_WINDOWS_PRIVACY", "windows_private_paths.py"),
        "source": ("_RPH_WINDOWS_SECURITY", "windows_descriptor_security_v029.py"),
    }[kind]
    embedded = globals().get(injection)
    if embedded is not None:
        return embedded
    spec = importlib.util.spec_from_file_location("rph_evidence_" + kind,
        Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_bytes(path):
    """Bounded no-follow snapshot of a unique regular file, not execution."""
    target = Path(path)
    if target.is_symlink():
        raise ValueError("source_symlink_refused")
    previous = target.lstat()
    if (not stat.S_ISREG(previous.st_mode) or previous.st_nlink != 1
            or previous.st_size > MAX_SOURCE_BYTES):
        raise ValueError("source_not_unique_regular_bounded_file")
    if os.name == "nt":
        try:
            location = target.absolute()
            return _windows_helper("source").read_project_file(
                location.parent, [location.name], MAX_SOURCE_BYTES)
        except (ValueError, OSError):
            raise ValueError("source_modified_or_oversized") from None
    descriptor = os.open(str(target), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_size > MAX_SOURCE_BYTES):
            raise ValueError("source_not_unique_regular_bounded_file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            content = stream.read(MAX_SOURCE_BYTES + 1)
            after = os.fstat(stream.fileno())
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
            or len(content) != before.st_size or len(content) > MAX_SOURCE_BYTES or
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise ValueError("source_modified_or_oversized")
    return content


def auditor_key_from_file(path):
    """Read one protected key on the same no-follow descriptor.

    POSIX retains owner-only mode checks. Windows requires currentowner/DACL
    privacy and holds the checked HANDLE. This does not attest an auditor.
    """
    target = Path(path)
    if target.is_symlink():
        raise ValueError("auditor_key_symlink_refused")
    if os.name == "nt":
        try:
            descriptor = _windows_helper("privacy").open_private_readonly(target.absolute())
        except (ValueError, OSError):
            raise ValueError("auditor_key_not_protected_regular_file") from None
    else:
        descriptor = os.open(str(target), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                             getattr(os, "O_NONBLOCK", 0))
    try:
        details = os.fstat(descriptor)
        if (not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or
                (os.name != "nt" and details.st_mode & 0o077) or details.st_size > 65):
            raise ValueError("auditor_key_not_protected_regular_file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(66)
            if os.name == "nt":
                try:
                    _windows_helper("privacy").assert_private_file_descriptor(stream.fileno())
                except (ValueError, OSError):
                    raise ValueError("auditor_key_not_protected_regular_file") from None
            after = os.fstat(stream.fileno())
            if (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
                    or (os.name != "nt" and after.st_mode & 0o077)
                    or len(raw) != details.st_size
                    or (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns) !=
                       (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                raise ValueError("auditor_key_modified_during_read")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        key = raw.decode("ascii").rstrip("\n")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid_auditor_key_encoding") from exc
    return validate_hex(key)


def payload(experiment_id, variant_id, code_sha256, config_sha256, created_at):
    validate_identity(experiment_id)
    validate_identity(variant_id)
    validate_hex(code_sha256)
    validate_hex(config_sha256)
    if type(created_at) is not int or not 0 <= created_at <= 4_102_444_800:
        raise ValueError("invalid_creation_time")
    return {"experiment_id": experiment_id, "variant_id": variant_id,
            "code_sha256": code_sha256, "config_sha256": config_sha256,
            "created_at": created_at}


def sign_for_test(experiment_id, variant_id, code_sha256, config_sha256,
                  created_at, auditor_key_hex):
    """Trusted fixture signer only; production signer must be independent."""
    validate_hex(auditor_key_hex)
    return hmac.new(bytes.fromhex(auditor_key_hex), canonical(payload(
        experiment_id, variant_id, code_sha256, config_sha256, created_at)),
        hashlib.sha256).hexdigest()


def database(path):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink() or not path.parent.is_dir():
        raise ValueError("unsafe_snapshot_database_path")
    try:
        old = path.stat()
    except FileNotFoundError:
        old = None
    if old is not None and (not stat.S_ISREG(old.st_mode) or old.st_nlink != 1 or
                            old.st_size > 128 * 1024 * 1024):
        raise ValueError("snapshot_database_not_unique_bounded_file")
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=3.0)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise ValueError("future_snapshot_schema_refused")
        if version not in (0, SCHEMA_VERSION):
            raise ValueError("unknown_snapshot_schema")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=3000")
        if version == 0:
            try:
                conn.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE IF NOT EXISTS experiments(
                      experiment_id TEXT PRIMARY KEY,
                      minimum_retention_days INTEGER NOT NULL,
                      archive_after_days INTEGER NOT NULL,
                      policy_sha256 TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS snapshots(
                      snapshot_id TEXT PRIMARY KEY,
                      experiment_id TEXT NOT NULL REFERENCES experiments(experiment_id),
                      variant_id TEXT NOT NULL, code_sha256 TEXT NOT NULL,
                      config_sha256 TEXT NOT NULL, created_at INTEGER NOT NULL,
                      recorded_at INTEGER NOT NULL,
                      source_signature TEXT NOT NULL, source_blob BLOB NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS archive_copies(
                      snapshot_id TEXT PRIMARY KEY REFERENCES snapshots(snapshot_id),
                      archived_at INTEGER NOT NULL,
                      source_blob BLOB NOT NULL, archive_sha256 TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS audit_events(
                      seq INTEGER PRIMARY KEY AUTOINCREMENT,
                      snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id),
                      action TEXT NOT NULL, event_at INTEGER NOT NULL,
                      previous_sha256 TEXT NOT NULL, event_sha256 TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_experiment_snapshots
                      ON snapshots(experiment_id, created_at, snapshot_id);
                    CREATE TRIGGER immutable_experiments_update BEFORE UPDATE ON experiments
                      BEGIN SELECT RAISE(ABORT,'immutable_experiment'); END;
                    CREATE TRIGGER immutable_experiments_delete BEFORE DELETE ON experiments
                      BEGIN SELECT RAISE(ABORT,'immutable_experiment'); END;
                    CREATE TRIGGER immutable_snapshots_update BEFORE UPDATE ON snapshots
                      BEGIN SELECT RAISE(ABORT,'immutable_snapshot'); END;
                    CREATE TRIGGER immutable_snapshots_delete BEFORE DELETE ON snapshots
                      BEGIN SELECT RAISE(ABORT,'immutable_snapshot'); END;
                    CREATE TRIGGER immutable_archive_update BEFORE UPDATE ON archive_copies
                      BEGIN SELECT RAISE(ABORT,'immutable_archive'); END;
                    CREATE TRIGGER immutable_archive_delete BEFORE DELETE ON archive_copies
                      BEGIN SELECT RAISE(ABORT,'immutable_archive'); END;
                    CREATE TRIGGER immutable_events_update BEFORE UPDATE ON audit_events
                      BEGIN SELECT RAISE(ABORT,'immutable_event'); END;
                    CREATE TRIGGER immutable_events_delete BEFORE DELETE ON audit_events
                      BEGIN SELECT RAISE(ABORT,'immutable_event'); END;
                    PRAGMA user_version=1;
                    COMMIT;
                """)
            except Exception:
                conn.rollback()
                raise
        expected = {
            "experiments": ("experiment_id", "minimum_retention_days",
                            "archive_after_days", "policy_sha256"),
            "snapshots": ("snapshot_id", "experiment_id", "variant_id", "code_sha256",
                          "config_sha256", "created_at", "recorded_at",
                          "source_signature", "source_blob"),
            "archive_copies": ("snapshot_id", "archived_at", "source_blob", "archive_sha256"),
            "audit_events": ("seq", "snapshot_id", "action", "event_at",
                             "previous_sha256", "event_sha256"),
        }
        for table, names in expected.items():
            found = tuple(row[1] for row in conn.execute(
                "PRAGMA table_info({})".format(table)))
            if found != names:
                raise ValueError("snapshot_schema_not_authoritative")
        triggers = {row[0]: row[1] for row in conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='trigger'")}
        required_triggers = {"immutable_experiments_update", "immutable_experiments_delete",
                "immutable_snapshots_update", "immutable_snapshots_delete",
                "immutable_archive_update", "immutable_archive_delete",
                "immutable_events_update", "immutable_events_delete"}
        if not required_triggers.issubset(triggers):
            raise ValueError("snapshot_immutability_triggers_missing")
        for name in required_triggers:
            trigger_sql = triggers[name].upper()
            action = "UPDATE" if name.endswith("_update") else "DELETE"
            table = {"immutable_experiments": "EXPERIMENTS",
                     "immutable_snapshots": "SNAPSHOTS",
                     "immutable_archive": "ARCHIVE_COPIES",
                     "immutable_events": "AUDIT_EVENTS"}[name.rsplit("_", 1)[0]]
            if ("BEFORE {} ON {}".format(action, table) not in trigger_sql or
                    "RAISE(ABORT" not in trigger_sql):
                raise ValueError("snapshot_immutability_triggers_corrupted")
        fks = {table: conn.execute("PRAGMA foreign_key_list({})".format(table)).fetchall()
               for table in ("snapshots", "archive_copies", "audit_events")}
        if (not any(row[2] == "experiments" for row in fks["snapshots"]) or
                not any(row[2] == "snapshots" for row in fks["archive_copies"]) or
                not any(row[2] == "snapshots" for row in fks["audit_events"])):
            raise ValueError("snapshot_foreign_keys_missing")
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        conn.close()
        raise


def register_experiment(conn, experiment_id, retention_days, archive_after_days,
                        policy_sha256):
    validate_identity(experiment_id)
    validate_hex(policy_sha256)
    if (type(retention_days) is not int or not 1 <= retention_days <= 3650 or
            type(archive_after_days) is not int or not 0 <= archive_after_days <= retention_days):
        raise ValueError("invalid_experiment_retention_policy")
    row = {"experiment_id": experiment_id, "minimum_retention_days": retention_days,
           "archive_after_days": archive_after_days, "policy_sha256": policy_sha256}
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        old = conn.execute("SELECT * FROM experiments WHERE experiment_id=?",
                           (experiment_id,)).fetchone()
        if old is not None:
            if any(old[field] != value for field, value in row.items()):
                raise ValueError("immutable_retention_policy_conflict")
            status = "EXISTING_POLICY_NOT_MUTATED"
        else:
            if conn.execute("SELECT COUNT(*) FROM experiments").fetchone()[0] >= MAX_EXPERIMENTS:
                raise ValueError("experiment_quota_exceeded")
            conn.execute("INSERT INTO experiments VALUES(?,?,?,?)", tuple(row.values()))
            status = "POLICY_REGISTERED"
    return {"status": status, "experiment_id": experiment_id,
            "retention_days": retention_days, "archive_after_days": archive_after_days,
            "source_executed": False}


def next_event(conn, snapshot_id, action, now):
    """Append-only local hash chain, not externally anchored/attested."""
    previous = conn.execute("SELECT event_sha256 FROM audit_events "
                            "ORDER BY seq DESC LIMIT 1").fetchone()
    prev = previous[0] if previous else "0" * 64
    record = {"snapshot_id": snapshot_id, "action": action,
              "event_at": now, "previous_sha256": prev}
    digest = hash_value(record)
    conn.execute("INSERT INTO audit_events(snapshot_id, action, event_at, previous_sha256, "
                 "event_sha256) VALUES(?,?,?,?,?)",
                 (snapshot_id, action, now, prev, digest))
    return digest


def record_snapshot(conn, experiment_id, variant_id, code_path, config_sha256,
                    created_at, source_signature, auditor_key_hex):
    """Store exactly signed source bytes, immutable even after archiving."""
    code = source_bytes(code_path)
    code_sha256 = hashlib.sha256(code).hexdigest()
    data = payload(experiment_id, variant_id, code_sha256, config_sha256, created_at)
    validate_hex(auditor_key_hex)
    validate_hex(source_signature)
    expected = hmac.new(bytes.fromhex(auditor_key_hex), canonical(data),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(source_signature, expected):
        raise ValueError("source_signature_invalid")
    snapshot_id = hash_value(data)
    recorded_at = int(time.time())
    if created_at > recorded_at + 300:
        raise ValueError("future_snapshot_creation_time_refused")
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        policy = conn.execute("SELECT experiment_id FROM experiments WHERE experiment_id=?",
                              (experiment_id,)).fetchone()
        if policy is None:
            raise ValueError("missing_registered_experiment")
        old = conn.execute("SELECT * FROM snapshots WHERE snapshot_id=?",
                           (snapshot_id,)).fetchone()
        if old is not None:
            if (old["source_blob"] != code or
                    old["source_signature"] != source_signature):
                raise ValueError("conflicting_immutable_snapshot")
            status = "ALREADY_RECORDED_NO_RETEST"
        else:
            if conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0] >= MAX_SNAPSHOTS:
                raise ValueError("snapshot_quota_exceeded")
            if conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] >= MAX_EVENTS:
                raise ValueError("audit_event_quota_exceeded")
            conn.execute("INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?,?)",
                         (snapshot_id, experiment_id, variant_id, code_sha256,
                          config_sha256, created_at, recorded_at, source_signature, code))
            next_event(conn, snapshot_id, "CREATED", recorded_at)
            status = "IMMUTABLE_SNAPSHOT_RECORDED"
    return {"status": status, "snapshot_id": snapshot_id,
            "source_sha256": code_sha256, "size_bytes": len(code),
            "source_executed": False, "signature_checked": True,
            "source_publisher_authenticated": False}


def archive_snapshot(conn, snapshot_id, now=None):
    validate_hex(snapshot_id)
    actual_now = int(time.time())
    if now is None:
        now = actual_now
    if type(now) is not int or not 0 <= now <= 4_102_444_800:
        raise ValueError("invalid_archive_time")
    if abs(now - actual_now) > 300:
        raise ValueError("untrusted_archive_clock_skew")
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT s.*, e.archive_after_days, e.minimum_retention_days "
                           "FROM snapshots s JOIN experiments e ON e.experiment_id=s.experiment_id "
                           "WHERE s.snapshot_id=?", (snapshot_id,)).fetchone()
        if row is None:
            return {"status": "NOT_FOUND", "source_executed": False}
        existing = conn.execute("SELECT snapshot_id FROM archive_copies WHERE snapshot_id=?",
                                (snapshot_id,)).fetchone()
        if existing:
            return {"status": "ALREADY_ARCHIVED", "snapshot_id": snapshot_id,
                    "source_executed": False}
        if now < row["recorded_at"] + row["archive_after_days"] * 86400:
            return {"status": "RETENTION_WINDOW_ACTIVE", "snapshot_id": snapshot_id,
                    "source_executed": False}
        if conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] >= MAX_EVENTS:
            raise ValueError("audit_event_quota_exceeded")
        code = row["source_blob"]
        digest = hashlib.sha256(code).hexdigest()
        if digest != row["code_sha256"]:
            raise ValueError("snapshot_bytes_corrupted")
        conn.execute("INSERT INTO archive_copies VALUES(?,?,?,?)",
                     (snapshot_id, now, code, digest))
        next_event(conn, snapshot_id, "ARCHIVED", now)
    return {"status": "ARCHIVED_COPY_RECORDED", "snapshot_id": snapshot_id,
            "source_sha256": digest, "source_executed": False,
            "minimum_retention_enforced": True,
            "deletion_performed": False}


def verify_snapshot(conn, snapshot_id, auditor_key_hex, now=None):
    validate_hex(snapshot_id)
    validate_hex(auditor_key_hex)
    if now is None:
        now = int(time.time())
    if type(now) is not int or not 0 <= now <= 4_102_444_800:
        raise ValueError("invalid_verification_time")
    row = conn.execute("SELECT s.*, e.minimum_retention_days, "
                       "e.archive_after_days FROM snapshots s "
                       "JOIN experiments e ON e.experiment_id=s.experiment_id "
                       "WHERE s.snapshot_id=?", (snapshot_id,)).fetchone()
    if row is None:
        return {"status": "NOT_FOUND", "source_executed": False}
    source_ok = hashlib.sha256(row["source_blob"]).hexdigest() == row["code_sha256"]
    expected_signature = sign_for_test(row["experiment_id"], row["variant_id"],
                                       row["code_sha256"], row["config_sha256"],
                                       row["created_at"], auditor_key_hex)
    signature_ok = hmac.compare_digest(row["source_signature"], expected_signature)
    archived = conn.execute("SELECT * FROM archive_copies WHERE snapshot_id=?",
                            (snapshot_id,)).fetchone()
    archive_ok = (archived is None or
                  archived["source_blob"] == row["source_blob"] and
                  archived["archive_sha256"] == row["code_sha256"])
    archive_policy_ok = (archived is None or
                         archived["archived_at"] >= row["recorded_at"] +
                         row["archive_after_days"] * 86400)
    retention_expiry = row["recorded_at"] + row["minimum_retention_days"] * 86400
    status = "LOCAL_INTEGRITY_MATCH_NOT_EXTERNAL_ATTESTATION" if (
        source_ok and signature_ok and archive_ok and archive_policy_ok) else "INVALID"
    return {"status": status, "snapshot_id": snapshot_id,
            "source_sha256": row["code_sha256"], "source_hash_match": source_ok,
            "operator_hmac_match": signature_ok, "archive_bytes_match": archive_ok,
            "archive_retention_policy_match": archive_policy_ok,
            "archived": archived is not None, "retention_expires_at": retention_expiry,
            "retention_window_active": now < retention_expiry,
            "retention_basis": "local_ingest_clock_not_external_timestamp_attestation",
            "source_executed": False, "source_publisher_authenticated": False,
            "external_audit_verified": False}


def inspect(conn):
    """Non-mutating audit of local immutable rows and append-only event chain."""
    foreign = conn.execute("PRAGMA foreign_key_check").fetchall()
    quick = conn.execute("PRAGMA quick_check(1)").fetchone()[0]
    events = conn.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
    previous = "0" * 64
    broken_chain = 0
    for row in events:
        record = {"snapshot_id": row["snapshot_id"], "action": row["action"],
                  "event_at": row["event_at"], "previous_sha256": previous}
        expected = hash_value(record)
        if (row["previous_sha256"] != previous or
                row["event_sha256"] != expected):
            broken_chain += 1
        previous = row["event_sha256"]
    tampered_blobs = conn.execute("""
      SELECT s.snapshot_id,s.source_blob,s.code_sha256,a.source_blob,a.archive_sha256,
             s.experiment_id,s.variant_id,s.config_sha256,s.created_at,
             e.minimum_retention_days,e.archive_after_days,s.recorded_at,a.archived_at
      FROM snapshots s LEFT JOIN archive_copies a ON a.snapshot_id=s.snapshot_id
      LEFT JOIN experiments e ON s.experiment_id=e.experiment_id
    """).fetchall()
    mismatches = 0
    for (snapshot_id, code, digest, archive_code, archive_digest, experiment_id,
         variant_id, config_sha, created_at, retain_days, archive_days,
         recorded_at, archived_at) in tampered_blobs:
        try:
            expected_id = hash_value(payload(experiment_id, variant_id, digest,
                                             config_sha, created_at))
        except (ValueError, TypeError):
            expected_id = None
        if (hashlib.sha256(code).hexdigest() != digest or
                snapshot_id != expected_id or
                archive_code is not None and
                (archive_code != code or archive_digest != digest) or
                not isinstance(retain_days, int) or not 1 <= retain_days <= 3650 or
                not isinstance(archive_days, int) or not 0 <= archive_days <= retain_days or
                not isinstance(recorded_at, int) or recorded_at + 300 < created_at or
                archived_at is not None and
                archived_at < recorded_at + archive_days * 86400):
            mismatches += 1
    inconsistent_events = 0
    by_snapshot = {}
    for row in events:
        by_snapshot.setdefault(row["snapshot_id"], []).append(row)
    for snapshot_id, _, _, _, _, _, _, _, _, _, _, recorded_at, archived_at in tampered_blobs:
        actions = by_snapshot.pop(snapshot_id, [])
        expected = ["CREATED"] + (["ARCHIVED"] if archived_at is not None else [])
        if ([event["action"] for event in actions] != expected or
                not actions or actions[0]["event_at"] != recorded_at or
                archived_at is not None and actions[-1]["event_at"] != archived_at):
            inconsistent_events += 1
    inconsistent_events += len(by_snapshot)
    good = (quick == "ok" and not foreign and not broken_chain and
            not mismatches and not inconsistent_events)
    return {"status": "LOCAL_LEDGER_INTACT_NOT_EXTERNAL_ATTESTATION" if good else "INVALID",
            "experiments": conn.execute("SELECT COUNT(*) FROM experiments").fetchone()[0],
            "snapshots": conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0],
            "archives": conn.execute("SELECT COUNT(*) FROM archive_copies").fetchone()[0],
            "events": len(events), "chain_breaks": broken_chain,
            "blob_mismatches": mismatches, "inconsistent_events": inconsistent_events,
            "foreign_key_violations": len(foreign),
            "external_anchor_verified": False,
            "all_sources_publishers_verified": False, "source_executed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("init")
    p = sub.add_parser("experiment")
    p.add_argument("--id", required=True)
    p.add_argument("--retention-days", required=True, type=int)
    p.add_argument("--archive-after-days", required=True, type=int)
    p.add_argument("--policy-sha256", required=True)
    p = sub.add_parser("record")
    p.add_argument("--experiment", required=True)
    p.add_argument("--variant", required=True)
    p.add_argument("--code", required=True, type=Path)
    p.add_argument("--config-sha256", required=True)
    p.add_argument("--created-at", required=True, type=int)
    p.add_argument("--signature", required=True)
    p.add_argument("--auditor-key-file", required=True, type=Path)
    p = sub.add_parser("archive")
    p.add_argument("--snapshot", required=True)
    p.add_argument("--now", type=int)
    p = sub.add_parser("verify")
    p.add_argument("--snapshot", required=True)
    p.add_argument("--auditor-key-file", required=True, type=Path)
    p.add_argument("--now", type=int)
    sub.add_parser("check")
    args = parser.parse_args()
    with closing(database(args.db)) as conn:
        if args.action == "init" or args.action == "check":
            report = inspect(conn)
        elif args.action == "experiment":
            report = register_experiment(conn, args.id, args.retention_days,
                                         args.archive_after_days, args.policy_sha256)
        elif args.action == "record":
            report = record_snapshot(conn, args.experiment, args.variant, args.code,
                                     args.config_sha256, args.created_at,
                                     args.signature,
                                     auditor_key_from_file(args.auditor_key_file))
        elif args.action == "archive":
            report = archive_snapshot(conn, args.snapshot, args.now)
        elif args.action == "verify":
            report = verify_snapshot(conn, args.snapshot,
                                     auditor_key_from_file(args.auditor_key_file),
                                     args.now)
        else:
            raise ValueError("unexpected_snapshot_action")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
