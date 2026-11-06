"""Offline periodic WAL-consistent SQLite backup and restore verification.

The caller explicitly opts into watching a specified local database. This is
not an OS scheduler, off-host disaster recovery, external attestation or a
claim that untrusted concurrent filesystem owners cannot race the backup.
"""

import argparse
from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time


MAX_DB_BYTES = 128 * 1024 * 1024
MAX_ARCHIVES = 200
MAX_LEDGER_BYTES = 150_000
ID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,39}\Z")


def _platform_adapter():
    embedded = globals().get("_RPH_PLATFORM_PRIVACY")
    if embedded is not None:
        return embedded
    path = Path(__file__).resolve().parent / "platform_privacy_v028.py"
    spec = importlib.util.spec_from_file_location("rph_backup_platform_privacy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


platform_privacy = _platform_adapter()


def _private_regular(path, *, maximum):
    source = Path(path)
    info = source.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_size < 0 or info.st_size > maximum):
        raise ValueError("source_must_be_unique_bounded_file")
    if os.name == "nt":
        descriptor = os.open(str(source), os.O_RDONLY)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                    info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
                raise ValueError("backup_source_changed_during_open")
            platform_privacy.private_descriptor(descriptor, "backup_file_must_be_owner_private")
        finally:
            os.close(descriptor)
    return source


def _private_directory(path):
    folder = Path(path)
    info = folder.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("backup_directory_must_be_owner_only")
    if os.name == "nt":
        platform_privacy.private_directory(folder, "backup_directory_must_be_owner_only")
    elif stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("backup_directory_must_be_owner_only")
    return folder


def _hash(path):
    digest = hashlib.sha256()
    before = Path(path).lstat()
    with Path(path).open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("backup_hash_source_changed_during_open")
        if os.name == "nt":
            platform_privacy.private_descriptor(stream.fileno(), "backup_hash_file_not_private")
        total = 0
        for block in iter(lambda: stream.read(131072), b""):
            total += len(block)
            if total > MAX_DB_BYTES:
                raise ValueError("backup_hash_source_exceeds_budget")
            digest.update(block)
        after = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("backup_hash_source_changed_during_read")
    return digest.hexdigest()


def _logical_digest(conn):
    result = conn.execute("PRAGMA integrity_check").fetchone()
    if result != ("ok",):
        raise ValueError("sqlite_integrity_check_failed")
    digest = hashlib.sha256()
    for row in conn.iterdump():
        digest.update(row.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _read_ledger(folder):
    ledger = folder / "drill-ledger.jsonl"
    if not ledger.exists():
        return [], "0" * 64
    _private_regular(ledger, maximum=MAX_LEDGER_BYTES)
    rows = []
    previous = "0" * 64
    for line in ledger.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if set(row) != {"archive", "backup_sha256", "logical_sha256", "previous",
                        "sequence", "event_sha256", "schema_version"}:
            raise ValueError("invalid_drill_chain_schema")
        expected = hashlib.sha256(json.dumps(
            {key: val for key, val in row.items() if key != "event_sha256"},
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if row["previous"] != previous or row["event_sha256"] != expected or \
                row["sequence"] != len(rows) + 1:
            raise ValueError("invalid_drill_chain")
        if not ID.fullmatch(row["archive"].removeprefix("backup-").removesuffix(".sqlite")):
            raise ValueError("invalid_archive_id")
        rows.append(row)
        previous = expected
        if len(rows) > MAX_ARCHIVES:
            raise ValueError("archive_count_limit")
    return rows, previous


def verify_archives(folder):
    """Check local immutable-name hash manifest plus every archived snapshot."""
    directory = _private_directory(folder)
    rows, _ = _read_ledger(directory)
    recorded = {row["archive"] for row in rows}
    actual = {entry.name for entry in directory.glob("backup-*.sqlite")}
    if recorded != actual:
        # A crash between atomic archive creation and ledger append must not
        # silently turn into a valid backup set on the next verification.
        raise ValueError("untracked_or_missing_archive")
    checked = 0
    for row in rows:
        path = _private_regular(directory / row["archive"], maximum=MAX_DB_BYTES)
        if _hash(path) != row["backup_sha256"]:
            raise ValueError("archive_checksum_mismatch")
        with closing(sqlite3.connect("file:{}?mode=ro".format(path), uri=True)) as conn:
            if _logical_digest(conn) != row["logical_sha256"]:
                raise ValueError("archive_logical_mismatch")
        checked += 1
    return {"status": "LOCAL_BACKUPS_VERIFIED_NOT_EXTERNAL_ATTESTATION",
            "checked": checked, "external_anchor_verified": False,
            "source_executed": False}


def drill_once(database_path, backup_directory, identifier):
    """Snapshot current committed WAL state and restore to a disposable DB."""
    source = _private_regular(database_path, maximum=MAX_DB_BYTES)
    directory = _private_directory(backup_directory)
    if not ID.fullmatch(identifier):
        raise ValueError("invalid_backup_identifier")
    rows, previous = _read_ledger(directory)
    if len(rows) >= MAX_ARCHIVES:
        raise ValueError("archive_count_limit")
    target = directory / ("backup-" + identifier + ".sqlite")
    if target.exists() or target.is_symlink():
        raise ValueError("archive_already_exists")
    # The underlying SQLite backup API reads a transactionally consistent
    # image that includes committed records still held in source WAL files.
    fd, raw = tempfile.mkstemp(prefix=".new-snapshot-", dir=str(directory))
    os.close(fd)
    staging = Path(raw)
    try:
        with closing(sqlite3.connect("file:{}?mode=ro".format(source), uri=True)) as reader:
            with closing(sqlite3.connect(str(staging))) as writer:
                reader.backup(writer)
                writer.commit()
        if os.name != "nt":
            staging.chmod(0o600)
        snapshot_hash = _hash(staging)
        with closing(sqlite3.connect("file:{}?mode=ro".format(staging), uri=True)) as copy:
            logical = _logical_digest(copy)
        with tempfile.TemporaryDirectory(prefix="drill-restore-", dir=str(directory)) as restore_dir:
            restored_path = Path(restore_dir) / "restored.sqlite"
            with closing(sqlite3.connect("file:{}?mode=ro".format(staging), uri=True)) as original:
                with closing(sqlite3.connect(str(restored_path))) as restored:
                    original.backup(restored)
                    restored.commit()
                    if _logical_digest(restored) != logical:
                        raise ValueError("restored_database_differs")
        # os.link is atomic non-overwrite; source staging is our own file.
        os.link(str(staging), str(target), follow_symlinks=False)
        row = {"schema_version": 1, "archive": target.name,
               "backup_sha256": snapshot_hash, "logical_sha256": logical,
               "previous": previous, "sequence": len(rows) + 1}
        row["event_sha256"] = hashlib.sha256(json.dumps(
            row, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        entry = json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
        ledger = directory / "drill-ledger.jsonl"
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(str(ledger), flags, 0o600)
        try:
            if os.name == "nt":
                platform_privacy.private_descriptor(descriptor, "backup_ledger_not_private")
            os.write(descriptor, entry.encode("utf-8"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return {"status": "DRILL_RESTORED_AND_SHA_VERIFIED",
                "archive": target.name, "sha256": snapshot_hash,
                "logical_sha256": logical, "sequence": row["sequence"],
                "restoration_verified": True,
                "wal_committed_state_included": True,
                "periodic_service_required": True,
                "source_executed": False, "external_attestation": False}
    finally:
        if staging.exists():
            staging.unlink()


def scheduled_drills(database_path, directory, *, cycles=3, interval_ms=25,
                     identifier_prefix="local"):
    """Run real timed cycles while this explicit opt-in service is alive."""
    if type(cycles) is not int or not 1 <= cycles <= 10:
        raise ValueError("invalid_cycle_count")
    if type(interval_ms) is not int or not 5 <= interval_ms <= 60000:
        raise ValueError("invalid_period")
    if not ID.fullmatch(identifier_prefix):
        raise ValueError("invalid_periodic_name")
    measurements = []
    for number in range(cycles):
        if number:
            time.sleep(interval_ms / 1000.0)
        started = time.monotonic()
        detail = drill_once(database_path, directory,
                            "{}-{:02d}".format(identifier_prefix, number + 1))
        measurements.append({"sequence": detail["sequence"],
                             "sha256": detail["sha256"],
                             "restore_verified": detail["restoration_verified"],
                             "elapsed_ms": round((time.monotonic() - started) * 1000, 4)})
    verification = verify_archives(directory)
    if verification["checked"] < len(measurements):
        raise ValueError("periodic_restore_did_not_verify_all")
    return {"status": "PERIODIC_LOCAL_DRILLS_VERIFIED",
            "cycles": cycles, "interval_ms": interval_ms,
            "measurements": measurements, "all_restores_verified": True,
            "external_scheduler_installed": False,
            "source_executed": False, "external_attestation": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True)
    parser.add_argument("--archive-dir", required=True)
    parser.add_argument("--id", default="local")
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--interval-ms", type=int, default=25)
    parser.add_argument("--action", choices=("watch", "once", "verify"), default="once")
    args = parser.parse_args()
    try:
        if args.action == "watch":
            report = scheduled_drills(args.database, args.archive_dir, cycles=args.cycles,
                                      interval_ms=args.interval_ms, identifier_prefix=args.id)
        elif args.action == "once":
            report = drill_once(args.database, args.archive_dir, args.id)
        else:
            report = verify_archives(args.archive_dir)
    except (ValueError, OSError, sqlite3.Error, json.JSONDecodeError):
        print(json.dumps({"status": "NOT_RUN", "reason": "invalid_source_or_archive",
                          "source_executed": False}))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
