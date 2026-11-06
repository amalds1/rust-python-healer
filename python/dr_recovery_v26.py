"""Fault-injected LOCAL disaster-recovery and release rollback drills.

Untrusted projects are never executed. The selftest owns all its temporary
SQLite files, simulated crash workers and locally signed canary artifacts.
User-selected recovery writes only a previously nonexistent destination.
This does not qualify off-host recovery, production RTO/RPO, other OSes or
external publisher signatures.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path


def _load_trusted_sibling(name):
    path = Path(__file__).resolve().parent / (name + ".py")
    spec = importlib.util.spec_from_file_location("rph_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


backup_drill = _load_trusted_sibling("backup_drill")
release_canary_v21 = _load_trusted_sibling("release_canary_v21")
platform_privacy = _load_trusted_sibling("platform_privacy_v028")


MAX_ARCHIVE_SIZE = 128 * 1024 * 1024
MAX_RTO_MS = 5000
MAX_RPO_LOST_COMMITS = 1
CRASH_CODE_BEFORE_COMMIT = 74
CRASH_CODE_AFTER_COMMIT = 75
TRUSTED_CRASH_WORKER = """
import os,sqlite3,sys,time
db,mode,sequence=sys.argv[1:]
connection=sqlite3.connect(db,timeout=2.0)
connection.execute('PRAGMA journal_mode=WAL')
connection.execute('PRAGMA synchronous=FULL')
connection.execute('INSERT INTO recovery_events(sequence,label,committed_at_ns) VALUES (?,?,?)',
                   (int(sequence),'trusted_crash_event',time.time_ns()))
if mode=='commit':
    connection.commit()
    os._exit(75)
if mode=='rollback':
    os._exit(74)
os._exit(76)
"""


def sha256_file(path, *, require_private=True):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        if os.name == "nt" and require_private:
            platform_privacy.private_descriptor(source.fileno(), "dr_hash_source_must_be_private")
        for chunk in iter(lambda: source.read(131072), b""):
            digest.update(chunk)
    return digest.hexdigest()


def private_dir(folder):
    folder = Path(folder)
    info = folder.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("dr_directory_must_be_private")
    if os.name == "nt":
        platform_privacy.private_directory(folder, "dr_directory_must_be_private")
    elif stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("dr_directory_must_be_private")
    return folder


def create_database(path):
    """Create only selftest's fresh file; never modify arbitrary source DBs."""
    path = Path(path)
    private_dir(path.parent)
    descriptor = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_RDWR |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if os.name == "nt":
            platform_privacy.private_descriptor(descriptor, "dr_created_database_must_be_private")
    finally:
        os.close(descriptor)
    with closing(sqlite3.connect(str(path))) as connection:
        journal = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        connection.execute("PRAGMA synchronous=FULL")
        if journal.lower() != "wal":
            raise ValueError("sqlite_wal_mode_not_activated")
        connection.execute("CREATE TABLE recovery_events (sequence INTEGER PRIMARY KEY, "
                           "label TEXT NOT NULL, committed_at_ns INTEGER NOT NULL)")
        connection.commit()


def append_committed_event(path, sequence, label):
    if type(sequence) is not int or sequence <= 0 or label not in {
            "before_snapshot", "after_snapshot"}:
        raise ValueError("invalid_trusted_event_fixture")
    with closing(sqlite3.connect(str(path))) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("INSERT INTO recovery_events VALUES (?,?,?)",
                           (sequence, label, time.time_ns()))
        connection.commit()


def event_rows(path):
    with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as conn:
        if conn.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ValueError("sqlite_integrity_failed")
        return conn.execute("SELECT sequence,label,committed_at_ns "
                            "FROM recovery_events ORDER BY sequence").fetchall()


def run_real_crash(db, commit):
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c",
                             TRUSTED_CRASH_WORKER, str(db),
                             "commit" if commit else "rollback",
                             "3" if commit else "2"], capture_output=True,
                            timeout=5, check=False)
    expected = CRASH_CODE_AFTER_COMMIT if commit else CRASH_CODE_BEFORE_COMMIT
    if result.returncode != expected or result.stdout or result.stderr:
        raise ValueError("trusted_child_process_crash_oracle_failed")
    return {"actual_exit_code": expected,
            "commit_was_explicitly_completed": bool(commit),
            "actual_child_process_crash": True,
            "unknown_project_code_executed": False}


def restore_verified(archive_directory, archive_filename, destination,
                     expected_sha256, expected_logical_sha256):
    """Restore a verified archived DB to a new private path, never overwrite.

    No source archiving, production release swap or mutable original is touched.
    The archive-directory ledger and every archived object are first verified.
    """
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64 or any(
            c not in "0123456789abcdef" for c in expected_sha256):
        raise ValueError("invalid_snapshot_sha256")
    if not isinstance(expected_logical_sha256, str) or len(expected_logical_sha256) != 64 or any(
            c not in "0123456789abcdef" for c in expected_logical_sha256):
        raise ValueError("invalid_logical_sha256")
    folder = private_dir(archive_directory)
    verification = backup_drill.verify_archives(folder)
    if verification["checked"] < 1:
        raise ValueError("no_verified_archives")
    if (not isinstance(archive_filename, str) or
            not archive_filename.startswith("backup-") or
            not archive_filename.endswith(".sqlite") or
            "/" in archive_filename or "\\" in archive_filename):
        raise ValueError("invalid_snapshot_archive_name")
    snapshot = folder / archive_filename
    info = snapshot.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_ARCHIVE_SIZE:
        raise ValueError("snapshot_not_unique_private_file")
    if sha256_file(snapshot) != expected_sha256:
        raise ValueError("archive_provenance_sha256_mismatch")
    with closing(sqlite3.connect(f"file:{snapshot}?mode=ro", uri=True)) as check:
        if backup_drill._logical_digest(check) != expected_logical_sha256:
            raise ValueError("logical_snapshot_mismatch")
    target = Path(destination)
    if not target.is_absolute() or target.parent.resolve() != target.parent:
        raise ValueError("absolute_private_destination_required")
    private_dir(target.parent)
    if target.parent == folder or target == snapshot:
        raise ValueError("destination_must_be_separate_from_archive")
    if target.exists() or target.is_symlink():
        raise FileExistsError("refuse_to_overwrite_existing_recovery_target")
    # Pre-3.13 Windows monotonic_ns uses a coarse tick clock and may report
    # zero for a successful fast restore. QPC-backed perf_counter_ns measures
    # the real elapsed interval without inventing a positive epsilon.
    started = time.perf_counter_ns()
    descriptor = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_RDWR |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    owned_info = os.fstat(descriptor)
    try:
        if os.name == "nt":
            platform_privacy.private_descriptor(descriptor, "dr_restore_target_must_be_private")
    finally:
        os.close(descriptor)
    try:
        with closing(sqlite3.connect(f"file:{snapshot}?mode=ro", uri=True)) as source:
            with closing(sqlite3.connect(str(target))) as restored:
                source.backup(restored)
                restored.commit()
                if backup_drill._logical_digest(restored) != expected_logical_sha256:
                    raise ValueError("post_restore_data_mismatch")
        if sha256_file(snapshot) != expected_sha256:
            raise ValueError("archive_changed_during_restore")
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
        return {"status": "LOCAL_RECOVERY_VERIFIED_NO_OVERWRITE",
                "rto_observed_ms": round(elapsed_ms, 5),
                "rto_clock": "perf_counter_ns",
                "rto_clock_resolution_seconds": time.get_clock_info("perf_counter").resolution,
                "snapshot_sha256": expected_sha256,
                "logical_sha256": expected_logical_sha256,
                "no_existing_destination_overwritten": True,
                "production_rto_qualified": False,
                "off_host_recovery_verified": False}
    except Exception:
        # Remove only the inode created exclusively by this operation, not
        # any concurrently substituted path owned by another operation.
        try:
            current = target.lstat()
        except FileNotFoundError:
            pass
        else:
            if ((current.st_dev, current.st_ino) ==
                    (owned_info.st_dev, owned_info.st_ino)):
                target.unlink()
        raise


def locally_signed_canary_failure(folder):
    """Exercise existing release rollback with fixed trusted JSON fixtures."""
    private_dir(folder)
    active = folder / "active.json"
    candidate = folder / "candidate.json"
    old = json.dumps({"release": "old", "health": "ready"}, sort_keys=True).encode()
    new = json.dumps({"release": "new", "health": "ready"}, sort_keys=True).encode()
    for path, content in ((active, old), (candidate, new)):
        descriptor = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    manifest = {"schema": 1, "operation": "local_canary",
                "old_sha256": hashlib.sha256(old).hexdigest(),
                "candidate_sha256": hashlib.sha256(new).hexdigest(),
                "release": "new", "actor": "drill-operator"}
    key = bytes(range(32))  # Known LOCAL test key; not a release publisher identity.
    signature = release_canary_v21.canary_signature(manifest, key)
    result = release_canary_v21.local_canary(
        active, candidate, manifest, signature, key, inject_health_failure=True)
    if (result["status"] != "CANARY_FAILED_ROLLED_BACK" or
            not result["automatic_rollback_verified"] or active.read_bytes() != old):
        raise ValueError("local_upgrade_rollback_not_verified")
    return {"locally_signed_test_approval_verified": result["approval_verified"],
            "rollback_verified": result["automatic_rollback_verified"],
            "original_sha256": result["active_sha256"],
            "durability_scope": result["durability_scope"],
            "production_release_authorized": False}


def selftest(*, max_rto_ms=MAX_RTO_MS, max_lost_commits=MAX_RPO_LOST_COMMITS):
    if (type(max_rto_ms) is not int or not 1 <= max_rto_ms <= 60000 or
            type(max_lost_commits) is not int or not 0 <= max_lost_commits <= 100):
        raise ValueError("invalid_predeclared_recovery_gate")
    with tempfile.TemporaryDirectory(prefix="trusted-dr-v26-") as raw:
        root = Path(raw)
        archive_dir = root / "archives"
        output_dir = root / "recovered"
        canary_dir = root / "canary"
        for folder in (archive_dir, output_dir, canary_dir):
            folder.mkdir(mode=0o700)
        db = root / "source.sqlite"
        create_database(db)
        append_committed_event(db, 1, "before_snapshot")
        before = run_real_crash(db, commit=False)
        if len(event_rows(db)) != 1 or any(row[0] == 2 for row in event_rows(db)):
            raise ValueError("precommit_crash_must_rollback")
        after = run_real_crash(db, commit=True)
        if [row[0] for row in event_rows(db)] != [1, 3]:
            raise ValueError("postcommit_crash_must_be_durable_in_wal")
        actual_wal = Path(str(db) + "-wal")
        if not actual_wal.exists() or actual_wal.stat().st_size == 0:
            raise ValueError("committed_sqlite_wal_not_present")
        snapshot = backup_drill.drill_once(db, archive_dir, "dr-v26")
        if backup_drill.verify_archives(archive_dir)["checked"] != 1:
            raise ValueError("archive_verification_failed")
        archive = archive_dir / snapshot["archive"]
        if [row[0] for row in event_rows(archive)] != [1, 3]:
            raise ValueError("committed_wal_rows_lost_from_archive")
        snapshot_ns = time.time_ns()
        append_committed_event(db, 4, "after_snapshot")
        fault_time_ns = time.time_ns()
        actual_rows = event_rows(db)
        recovered_path = output_dir / "new-recovered.sqlite"
        recovered = restore_verified(archive_dir, archive.name, recovered_path,
                                     snapshot["sha256"], snapshot["logical_sha256"])
        restored_rows = event_rows(recovered_path)
        if [row[0] for row in restored_rows] != [1, 3]:
            raise ValueError("recovery_snapshot_rows_changed")
        restored_ids = {row[0] for row in restored_rows}
        lost = [row for row in actual_rows if row[0] not in restored_ids]
        rpo_lost = len(lost)
        # Measured from the latest recovery checkpoint to the local simulated
        # failure event. Never interpreted as production RPO on another host.
        observed_rpo_seconds = max(0.0, (fault_time_ns - snapshot_ns) / 1e9)
        if rpo_lost != 1 or not lost or lost[0][0] != 4:
            raise ValueError("local_recovery_loss_count_inaccurate")
        if (recovered["rto_observed_ms"] > max_rto_ms or
                rpo_lost > max_lost_commits):
            raise ValueError("predeclared_local_rto_or_rpo_gate_failed")
        collision_sha = sha256_file(recovered_path)
        try:
            restore_verified(archive_dir, archive.name, recovered_path,
                             snapshot["sha256"], snapshot["logical_sha256"])
        except FileExistsError:
            pass
        else:
            raise ValueError("existing_recovery_destination_not_refused")
        if sha256_file(recovered_path) != collision_sha:
            raise ValueError("existing_recovery_destination_was_changed")
        # Only a DISPOSABLE duplicate is corrupted; the verified original
        # archive and user input never suffer fault injection.
        copy = root / "corrupt-candidate.sqlite"
        shutil.copyfile(archive, copy)
        with copy.open("r+b") as stream:
            stream.seek(0)
            stream.write(b"CORRUPTED_SQLITE")
        if sha256_file(copy) == snapshot["sha256"]:
            raise ValueError("fault_injection_failed_to_change_checksum")
        if sha256_file(archive) != snapshot["sha256"]:
            raise ValueError("original_archive_mutated_during_fault_injection")
        canary = locally_signed_canary_failure(canary_dir)
        return {"status": "LOCAL_WAL_CRASH_RESTORE_RTO_RPO_GATES_PASS",
                "actual_python_patch": ".".join(map(str, sys.version_info[:3])),
                "real_child_crashes": [before, after],
                "sqlite_runtime_version": sqlite3.sqlite_version,
                "wal_committed_snapshot_verified": True,
                "snapshot_sha256": snapshot["sha256"],
                "snapshot_ledger_chain_verified": True,
                "backup_logical_sha256": snapshot["logical_sha256"],
                "rto_observed_ms": recovered["rto_observed_ms"],
                "rto_gate_ms": max_rto_ms,
                "rpo_lost_commits_observed": rpo_lost,
                "rpo_lost_commits_gate": max_lost_commits,
                "rpo_checkpoint_to_simulated_fault_seconds": round(observed_rpo_seconds, 6),
                "negative_existing_output_never_overwritten": True,
                "negative_corrupt_snapshot_copy_detected": True,
                "local_canary_rollback": canary,
                "trusted_fixture_code_executed": True,
                "unknown_project_executed": False,
                "independent_off_host_audit": False,
                "production_disaster_recovery_qualified": False,
                "native_windows_macos_crash_qualified": False,
                "trial_source_sha256": sha256_file(Path(__file__).resolve(), require_private=False),
                "external_release_approved": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("selftest", "restore"), required=True)
    parser.add_argument("--max-rto-ms", type=int, default=MAX_RTO_MS)
    parser.add_argument("--max-lost-commits", type=int, default=MAX_RPO_LOST_COMMITS)
    parser.add_argument("--archive-dir", type=Path)
    parser.add_argument("--archive")
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--snapshot-sha256")
    parser.add_argument("--logical-sha256")
    args = parser.parse_args(argv)
    try:
        if args.mode == "selftest":
            if any(value is not None for value in (args.archive_dir, args.archive,
                    args.destination, args.snapshot_sha256, args.logical_sha256)):
                raise ValueError("selftest_must_use_owned_disposable_fixtures")
            result = selftest(max_rto_ms=args.max_rto_ms,
                              max_lost_commits=args.max_lost_commits)
        else:
            if any(value is None for value in (args.archive_dir, args.archive,
                    args.destination, args.snapshot_sha256, args.logical_sha256)):
                raise ValueError("restore_requires_explicit_provenance_and_destination")
            result = restore_verified(args.archive_dir, args.archive, args.destination,
                                      args.snapshot_sha256, args.logical_sha256)
    except (ValueError, OSError, sqlite3.Error, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "NO_PASS", "reason": type(exc).__name__,
                          "production_qualified": False, "unknown_project_executed": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
