"""Append-only, authenticated SQLite decisions for the six-axis policy gate.

An operator must separately protect the auditor keys and this log's HMAC key.
SQLite+HMAC detects alteration of retained rows; it cannot independently
prove real-world test execution, protect against whole-ledger rollback or
establish physical WORM immutability without external archival anchoring.
Never runs project code, tests, installers, or package modules.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
import stat
from urllib.parse import quote

from qualification_policy import bounded_file, canonical, digest, qualify


MAX_EVENTS = 10_000
MAX_DATABASE_BYTES = 64_000_000
MAX_REPORT_BYTES = 128_000
ZERO_HASH = "0" * 64
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,95}\Z")
FIELDS = (
    "seq", "run_id", "variant_set_sha256", "policy_sha256", "evidence_sha256",
    "recorded_at_utc", "retest", "report_json", "report_sha256",
    "previous_chain_sha256", "chain_sha256", "mac_sha256",
)


def checked_key(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "key_hex"}:
        raise ValueError("invalid_audit_trust_file")
    if data["schema_version"] != 1 or not isinstance(data["key_hex"], str) or not HEX64.fullmatch(data["key_hex"]):
        raise ValueError("invalid_audit_key")
    return bytes.fromhex(data["key_hex"])


def variant_set_hash(report):
    return digest(sorted(row["variant_id"] for row in report["decision_log"]))


def protected_database_path(path, create):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("audit_database_symlink_refused")
    if path.exists():
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_DATABASE_BYTES:
            raise ValueError("audit_database_not_unique_bounded_file")
    elif not create:
        raise ValueError("audit_database_not_found")
    elif not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError("audit_database_parent_refused")
    return path


def open_database(path, create):
    path = protected_database_path(path, create)
    if create:
        # SQLite manages the database and journals. An independently protected
        # outer workspace boundary is still required against root swapping.
        connection = sqlite3.connect(str(path), isolation_level=None, timeout=5)
    else:
        absolute = str(path.resolve())
        connection = sqlite3.connect("file:" + quote(absolute, safe="/") + "?mode=ro",
                                     uri=True, timeout=5)
        connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA trusted_schema=OFF")
    return connection


def install_schema(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
          seq INTEGER PRIMARY KEY AUTOINCREMENT,
          run_id TEXT NOT NULL UNIQUE,
          variant_set_sha256 TEXT NOT NULL,
          policy_sha256 TEXT NOT NULL,
          evidence_sha256 TEXT NOT NULL,
          recorded_at_utc TEXT NOT NULL,
          retest INTEGER NOT NULL CHECK (retest IN (0,1)),
          report_json TEXT NOT NULL,
          report_sha256 TEXT NOT NULL,
          previous_chain_sha256 TEXT NOT NULL,
          chain_sha256 TEXT NOT NULL,
          mac_sha256 TEXT NOT NULL
        )
    """)
    connection.execute("""
        CREATE TRIGGER IF NOT EXISTS audit_no_update
        BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT,'immutable_audit_entry'); END
    """)
    connection.execute("""
        CREATE TRIGGER IF NOT EXISTS audit_no_delete
        BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'immutable_audit_entry'); END
    """)


def event_body(event):
    return {name: event[name] for name in FIELDS if name not in ("chain_sha256", "mac_sha256")}


def checked_report(report):
    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise ValueError("invalid_report_schema")
    if report.get("status") != "POLICY_EVALUATED_NOT_BEHAVIORALLY_PROVEN":
        raise ValueError("report_status_not_accepted")
    if (report.get("source_executed") is not False or
            report.get("release_authorized") is not False or
            report.get("independent_execution_verified") is not False):
        raise ValueError("report_verification_claims_invalid")
    primary, reserve = report.get("primary_variant"), report.get("reserve_variant")
    if primary is not None and (not isinstance(primary, str) or not RUN_ID.fullmatch(primary)):
        raise ValueError("invalid_primary_identity")
    if reserve is not None and (not isinstance(reserve, str) or not RUN_ID.fullmatch(reserve)):
        raise ValueError("invalid_reserve_identity")
    if reserve == primary and reserve is not None:
        raise ValueError("primary_and_reserve_must_differ")
    if report.get("maximum_reserves") != 1:
        raise ValueError("reserve_budget_invalid")
    if report.get("decision") == "NO_WINNER" and (primary is not None or reserve is not None):
        raise ValueError("no_winner_must_not_have_variants")
    if report.get("decision") == "POLICY_PRIMARY_EXISTS" and primary is None:
        raise ValueError("policy_primary_required")
    if report.get("decision") not in ("NO_WINNER", "POLICY_PRIMARY_EXISTS"):
        raise ValueError("invalid_decision")
    if report.get("audit_record_sha256") != digest(report.get("decision_log")):
        raise ValueError("decision_log_hash_invalid")


def row_event(row):
    return dict(zip(FIELDS, row))


def verify_connection(connection, key):
    columns = [row[1] for row in connection.execute("PRAGMA table_info(audit_events)")]
    if columns != list(FIELDS):
        raise ValueError("audit_schema_missing_or_modified")
    count = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    if not 0 <= count <= MAX_EVENTS:
        raise ValueError("audit_event_quota_exceeded")
    previous, last_seq, seen_runs = ZERO_HASH, 0, set()
    seen_instances = set()
    for row in connection.execute("SELECT * FROM audit_events ORDER BY seq"):
        entry = row_event(row)
        if (entry["seq"] != last_seq + 1 or
                not isinstance(entry["run_id"], str) or not RUN_ID.fullmatch(entry["run_id"]) or
                entry["run_id"] in seen_runs or
                entry["previous_chain_sha256"] != previous or
                entry["retest"] not in (0, 1)):
            raise ValueError("audit_chain_sequence_broken")
        if (not isinstance(entry["report_json"], str) or
                len(entry["report_json"].encode("utf-8")) > MAX_REPORT_BYTES):
            raise ValueError("audit_report_size_refused")
        if hashlib.sha256(entry["report_json"].encode("utf-8")).hexdigest() != entry["report_sha256"]:
            raise ValueError("audit_report_sha256_mismatch")
        try:
            report = json.loads(entry["report_json"])
        except (ValueError, TypeError, UnicodeError):
            raise ValueError("invalid_audit_report_json")
        checked_report(report)
        if (report.get("policy_sha256") != entry["policy_sha256"] or
                report.get("evidence_sha256") != entry["evidence_sha256"] or
                variant_set_hash(report) != entry["variant_set_sha256"]):
            raise ValueError("audit_input_hash_mismatch")
        instance = (entry["policy_sha256"], entry["variant_set_sha256"])
        if instance in seen_instances and entry["retest"] != 1:
            raise ValueError("missing_explicit_retest")
        if instance not in seen_instances and entry["retest"] != 0:
            raise ValueError("unexpected_first_retest")
        seen_instances.add(instance)
        actual_chain = digest(event_body(entry))
        if entry["chain_sha256"] != actual_chain:
            raise ValueError("audit_chain_sha256_mismatch")
        expected_mac = hmac.new(key, bytes.fromhex(actual_chain), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_mac, entry["mac_sha256"]):
            raise ValueError("audit_hmac_invalid")
        previous = actual_chain
        last_seq = entry["seq"]
        seen_runs.add(entry["run_id"])
    return {"status": "AUDIT_CHAIN_VERIFIED_NOT_WORM", "events": last_seq,
            "chain_tip_sha256": previous, "release_authorized": False,
            "behavioral_correctness": "NOT_VERIFIED", "source_executed": False,
            "note": "Verified retained SQLite rows and operator HMAC; whole-ledger rollback "
                    "or authorized key compromise requires an external checkpoint"}


def verify_database(path, secret):
    key = checked_key(secret)
    connection = open_database(path, False)
    try:
        return verify_connection(connection, key)
    finally:
        connection.close()


def append_decision(path, policy, trust, evidence, secret, run_id, retest=False):
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise ValueError("invalid_audit_run_id")
    if type(retest) is not bool:
        raise ValueError("explicit_retest_boolean_required")
    key = checked_key(secret)
    # Never accept arbitrary caller-supplied decision reports; recompute the
    # exact candidate ranking from all verified six-axis evidence first.
    report = qualify(policy, trust, evidence)
    checked_report(report)
    encoded = canonical(report).decode("ascii")
    if len(encoded.encode("ascii")) > MAX_REPORT_BYTES:
        raise ValueError("audit_report_size_refused")
    candidate_set = variant_set_hash(report)
    connection = open_database(path, True)
    try:
        connection.execute("BEGIN IMMEDIATE")
        install_schema(connection)
        status = verify_connection(connection, key)
        if status["events"] >= MAX_EVENTS:
            raise ValueError("audit_event_quota_exceeded")
        earlier = connection.execute(
            "SELECT seq, run_id, chain_sha256 FROM audit_events "
            "WHERE policy_sha256=? AND evidence_sha256=?",
            (report["policy_sha256"], report["evidence_sha256"])).fetchone()
        if earlier:
            if earlier[1] != run_id:
                raise ValueError("duplicate_evidence_new_run_id_refused")
            connection.execute("ROLLBACK")
            return {"status": "ALREADY_RECORDED_NO_NEW_MEASUREMENT",
                    "seq": earlier[0], "chain_tip_sha256": earlier[2],
                    "release_authorized": False, "source_executed": False}
        if connection.execute("SELECT 1 FROM audit_events WHERE run_id=?", (run_id,)).fetchone():
            raise ValueError("audit_run_id_conflict")
        old = connection.execute(
            "SELECT 1 FROM audit_events WHERE policy_sha256=? AND variant_set_sha256=? LIMIT 1",
            (report["policy_sha256"], candidate_set)).fetchone()
        if bool(old) != retest:
            raise ValueError("explicit_retest_required_or_unexpected")
        previous = status["chain_tip_sha256"]
        seq = status["events"] + 1
        entry = {
            "seq": seq, "run_id": run_id, "variant_set_sha256": candidate_set,
            "policy_sha256": report["policy_sha256"],
            "evidence_sha256": report["evidence_sha256"],
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "retest": int(retest), "report_json": encoded,
            "report_sha256": hashlib.sha256(encoded.encode("ascii")).hexdigest(),
            "previous_chain_sha256": previous,
        }
        entry["chain_sha256"] = digest(event_body(entry))
        entry["mac_sha256"] = hmac.new(key, bytes.fromhex(entry["chain_sha256"]),
                                          hashlib.sha256).hexdigest()
        connection.execute(
            "INSERT INTO audit_events (" + ",".join(FIELDS) + ") VALUES (" +
            ",".join("?" for _ in FIELDS) + ")",
            [entry[name] for name in FIELDS])
        connection.execute("COMMIT")
        verified = verify_connection(connection, key)
        if verified["events"] != seq or verified["chain_tip_sha256"] != entry["chain_sha256"]:
            raise ValueError("audit_commit_verification_failed")
        return {"status": "AUDIT_RECORDED_AUTHENTICATED_NOT_WORM",
                "seq": seq, "decision": report["decision"],
                "primary_variant": report["primary_variant"],
                "reserve_variant": report["reserve_variant"],
                "chain_tip_sha256": entry["chain_sha256"],
                "events": verified["events"],
                "source_executed": False, "release_authorized": False,
                "independent_execution_verified": False}
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--audit-key", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--trust", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--retest", action="store_true")
    args = parser.parse_args()
    try:
        secret = bounded_file(args.audit_key)
        if args.verify:
            if any((args.policy, args.trust, args.evidence, args.run_id, args.retest)):
                raise ValueError("verify_mode_read_only_only")
            report = verify_database(args.db, secret)
        else:
            if not all((args.policy, args.trust, args.evidence, args.run_id)):
                raise ValueError("policy_trust_evidence_and_run_id_required")
            report = append_decision(
                args.db, bounded_file(args.policy), bounded_file(args.trust),
                bounded_file(args.evidence), secret, args.run_id, retest=args.retest)
        print(json.dumps(report))
    except (ValueError, KeyError, TypeError, sqlite3.Error, OSError) as exc:
        # Never expose raw parser content, source, credentials, exception paths
        # or user-provided database bytes in stdout/stderr.
        reason = str(exc)
        if not re.fullmatch(r"[a-z0-9_]+", reason):
            reason = "audit_failed_closed"
        print(json.dumps({"status": "REJECTED", "reason": reason,
                          "source_executed": False, "release_authorized": False}))
        raise SystemExit(2)


if __name__ == "__main__":
    main()
