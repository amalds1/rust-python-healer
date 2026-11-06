"""Bounded, append-only observed experiment accounting and replay statistics.

Records explicitly supplied event measurements in SQLite; never calls cloud
APIs, executes arbitrary test code or claims self-reported costs are audited.
The hash chain detects accidental damage, not an attacker able to rewrite an
entire local database. Human-approved policy is a separate input file.
"""

import argparse
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import statistics
from pathlib import Path
from urllib.parse import quote

MAX_BYTES = 1_048_576
MAX_EVENTS = 1000
MAX_RECORDED_EVENTS = 10000
MAX_LEDGER_BYTES = 64_000_000
SHA = re.compile(r"[a-f0-9]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z")
FIELDS = ("run_id", "runtime", "status", "retest", "submitted_ms",
          "started_ms", "finished_ms", "input_tokens", "output_tokens",
          "cloud_micro_usd", "provider")


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def bounded_json(path):
    """Read only unique bounded regular JSON; refuse duplicate dict keys."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError("input_symlink_refused")
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("input_not_unique_regular")
        if before.st_size > MAX_BYTES:
            raise ValueError("input_oversized")
        raw = handle.read(MAX_BYTES + 1)
        after = os.fstat(handle.fileno())
        if len(raw) > MAX_BYTES or (before.st_dev, before.st_ino, before.st_size,
                                   before.st_mtime_ns) != (after.st_dev, after.st_ino,
                                                             after.st_size, after.st_mtime_ns):
            raise ValueError("input_changed_or_oversized")

    def unique_pairs(pairs):
        result = {}
        for name, item in pairs:
            if name in result:
                raise ValueError("duplicate_json_key")
            result[name] = item
        return result

    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(
                          ValueError("nonfinite_json_number")))


def validate_policy(policy):
    """Policy thresholds are separate from and never chosen by a candidate."""
    required = {"schema_version", "policy_id", "minimum_repetitions",
                "maximum_latency_p95_ms", "maximum_wait_p95_ms",
                "maximum_cloud_micro_usd"}
    if not isinstance(policy, dict) or set(policy) != required or policy["schema_version"] != 1:
        raise ValueError("invalid_policy_schema")
    if not isinstance(policy["policy_id"], str) or not IDENT.fullmatch(policy["policy_id"]):
        raise ValueError("invalid_policy_identity")
    n = policy["minimum_repetitions"]
    if type(n) is not int or n < 10 or n > 1000:
        raise ValueError("at_least_ten_repetitions_required")
    for key in ("maximum_latency_p95_ms", "maximum_wait_p95_ms"):
        value = policy[key]
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0 or value > 60000:
            raise ValueError("invalid_latency_policy")
    cloud = policy["maximum_cloud_micro_usd"]
    if type(cloud) is not int or not 0 <= cloud <= 1_000_000_000_000:
        raise ValueError("invalid_cloud_budget")
    return policy


def validate_evidence(evidence):
    if not isinstance(evidence, dict) or set(evidence) != {"schema_version", "candidate", "runs"}:
        raise ValueError("invalid_evidence_schema")
    if evidence["schema_version"] != 1:
        raise ValueError("invalid_evidence_version")
    variant = evidence["candidate"]
    if not isinstance(variant, dict) or set(variant) != {
            "variant_id", "engine", "code_sha256", "config_sha256"}:
        raise ValueError("invalid_variant_shape")
    if not isinstance(variant["engine"], str) or not IDENT.fullmatch(variant["engine"]):
        raise ValueError("invalid_engine")
    for field in ("code_sha256", "config_sha256"):
        if not isinstance(variant[field], str) or not SHA.fullmatch(variant[field]):
            raise ValueError("invalid_variant_hash")
    identifier = "V-" + hashlib.sha256((variant["engine"] + ":" +
                    variant["code_sha256"] + ":" + variant["config_sha256"])
                    .encode("ascii")).hexdigest()[:16]
    if variant["variant_id"] != identifier:
        raise ValueError("variant_identity_mismatch")
    runs = evidence["runs"]
    if not isinstance(runs, list) or not 0 < len(runs) <= MAX_EVENTS:
        raise ValueError("invalid_run_count")
    seen = set()
    for i, row in enumerate(runs):
        if not isinstance(row, dict) or set(row) != set(FIELDS):
            raise ValueError("invalid_run_fields")
        for key in ("run_id", "runtime", "provider"):
            if not isinstance(row[key], str) or not IDENT.fullmatch(row[key]):
                raise ValueError("invalid_run_identity")
        if row["run_id"] in seen:
            raise ValueError("duplicate_run_id_without_retest")
        seen.add(row["run_id"])
        if row["status"] not in ("PASS", "FAIL", "NOT_RUN"):
            raise ValueError("invalid_run_status")
        if type(row["retest"]) is not bool or (i > 0 and not row["retest"]):
            raise ValueError("explicit_retest_required")
        for field in ("submitted_ms", "started_ms", "finished_ms"):
            if type(row[field]) not in (int, float) or not math.isfinite(row[field]) or not 0 <= row[field] <= 1e15:
                raise ValueError("invalid_timestamp")
        if not row["submitted_ms"] <= row["started_ms"] <= row["finished_ms"]:
            raise ValueError("impossible_timeline")
        for field in ("input_tokens", "output_tokens", "cloud_micro_usd"):
            if type(row[field]) is not int or not 0 <= row[field] <= 1_000_000_000:
                raise ValueError("invalid_usage_metric")
        if row["status"] == "NOT_RUN" and (row["finished_ms"] > row["started_ms"] or
                                           row["input_tokens"] or row["output_tokens"] or
                                           row["cloud_micro_usd"]):
            raise ValueError("not_run_has_usage_or_duration")
    if len({row["runtime"] for row in runs}) != 1:
        raise ValueError("mixed_runtimes_in_one_repetition_group")
    return variant, runs


def open_ledger(path, create=True):
    """Create/inspect an operator-selected unique regular SQLite ledger."""
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink() or not path.parent.is_dir():
        raise ValueError("unsafe_ledger_path")
    if path.exists():
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_LEDGER_BYTES:
            raise ValueError("ledger_not_unique_regular")
    elif not create:
        raise ValueError("missing_ledger")
    else:
        new_fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_RDWR |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(new_fd)
    if not create:
        # `mode=ro` prevents summary queries from migrating/creating a database.
        return sqlite3.connect("file:{}?mode=ro".format(quote(str(path.resolve()), safe="/")),
                               uri=True, timeout=10)
    connection = sqlite3.connect(str(path), timeout=10, isolation_level=None)
    connection.execute("PRAGMA busy_timeout=10000")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.executescript("""
CREATE TABLE IF NOT EXISTS usage_events (
 seq INTEGER PRIMARY KEY AUTOINCREMENT,
 variant_id TEXT NOT NULL,
 engine TEXT NOT NULL,
 code_sha256 TEXT NOT NULL,
 config_sha256 TEXT NOT NULL,
 policy_sha256 TEXT NOT NULL,
 run_id TEXT NOT NULL,
 runtime TEXT NOT NULL,
 status TEXT NOT NULL,
 retest INTEGER NOT NULL,
 submitted_ms REAL NOT NULL,
 started_ms REAL NOT NULL,
 finished_ms REAL NOT NULL,
 input_tokens INTEGER NOT NULL,
 output_tokens INTEGER NOT NULL,
 cloud_micro_usd INTEGER NOT NULL,
 provider TEXT NOT NULL,
 prev_sha256 TEXT NOT NULL,
 record_sha256 TEXT NOT NULL,
 UNIQUE(variant_id, run_id)
);
CREATE TRIGGER IF NOT EXISTS usage_no_update BEFORE UPDATE ON usage_events
BEGIN SELECT RAISE(ABORT, 'usage_events_immutable'); END;
CREATE TRIGGER IF NOT EXISTS usage_no_delete BEFORE DELETE ON usage_events
BEGIN SELECT RAISE(ABORT, 'usage_events_immutable'); END;
""")
    return connection


def stored_event(row):
    """Normalize database row into a stable signed-hash-chain JSON envelope."""
    keys = ("variant_id", "engine", "code_sha256", "config_sha256",
            "policy_sha256") + FIELDS
    event = {name: row[name] for name in keys}
    event["retest"] = bool(event["retest"])
    return event


def check_chain(rows):
    previous = "0" * 64
    for row in rows:
        if row["prev_sha256"] != previous:
            raise ValueError("evidence_hash_chain_broken")
        expected = hashlib.sha256(previous.encode("ascii") +
                                  canonical(stored_event(row))).hexdigest()
        if row["record_sha256"] != expected:
            raise ValueError("usage_evidence_tampered")
        previous = expected
    return previous


def ingest(db_path, policy, evidence):
    """Atomically append runs, reject duplicates and changes of declared policy."""
    validate_policy(policy)
    variant, runs = validate_evidence(evidence)
    policy_sha = fingerprint(policy)
    connection = open_ledger(db_path)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("BEGIN IMMEDIATE")
        all_rows = connection.execute(
            "SELECT * FROM usage_events ORDER BY seq LIMIT ?", (MAX_RECORDED_EVENTS + 1,)
        ).fetchall()
        if len(all_rows) + len(runs) > MAX_RECORDED_EVENTS:
            raise ValueError("ledger_record_limit")
        previous = check_chain(all_rows)
        prior = [row for row in all_rows if row["variant_id"] == variant["variant_id"]]
        if prior and (any(row["policy_sha256"] != policy_sha or
                          row["code_sha256"] != variant["code_sha256"] or
                          row["config_sha256"] != variant["config_sha256"] for row in prior)):
            raise ValueError("policy_or_variant_modified_between_runs")
        if prior and not runs[0]["retest"]:
            # First run_id in a fresh batch cannot silently become an implicit retry.
            raise ValueError("existing_candidate_requires_explicit_retest")
        if not prior and runs[0]["retest"]:
            raise ValueError("initial_run_cannot_be_retest")
        for row in runs:
            payload = dict(variant, policy_sha256=policy_sha, **row)
            for key in ("submitted_ms", "started_ms", "finished_ms"):
                payload[key] = float(payload[key])
            current = hashlib.sha256(previous.encode("ascii") +
                                     canonical(payload)).hexdigest()
            connection.execute("""INSERT INTO usage_events(
variant_id,engine,code_sha256,config_sha256,policy_sha256,run_id,runtime,status,
retest,submitted_ms,started_ms,finished_ms,input_tokens,output_tokens,
cloud_micro_usd,provider,prev_sha256,record_sha256)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                               (variant["variant_id"], variant["engine"],
                                variant["code_sha256"], variant["config_sha256"], policy_sha,
                                row["run_id"], row["runtime"], row["status"], int(row["retest"]),
                                row["submitted_ms"], row["started_ms"], row["finished_ms"],
                                row["input_tokens"], row["output_tokens"], row["cloud_micro_usd"],
                                row["provider"], previous, current))
            previous = current
        connection.commit()
        return {"status": "RECORDED_UNVERIFIED", "variant_id": variant["variant_id"],
                "events_added": len(runs), "chain_head_sha256": previous,
                "candidate_code_executed": False, "usage_independently_verified": False}
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def percentile(values, quantile):
    """Deterministic nearest-rank empirical percentile (not an estimate of a population)."""
    if not values:
        return None
    return sorted(values)[math.ceil(quantile * len(values)) - 1]


def summarize(rows, policy):
    """Observed usage, wait pressure, throughput and empirical median/p95."""
    validate_policy(policy)
    if not rows:
        return {"state": "NO_MEASUREMENTS", "runs": 0, "observations_verified": False}
    timeline = [dict(row) for row in rows]
    runtimes = sorted({row["runtime"] for row in timeline})
    passed = sum(row["status"] == "PASS" for row in timeline)
    failed = sum(row["status"] == "FAIL" for row in timeline)
    skipped = sum(row["status"] == "NOT_RUN" for row in timeline)
    delays = [row["started_ms"] - row["submitted_ms"] for row in timeline]
    service = [row["finished_ms"] - row["started_ms"] for row in timeline]
    span = max(row["finished_ms"] for row in timeline) - min(
        row["submitted_ms"] for row in timeline)
    edges = []
    for row in timeline:
        if row["started_ms"] > row["submitted_ms"]:
            edges.append((row["submitted_ms"], 1))
            edges.append((row["started_ms"], -1))
    pressure = 0
    peak_pressure = 0
    for _, delta in sorted(edges, key=lambda pair: (pair[0], pair[1])):
        pressure += delta
        peak_pressure = max(peak_pressure, pressure)
    latency_p95 = percentile(service, 0.95)
    wait_p95 = percentile(delays, 0.95)
    total_cost = sum(row["cloud_micro_usd"] for row in timeline)
    minimum = policy["minimum_repetitions"]
    if failed or skipped:
        stability = "OBSERVED_FAIL_OR_MISSING"
    elif len(timeline) < minimum:
        stability = "INSUFFICIENT_REPETITIONS"
    elif len(runtimes) > 1:
        stability = "INCONSISTENT_RUNTIME"
    else:
        stability = "TEN_OR_MORE_IDENTICAL_STATUS_RETESTS_RECORDED_NOT_PROVEN"
    limits = {
        "latency_p95_ms": latency_p95 <= policy["maximum_latency_p95_ms"],
        "wait_p95_ms": wait_p95 <= policy["maximum_wait_p95_ms"],
        "cloud_micro_usd": total_cost <= policy["maximum_cloud_micro_usd"],
        "min_repetitions": len(timeline) >= minimum and not failed and not skipped,
    }
    return {
        "state": stability,
        "runs": len(timeline), "runtimes": runtimes,
        "pass": passed, "fail": failed, "not_run": skipped,
        "total_input_tokens_recorded": sum(row["input_tokens"] for row in timeline),
        "total_output_tokens_recorded": sum(row["output_tokens"] for row in timeline),
        "total_cloud_micro_usd_recorded": total_cost,
        "duration_median_ms": statistics.median(service),
        "duration_p95_ms": latency_p95,
        "queue_wait_median_ms": statistics.median(delays),
        "queue_wait_p95_ms": wait_p95,
        "peak_queued_events": peak_pressure,
        "observed_throughput_runs_per_minute": round(len(timeline) * 60000 / span, 3) if span > 0 else None,
        "gate_results": limits,
        "all_numeric_gates_pass": all(limits.values()),
        "source_executed": False,
        "observations_verified": False,
        "note": "Accurate recorded arithmetic; self-reported runtime and cloud bills remain unverified",
    }


def report(db_path, policy, candidate_id):
    """Recheck entire ledger chain before reporting one candidate."""
    validate_policy(policy)
    if not isinstance(candidate_id, str) or not IDENT.fullmatch(candidate_id):
        raise ValueError("invalid_candidate_id")
    connection = open_ledger(db_path, create=False)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            "SELECT * FROM usage_events ORDER BY seq LIMIT ?", (MAX_RECORDED_EVENTS + 1,)
        ).fetchall()
        if len(rows) > MAX_RECORDED_EVENTS:
            raise ValueError("ledger_record_limit")
        head = check_chain(rows)
        selected = [row for row in rows if row["variant_id"] == candidate_id]
        if any(row["policy_sha256"] != fingerprint(policy) for row in selected):
            raise ValueError("report_policy_mismatch")
        data = summarize(selected, policy)
        return {"schema_version": 1, "status": "REPORTED_UNVERIFIED",
                "candidate": candidate_id, "ledger_events": len(rows),
                "evidence_chain_head_sha256": head,
                "statistics": data,
                "release_authorized": False, "tests_independently_executed": False}
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--evidence", type=Path)
    group.add_argument("--candidate")
    args = parser.parse_args()
    policy = bounded_json(args.policy)
    outcome = (ingest(args.db, policy, bounded_json(args.evidence)) if args.evidence else
               report(args.db, policy, args.candidate))
    print(json.dumps(outcome, sort_keys=True))


if __name__ == "__main__":
    main()
