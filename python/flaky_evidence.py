"""Conservative repeated-test evidence analyzer; never executes tested code.

An imported JSON record is untrusted self-reporting, NOT independent proof
of correctness, sandboxing, or even that the claimed test actually ran.
"""

import argparse
from collections import defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import re


MAX_BYTES = 1_000_000
MAX_RUNS = 10_000
IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,95}\Z")
STATUSES = frozenset(("PASS", "FAIL", "NOT_RUN"))
MIN_REPEATS = 3


def inspect(data):
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("invalid_evidence_schema")
    rows = data.get("runs")
    if not isinstance(rows, list) or not 0 < len(rows) <= MAX_RUNS:
        raise ValueError("invalid_run_count")
    groups = defaultdict(list)
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid_run_record")
        fields = ("candidate", "case", "runtime", "run_id")
        if any(not isinstance(row.get(k), str) or not IDENTITY.fullmatch(row[k]) for k in fields):
            raise ValueError("invalid_run_identity")
        if not isinstance(row.get("status"), str) or row["status"] not in STATUSES:
            raise ValueError("invalid_run_status")
        millis = row.get("duration_ms")
        if type(millis) not in (int, float) or not math.isfinite(millis) or millis < 0 or millis > 3_600_000:
            raise ValueError("invalid_run_duration")
        if type(row.get("retest")) is not bool:
            raise ValueError("retest_flag_required")
        key = (row["candidate"], row["case"], row["runtime"])
        fingerprint = key + (row["run_id"],)
        if fingerprint in seen:
            raise ValueError("duplicate_run_id")
        seen.add(fingerprint)
        group = groups[key]
        if bool(group) != row["retest"]:
            # Only explicit RETEST counts as a later measurement.
            raise ValueError("repeated_run_requires_retest")
        group.append(row["status"])
    findings = []
    for (candidate, case, runtime), outcomes in sorted(groups.items()):
        distinct = set(outcomes)
        if "NOT_RUN" in distinct:
            state = "INCOMPLETE"
        elif len(outcomes) < MIN_REPEATS:
            state = "INSUFFICIENT"
        elif len(distinct) > 1:
            state = "FLAKY"
        elif distinct == {"PASS"}:
            state = "REPEATABLE_PASS_NOT_VERIFIED"
        else:
            state = "REPEATABLE_FAIL"
        findings.append({
            "candidate": candidate,
            "case": case,
            "runtime": runtime,
            "runs": len(outcomes),
            "pass": outcomes.count("PASS"),
            "fail": outcomes.count("FAIL"),
            "not_run": outcomes.count("NOT_RUN"),
            "state": state,
        })
    summary = {state: sum(row["state"] == state for row in findings) for state in
               ("FLAKY", "INCOMPLETE", "INSUFFICIENT", "REPEATABLE_PASS_NOT_VERIFIED", "REPEATABLE_FAIL")}
    return {
        "status": "ANALYZED_NOT_INDEPENDENTLY_VERIFIED",
        "groups": findings,
        "summary": summary,
        "measurements": len(rows),
        "repetitions_per_group_required": MIN_REPEATS,
        "behavioral_correctness": "NOT_VERIFIED",
        "source_executed": False,
        "note": "Input statuses are untrusted assertions; no independent behavior oracle or execution sandbox",
    }


def inspect_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("evidence_file_refused")
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        contents = stream.read(MAX_BYTES + 1)
    if len(contents) > MAX_BYTES:
        raise ValueError("evidence_size_limit")
    data = json.loads(contents.decode("utf-8"), parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_float")))
    report = inspect(data)
    report["input_sha256"] = hashlib.sha256(contents).hexdigest()
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect_file(args.file)))


if __name__ == "__main__":
    main()
