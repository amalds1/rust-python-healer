"""Bounded, read-only release-quality trend analyzer for external measurements.

Never execute a Python project, invoke tests, install dependencies or approve
a release. All imported oracle labels are UNVERIFIED self-reports; their
false-positive and repair-success counts are not independent ground truth.
The thresholds are defined in this code *before* reading any measurements.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import statistics


MAX_BYTES = 1_048_576
MAX_RELEASES = 64
MAX_REPEATS = 1000
MIN_REPEATS = 10
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
VERSION = re.compile(r"(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\Z")
PYTHON_MINOR = re.compile(r"3\.(0|[1-9][0-9]{0,2})\Z")
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,95}\Z")
THRESHOLDS = {
    "false_positive_percent_max": 1.0,
    "new_regressions_max": 0,
    "throughput_drop_percent_max": 5.0,
    "repair_quality_drop_pp_max": 1.0,
    "p95_latency_increase_percent_max": 10.0,
    "minimum_oracle_observations": 100,
    "minimum_duration_repetitions": MIN_REPEATS,
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def version_parts(value):
    if not isinstance(value, str):
        raise ValueError("invalid_release_version")
    match = VERSION.fullmatch(value)
    if not match:
        raise ValueError("invalid_release_version")
    return tuple(int(part) for part in match.groups())


def nonnegative_int(value, maximum=10_000_000):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("invalid_reported_integer")
    return value


def checked_durations(value):
    if not isinstance(value, list) or not MIN_REPEATS <= len(value) <= MAX_REPEATS:
        raise ValueError("insufficient_or_excessive_benchmark_repetitions")
    for duration in value:
        if (type(duration) not in (int, float) or not math.isfinite(duration) or
                not 0 <= duration <= 3_600_000):
            raise ValueError("invalid_benchmark_duration")
    ordered = sorted(value)
    # Nearest-rank p95 is deterministic at n=10 and intentionally conservative.
    rank = math.ceil(0.95 * len(ordered)) - 1
    return {"observations": len(ordered),
            "median_ms": statistics.median(ordered),
            "p95_ms": ordered[rank],
            "max_ms": ordered[-1], "measurements_sha256": digest(value)}


def observe(row):
    if not isinstance(row, dict) or set(row) != {
            "version", "source_sha256", "binary_sha256", "run_id",
            "python_minors", "oracle_checked", "reported_false_positives",
            "regression_failures", "repair_candidates", "reported_repair_successes",
            "jobs_completed", "elapsed_ms", "durations_ms", "record_sha256"}:
        raise ValueError("invalid_release_observation_fields")
    claimed_hash = row["record_sha256"]
    if not isinstance(claimed_hash, str) or not HEX64.fullmatch(claimed_hash):
        raise ValueError("invalid_release_record_sha256")
    if claimed_hash != digest({key: value for key, value in row.items()
                              if key != "record_sha256"}):
        raise ValueError("release_record_sha256_mismatch")
    release_version = row["version"]
    version_parts(release_version)
    if not isinstance(row["run_id"], str) or not RUN_ID.fullmatch(row["run_id"]):
        raise ValueError("invalid_release_run_id")
    for name in ("source_sha256", "binary_sha256"):
        if not isinstance(row[name], str) or not HEX64.fullmatch(row[name]):
            raise ValueError("invalid_artifact_hash")
    minors = row["python_minors"]
    if (not isinstance(minors, list) or not 1 <= len(minors) <= 64 or
            any(not isinstance(x, str) or not PYTHON_MINOR.fullmatch(x) for x in minors) or
            minors != sorted(set(minors), key=lambda s: int(s.split(".")[1]))):
        raise ValueError("ambiguous_python_coverage")
    integer_fields = (
        "oracle_checked", "reported_false_positives", "regression_failures",
        "repair_candidates", "reported_repair_successes", "jobs_completed",
    )
    numbers = {field: nonnegative_int(row[field]) for field in integer_fields}
    if (numbers["reported_false_positives"] > numbers["oracle_checked"] or
            numbers["reported_repair_successes"] > numbers["repair_candidates"]):
        raise ValueError("reported_counts_exceed_totals")
    elapsed = row["elapsed_ms"]
    if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or not 0 < elapsed <= 3_600_000_000:
        raise ValueError("invalid_elapsed_duration")
    samples = checked_durations(row["durations_ms"])
    oracle_count = numbers["oracle_checked"]
    candidates = numbers["repair_candidates"]
    false_positive_pct = 100 * numbers["reported_false_positives"] / oracle_count if oracle_count else None
    proxy_success_pct = 100 * numbers["reported_repair_successes"] / candidates if candidates else None
    return {
        "version": release_version,
        "run_id": row["run_id"],
        "source_sha256": row["source_sha256"],
        "binary_sha256": row["binary_sha256"],
        "python_minors": minors,
        "observation_sha256": digest(row),
        "reported_oracle_observations": oracle_count,
        "reported_false_positives": numbers["reported_false_positives"],
        "reported_false_positive_percent": false_positive_pct,
        "reported_regression_failures": numbers["regression_failures"],
        "reported_repair_candidates": candidates,
        "reported_repair_successes": numbers["reported_repair_successes"],
        "reported_repair_quality_proxy_percent": proxy_success_pct,
        "reported_jobs_completed": numbers["jobs_completed"],
        "reported_elapsed_ms": elapsed,
        "reported_throughput_jobs_per_second": numbers["jobs_completed"] * 1000 / elapsed,
        "benchmark": samples,
    }


def analyze(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "releases"} or data["schema_version"] != 1:
        raise ValueError("invalid_release_quality_schema")
    releases = data["releases"]
    if not isinstance(releases, list) or not 1 <= len(releases) <= MAX_RELEASES:
        raise ValueError("invalid_release_count")
    findings = []
    previous, previous_version, run_ids = None, None, set()
    for row in releases:
        current = observe(row)
        version_tuple = version_parts(current["version"])
        if previous_version is not None and version_tuple <= previous_version:
            raise ValueError("releases_must_be_unique_and_strictly_ascending")
        if current["run_id"] in run_ids:
            raise ValueError("duplicate_release_run_id_without_retest")
        run_ids.add(current["run_id"])
        previous_version = version_tuple

        false_positive_status = (
            "NOT_RUN_TOO_FEW_ORACLE_OBSERVATIONS"
            if current["reported_oracle_observations"] < THRESHOLDS["minimum_oracle_observations"]
            else "REPORTED_THRESHOLD_EXCEEDED"
            if current["reported_false_positive_percent"] > THRESHOLDS["false_positive_percent_max"]
            else "WITHIN_REPORTED_THRESHOLD_NOT_VERIFIED")
        thresholds = {"false_positive": false_positive_status,
                      "regressions": "REPORTED_REGRESSIONS_PRESENT" if
                      current["reported_regression_failures"] else "NO_REGRESSIONS_REPORTED_UNVERIFIED"}
        baseline = None
        if previous is not None:
            coverage_comparable = current["python_minors"] == previous["python_minors"]
            baseline = {
                "baseline_version": previous["version"],
                "python_coverage_comparable": coverage_comparable,
                "new_regression_failures": max(0, current["reported_regression_failures"] -
                                               previous["reported_regression_failures"]),
            }
            old_speed = previous["reported_throughput_jobs_per_second"]
            new_speed = current["reported_throughput_jobs_per_second"]
            baseline["throughput_change_percent"] = ((new_speed / old_speed - 1) * 100
                                                      if old_speed > 0 else None)
            old_quality = previous["reported_repair_quality_proxy_percent"]
            new_quality = current["reported_repair_quality_proxy_percent"]
            baseline["repair_quality_change_pp"] = ((new_quality - old_quality)
                                                     if new_quality is not None and old_quality is not None
                                                     else None)
            old_p95 = previous["benchmark"]["p95_ms"]
            new_p95 = current["benchmark"]["p95_ms"]
            baseline["p95_latency_change_percent"] = ((new_p95 / old_p95 - 1) * 100
                                                      if old_p95 > 0 else None)
            baseline["comparison_status"] = (
                "COMPARABLE_UNVERIFIED" if coverage_comparable else
                "NOT_COMPARABLE_DIFFERENT_PYTHON_COVERAGE")
            if coverage_comparable:
                thresholds["new_regressions"] = (
                    "REPORTED_THRESHOLD_EXCEEDED" if baseline["new_regression_failures"] >
                    THRESHOLDS["new_regressions_max"] else "WITHIN_REPORTED_THRESHOLD_NOT_VERIFIED")
                thresholds["throughput_regression"] = (
                    "NOT_RUN_ZERO_BASELINE" if baseline["throughput_change_percent"] is None else
                    "REPORTED_THRESHOLD_EXCEEDED" if baseline["throughput_change_percent"] <
                    -THRESHOLDS["throughput_drop_percent_max"] else
                    "WITHIN_REPORTED_THRESHOLD_NOT_VERIFIED")
                thresholds["repair_quality_regression"] = (
                    "NOT_RUN_MISSING_BASELINE" if baseline["repair_quality_change_pp"] is None else
                    "REPORTED_THRESHOLD_EXCEEDED" if baseline["repair_quality_change_pp"] <
                    -THRESHOLDS["repair_quality_drop_pp_max"] else
                    "WITHIN_REPORTED_THRESHOLD_NOT_VERIFIED")
                thresholds["p95_latency_regression"] = (
                    "NOT_RUN_ZERO_BASELINE" if baseline["p95_latency_change_percent"] is None else
                    "REPORTED_THRESHOLD_EXCEEDED" if baseline["p95_latency_change_percent"] >
                    THRESHOLDS["p95_latency_increase_percent_max"] else
                    "WITHIN_REPORTED_THRESHOLD_NOT_VERIFIED")
            else:
                for key in ("new_regressions", "throughput_regression", "repair_quality_regression",
                            "p95_latency_regression"):
                    thresholds[key] = "NOT_RUN_INCOMPARABLE_COVERAGE"
        current["baseline"] = baseline
        current["threshold_observations"] = thresholds
        current["external_measurements_verified"] = False
        current["release_qualified"] = False
        findings.append(current)
        previous = current
    return {
        "schema_version": 1,
        "status": "ANALYZED_UNVERIFIED_RELEASE_MEASUREMENTS",
        "releases": findings,
        "releases_examined": len(findings),
        "policy_thresholds_predeclared": THRESHOLDS,
        "input_sha256": digest(data),
        "source_executed": False,
        "packages_imported": False,
        "external_measurements_verified": False,
        "behavioral_correctness": "NOT_VERIFIED",
        "release_authorized": False,
        "primary_or_reserve_selected": False,
        "note": "External oracle/repair-success labels are untrusted; this is trend analysis, not a release PASS",
    }


def inspect_file(path):
    target = Path(path)
    if target.is_symlink():
        raise ValueError("release_evidence_symlink_refused")
    descriptor = os.open(str(target), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_BYTES:
            raise ValueError("release_evidence_not_unique_bounded_file")
        raw = handle.read(MAX_BYTES + 1)
        after = os.fstat(handle.fileno())
    if (len(raw) > MAX_BYTES or
            (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) !=
            (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns)):
        raise ValueError("release_evidence_changed_or_oversized")
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_release_json_key")
            result[key] = value
        return result
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                      parse_constant=lambda _:
                      (_ for _ in ()).throw(ValueError("invalid_json_number")))
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect_file(args.file)))


if __name__ == "__main__":
    main()
