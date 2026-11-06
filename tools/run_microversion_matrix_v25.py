"""SHA-pinned, budgeted real CPython patch-release matrix.

Only operator-selected interpreter files whose complete SHA256 matches a
separate explicit pin are ever executed. A missing patch release is NOT_RUN;
even a green declared subset does not qualify *all* Python microversions.
The 100 cases are the repository's trusted, curated version_suite.py cases.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "python" / "version_suite.py"
RELEASE_MANIFEST = ROOT / "config" / "versions.json"
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
PATCH = re.compile(r"3\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


def version_tuple(value):
    if not isinstance(value, str) or not PATCH.fullmatch(value):
        raise ValueError("invalid_exact_cpython_patch_version")
    parts = tuple(map(int, value.split(".")))
    if parts < (3, 9, 0):
        raise ValueError("python_minor_below_3_9")
    return parts


def read_release_manifest(path=RELEASE_MANIFEST):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if (not isinstance(document, dict) or document.get("schema_version") != 1 or
            not isinstance(document.get("minimum_python"), str)):
        raise ValueError("invalid_release_manifest")
    latest = document.get("latest_stable")
    return latest, version_tuple(latest)


def parse_mappings(items, required, kind):
    mapping = {}
    for item in items:
        if not isinstance(item, str):
            raise ValueError("invalid_" + kind)
        label, equals, value = item.partition("=")
        version_tuple(label)
        if not equals or label in mapping or label not in required or not value:
            raise ValueError("duplicate_or_undeclared_" + kind)
        mapping[label] = value
    return mapping


def read_previous(path, required, latest_stable):
    if path is None:
        return {}
    previous = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(previous, dict) or previous.get("schema_version") != 1:
        raise ValueError("invalid_previous_report")
    prior_latest = previous.get("latest_stable")
    version_tuple(prior_latest)
    if version_tuple(latest_stable) < version_tuple(prior_latest):
        raise ValueError("latest_stable_downgrade_refused")
    prior_required = previous.get("required_versions")
    if not isinstance(prior_required, list) or any(
            not isinstance(v, str) for v in prior_required):
        raise ValueError("invalid_previous_required_versions")
    if len(prior_required) != len(set(prior_required)):
        raise ValueError("duplicate_previous_required_versions")
    for version in prior_required:
        version_tuple(version)
    if not set(prior_required).issubset(required):
        raise ValueError("prior_microversion_coverage_cannot_disappear")
    rows = previous.get("results")
    if not isinstance(rows, list):
        raise ValueError("invalid_previous_results")
    known = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("version"), str):
            raise ValueError("invalid_previous_result_row")
        version_tuple(row["version"])
        if row["version"] in known:
            raise ValueError("duplicate_previous_result_row")
        known[row["version"]] = row.get("executable_sha256")
    return known


def pin_hash(path):
    with path.open("rb") as stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        return digest.hexdigest()


def check_probe(binary, expected_version, timeout):
    script = ("import json,sys;print(json.dumps({'version':list(sys.version_info[:5]),"
              "'implementation':sys.implementation.name}))")
    run = subprocess.run([str(binary), "-I", "-S", "-B", "-c", script],
                         capture_output=True, text=True, cwd=str(ROOT),
                         timeout=timeout, check=False)
    if run.returncode or len(run.stdout) > 500 or len(run.stderr) > 1000:
        raise ValueError("identity_probe_failed")
    info = json.loads(run.stdout)
    version = info.get("version")
    if (info.get("implementation") != "cpython" or not isinstance(version, list)
            or len(version) != 5 or version[:3] != list(version_tuple(expected_version))
            or version[3] != "final" or version[4] != 0):
        raise ValueError("actual_cpython_patch_identity_mismatch")
    return info


def check_suite(binary, expected_version, timeout):
    run = subprocess.run([str(binary), "-I", "-S", "-B", str(SUITE)],
                         capture_output=True, text=True, cwd=str(ROOT),
                         timeout=timeout, check=False)
    if run.returncode or len(run.stdout) > 100_000 or len(run.stderr) > 10_000:
        raise ValueError("trusted_100_case_suite_exited_nonzero")
    report = json.loads(run.stdout)
    results = report.get("results")
    if (report.get("python") != expected_version or
            report.get("implementation") != "cpython" or
            report.get("status") != "PASS" or report.get("cases") != 100 or
            report.get("pass") != 100 or report.get("fail") != 0 or
            not isinstance(results, list) or len(results) != 100 or
            any(not isinstance(item, dict) or item.get("status") != "PASS"
                for item in results) or
            len({item.get("id") for item in results}) != 100):
        raise ValueError("trusted_100_case_oracle_not_qualified")
    return report["duration_ms"]


def evaluate_versions(required_versions, interpreters, pins, max_runs,
                      timeout, prior_hashes=None):
    if (not isinstance(max_runs, int) or not 1 <= max_runs <= 1000 or
            not isinstance(timeout, (float, int)) or not 1 <= timeout <= 120):
        raise ValueError("invalid_explicit_resource_budget")
    prior_hashes = prior_hashes or {}
    records = []
    used_resolved_paths = set()
    attempted = 0
    for version in sorted(required_versions, key=version_tuple):
        record = {"version": version, "status": "NOT_RUN", "tests_pass": 0,
                  "tests_planned": 100, "tests_executed": 0,
                  "reason": "no_operator_pinned_interpreter"}
        value = interpreters.get(version)
        expected_pin = pins.get(version)
        if value is None or expected_pin is None:
            records.append(record)
            continue
        if not SHA256.fullmatch(expected_pin):
            record.update(status="BLOCKED", reason="invalid_sha256_pin")
            records.append(record)
            continue
        binary = Path(value)
        if not binary.is_absolute():
            record.update(status="BLOCKED", reason="relative_interpreter_path_rejected")
            records.append(record)
            continue
        resolved = binary.resolve()
        if not resolved.is_file():
            record.update(status="NOT_RUN", reason="interpreter_absent")
            records.append(record)
            continue
        if str(resolved) in used_resolved_paths:
            record.update(status="BLOCKED", reason="duplicate_interpreter_executable")
            records.append(record)
            continue
        used_resolved_paths.add(str(resolved))
        actual_hash = pin_hash(resolved)
        record["executable_sha256"] = actual_hash
        if actual_hash != expected_pin:
            record.update(status="BLOCKED", reason="sha256_pin_mismatch_no_execution")
            records.append(record)
            continue
        if (version in prior_hashes and prior_hashes[version] and
                prior_hashes[version] != actual_hash):
            record.update(status="BLOCKED", reason="previously_pinned_binary_changed")
            records.append(record)
            continue
        if attempted >= max_runs:
            record.update(status="NOT_RUN", reason="operator_run_budget_exhausted")
            records.append(record)
            continue
        attempted += 1
        try:
            check_probe(resolved, version, timeout)
            elapsed_ms = check_suite(resolved, version, timeout)
            if pin_hash(resolved) != expected_pin:
                raise ValueError("interpreter_changed_during_test")
            record.update(status="PASS", tests_pass=100, tests_executed=100,
                          elapsed_ms=elapsed_ms, reason="exact_real_patch_100_fixtures")
        except (ValueError, OSError, subprocess.TimeoutExpired,
                json.JSONDecodeError, KeyError, TypeError) as error:
            record.update(status="FAIL", reason=type(error).__name__ + ":" +
                          str(error)[:110])
        records.append(record)
    return records


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-version", action="append", required=True)
    parser.add_argument("--interpreter", action="append", default=[])
    parser.add_argument("--sha256", action="append", default=[])
    parser.add_argument("--max-runs", type=int, default=7)
    parser.add_argument("--timeout-seconds", type=float, default=40)
    parser.add_argument("--previous-report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        required = set()
        for item in args.require_version:
            version_tuple(item)
            if item in required:
                raise ValueError("duplicate_required_microversion")
            required.add(item)
        latest, _ = read_release_manifest()
        if latest not in required:
            raise ValueError("configured_latest_stable_must_be_required")
        interpreters = parse_mappings(args.interpreter, required, "interpreter")
        pins = parse_mappings(args.sha256, required, "sha256")
        prior = read_previous(args.previous_report, required, latest)
        if not args.output.parent.is_dir():
            raise ValueError("output_parent_not_found")
        records = evaluate_versions(required, interpreters, pins, args.max_runs,
                                    args.timeout_seconds, prior)
        result = {"schema_version": 1, "status": "PASS_DECLARED_SUBSET_ONLY" if all(
            row["status"] == "PASS" for row in records) else "INCOMPLETE_NOT_ALL_PASS",
            "measured_utc": datetime.now(timezone.utc).isoformat(),
            "latest_stable": latest,
            "required_versions": sorted(required, key=version_tuple),
            "source_suite_sha256": pin_hash(SUITE),
            "results": records,
            "actual_tests_pass": sum(row["tests_pass"] for row in records),
            "actual_tests_executed": sum(row["tests_executed"] for row in records),
            "all_existing_microversions_qualified": False,
            "future_microversions_qualified": False,
            "arbitrary_user_source_executed": False,
            "local_sha_pin_not_external_authenticity_audit": True,
            "expected_patches_not_in_required_set_unqualified": True}
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
        print("MICROVERSION {} / {} exact declared patches PASS; {} / {} trusted cases".format(
            sum(row["status"] == "PASS" for row in records), len(records),
            result["actual_tests_pass"], len(records) * 100))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
