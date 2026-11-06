"""Run EVERY discovered Python unittest sequentially on seven actual minors.

Independent interpreter processes avoid resource competition falsely tripping
pre-existing latency/speed gates. Logs include failures; counts never mean an
untested feature is complete. Unknown source execution is not permitted here.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
TEST_SUMMARY = re.compile(r"Ran (\d+) tests? in ([0-9.]+)s")
SKIPS = re.compile(r"skipped=(\d+)")


def run_version(label, interpreter, evidence_dir, release_label="v0.23"):
    if not re.fullmatch(r"v0\.[0-9]{1,3}", release_label):
        raise ValueError("invalid_release_label")
    if not interpreter.is_absolute() or not interpreter.resolve().is_file():
        raise ValueError("interpreter_must_be_explicit_existing_executable")
    identity = subprocess.run([str(interpreter), "-I", "-S", "-B", "-c",
                               "import sys,json; print(json.dumps({\"version\":list(sys.version_info[:3]),\"implementation\":sys.implementation.name}))"],
                              capture_output=True, text=True, timeout=10, check=False)
    if identity.returncode != 0:
        raise ValueError("interpreter_identity_probe_failed")
    info = json.loads(identity.stdout)
    if info["implementation"] != "cpython" or info["version"][:2] != [3, int(label.split(".")[1])]:
        raise ValueError("interpreter_minor_does_not_match")
    process = subprocess.run([str(interpreter), "-m", "unittest", "discover", "-s", "tests",
                              "-p", "test_*.py", "-q"], cwd=str(ROOT),
                             capture_output=True, text=True, timeout=600, check=False)
    log = (process.stdout + "\n" + process.stderr).strip() + "\n"
    path = evidence_dir / ("PYTEST_" + label + "_" + release_label + ".log")
    path.write_text(log, encoding="utf-8")
    matches = TEST_SUMMARY.findall(log)
    if len(matches) != 1:
        raise ValueError("missing_or_ambiguous_unittest_test_counter")
    cases = int(matches[0][0])
    skipped = SKIPS.findall(log)
    skips = int(skipped[-1]) if skipped else 0
    passed = process.returncode == 0 and "\nOK" in log and "FAILED (" not in log
    return {"version": label, "actual_python": ".".join(map(str, info["version"])),
            "test_cases_recorded": cases, "skips_recorded": skips,
            "assertion_results_pass": passed, "exit_code": process.returncode,
            "duration_seconds_reported": float(matches[0][1]),
            "log": path.name, "log_sha256": hashlib.sha256(log.encode("utf-8")).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interpreter", action="append", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--release-label", default="v0.23")
    args = parser.parse_args()
    mapping = {}
    for item in args.interpreter:
        version, separator, path = item.partition("=")
        if not separator or version not in {"3." + str(x) for x in range(9, 16)} or version in mapping:
            parser.error("exact zeven unieke minor=exe-paren vereist")
        mapping[version] = Path(path)
    if len(mapping) != 7 or not args.evidence_dir.is_dir():
        parser.error("exact zeven echte CPython-versies en bestaande bewijsmap vereist")
    records = []
    for version in ("3." + str(x) for x in range(9, 16)):
        record = run_version(version, mapping[version], args.evidence_dir,
                             args.release_label)
        records.append(record)
        print("PYTHON {} {}/{} tests PASS; {} skipped".format(
            version, record["test_cases_recorded"] - record["skips_recorded"]
            if record["assertion_results_pass"] else 0,
            record["test_cases_recorded"], record["skips_recorded"]), flush=True)
        if not record["assertion_results_pass"]:
            break
    report = {"schema_version": 1, "tested_at_utc": datetime.now(timezone.utc).isoformat(),
              "status": "PASS" if len(records) == 7 and all(
                  row["assertion_results_pass"] for row in records) else "FAIL",
              "coverage": "TRUSTED_LOCAL_UNIT_FIXTURES_NO_UNKNOWN_PROJECT_CODE",
              "python_versions": records, "tests_discovered": sum(
                  row["test_cases_recorded"] for row in records),
              "tests_skipped": sum(row["skips_recorded"] for row in records),
              "not_full_function_qualification": True}
    (args.evidence_dir / ("UNIT_MATRIX_" + args.release_label + ".json")).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if report["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
