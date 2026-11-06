"""Record 100 genuine, curated CPython checks per Windows matrix cell.

The only executed source is the reviewed, fixed python/version_suite.py.
This is not a sandbox, a package-ecosystem certification or user-code test.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "python" / "version_suite.py"
SUPPORTED = tuple("3.{}".format(i) for i in range(9, 16))


def qualify(expected_minor):
    if type(expected_minor) is not str or expected_minor not in SUPPORTED:
        raise ValueError("unsupported_expected_python_minor")
    current = "{}.{}".format(*sys.version_info[:2])
    report = {
        "schema_version": 1,
        "expected_minor": expected_minor,
        "actual_minor": current,
        "runtime": sys.implementation.name,
        "suite_sha256": hashlib.sha256(SUITE.read_bytes()).hexdigest(),
        "fixed_curated_suite_only": True,
        "untrusted_code_executed": False,
        "full_compatibility_proven": False,
        "status": "NOT_RUN",
        "cases": 0,
        "passed": 0,
        "failed": 0,
    }
    if sys.implementation.name != "cpython" or current != expected_minor:
        return dict(report, status="FAIL", reason="actual_cpython_minor_mismatch")
    try:
        process = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(SUITE)],
            cwd=str(ROOT), capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return dict(report, reason="child_" + type(exc).__name__)
    if process.returncode != 0 or len(process.stdout) > 65_536 or len(process.stderr) > 1024:
        return dict(report, status="FAIL", reason="bounded_curated_child_failed")
    try:
        measured = json.loads(process.stdout)
    except (UnicodeError, ValueError):
        return dict(report, status="FAIL", reason="invalid_suite_json")
    if type(measured) is not dict:
        return dict(report, status="FAIL", reason="invalid_suite_shape")
    results = measured.get("results")
    if (type(results) is not list or len(results) != 100 or
            any(type(row) is not dict or type(row.get("id")) is not str or
                not row["id"].isascii() or len(row["id"]) > 100 or
                row.get("status") not in ("PASS", "FAIL") for row in results)):
        return dict(report, status="FAIL", reason="suite_identity_or_count_invalid")
    ids = [row["id"] for row in results]
    passed = sum(row["status"] == "PASS" for row in results)
    failed = 100 - passed
    if (len(set(ids)) != 100 or measured.get("cases") != 100 or
            measured.get("pass") != passed or measured.get("fail") != failed or
            measured.get("python", "").split(".")[:2] != expected_minor.split(".") or
            measured.get("implementation") != "cpython"):
        return dict(report, status="FAIL", reason="suite_result_inconsistent")
    status = "PASS" if failed == 0 and measured.get("status") == "PASS" else "FAIL"
    return dict(report, status=status, cases=100, passed=passed, failed=failed,
                child_stdout_sha256=hashlib.sha256(process.stdout).hexdigest(),
                case_results=results, reason="fixed_curated_suite_qualified_only")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-minor", choices=SUPPORTED, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.expected_minor)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps({"status": result["status"], "passed": result["passed"],
                      "failed": result["failed"]}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
