"""Measure trusted WAL/crash/rollback DR fixtures on seven real CPython minors.

Each run is a disposable local drill. Production and offsite qualification
remain false regardless of this result. Only operator-selected executables
are invoked; no unknown projects are run or mutated.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "dr_recovery_v26.py"
MINORS = tuple(f"3.{n}" for n in range(9, 16))
PATCH = re.compile(r"3\.[0-9]+\.[0-9]+\Z")


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(131072), b""):
            digest.update(chunk)
    return digest.hexdigest()


def measure_minor(minor, interpreter, max_rto_ms):
    if minor not in MINORS or not isinstance(interpreter, Path) or not interpreter.is_absolute():
        raise ValueError("explicit_known_cpython_minor_and_absolute_path_required")
    executable = interpreter.resolve(strict=True)
    if not executable.is_file():
        raise ValueError("actual_python_binary_missing")
    first_hash = sha256(executable)
    run = subprocess.run([str(executable), "-I", "-S", "-B", str(SCRIPT),
                          "--mode", "selftest", "--max-rto-ms", str(max_rto_ms),
                          "--max-lost-commits", "1"], cwd=str(ROOT),
                         capture_output=True, text=True, check=False, timeout=20)
    if run.returncode != 0 or len(run.stdout) > 20000 or len(run.stderr) > 1000:
        raise ValueError("local_drill_subprocess_failed")
    evidence = json.loads(run.stdout)
    patch = evidence.get("actual_python_patch")
    if not isinstance(patch, str) or not PATCH.fullmatch(patch) or \
            not patch.startswith(minor + "."):
        raise ValueError("incorrect_real_python_patch_identity")
    if (evidence.get("status") != "LOCAL_WAL_CRASH_RESTORE_RTO_RPO_GATES_PASS" or
            evidence.get("rto_observed_ms", 0) <= 0 or
            evidence.get("rto_observed_ms") > max_rto_ms or
            evidence.get("rpo_lost_commits_observed") != 1 or
            evidence.get("rpo_lost_commits_gate") != 1 or
            evidence.get("rpo_checkpoint_to_simulated_fault_seconds", -1) < 0 or
            evidence.get("real_child_crashes") is None or
            [item["actual_exit_code"] for item in evidence["real_child_crashes"]] != [74, 75] or
            evidence.get("negative_existing_output_never_overwritten") is not True or
            evidence.get("negative_corrupt_snapshot_copy_detected") is not True or
            evidence.get("local_canary_rollback", {}).get("rollback_verified") is not True or
            evidence.get("trial_source_sha256") != sha256(SCRIPT) or
            evidence.get("production_disaster_recovery_qualified") is not False or
            evidence.get("independent_off_host_audit") is not False or
            evidence.get("unknown_project_executed") is not False):
        raise ValueError("unqualified_or_misreported_disaster_recovery_result")
    if sha256(executable) != first_hash:
        raise ValueError("interpreter_binary_changed_during_drill")
    return {"minor": minor, "actual_patch": patch,
            "executable_sha256": first_hash,
            "status": "PASS_BOUND_LOCAL_DR_DRILL_ONLY",
            "rto_observed_ms": evidence["rto_observed_ms"],
            "rpo_lost_commits": evidence["rpo_lost_commits_observed"],
            "rpo_checkpoint_to_fault_seconds": evidence[
                "rpo_checkpoint_to_simulated_fault_seconds"],
            "local_rollback_verified": True,
            "real_crash_process_exit_codes": [74, 75],
            "off_host_recovery_attested": False,
            "production_rto_rpo_qualified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interpreter", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-rto-ms", type=int, default=5000)
    args = parser.parse_args(argv)
    mapping = {}
    for entry in args.interpreter:
        version, sep, path = entry.partition("=")
        if not sep or version not in MINORS or version in mapping or not path:
            parser.error("exact zeven unieke minor=absolute-python entries vereist")
        mapping[version] = Path(path)
    if (set(mapping) != set(MINORS) or not args.output.parent.is_dir() or
            not 1 <= args.max_rto_ms <= 60000):
        parser.error("zeven interpreters, bestaande outputmap en geldig RTO-budget vereist")
    outcomes = []
    for version in MINORS:
        try:
            outcomes.append(measure_minor(version, mapping[version], args.max_rto_ms))
        except (ValueError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            outcomes.append({"minor": version, "status": "FAIL",
                             "reason": type(exc).__name__ + ":" + str(exc)[:120]})
    report = {"schema_version": 1,
              "measured_utc": datetime.now(timezone.utc).isoformat(),
              "source_sha256": sha256(SCRIPT),
              "status": "PASS_LOCAL_DISPOSABLE_DR_ONLY" if all(
                  row["status"] == "PASS_BOUND_LOCAL_DR_DRILL_ONLY" for row in outcomes)
                  else "FAIL",
              "records": outcomes,
              "real_minor_drills_passed": sum(
                  row["status"] == "PASS_BOUND_LOCAL_DR_DRILL_ONLY" for row in outcomes),
              "production_and_off_host_qualified": False,
              "unknown_project_code_executed": False,
              "external_independent_audit_claimed": False}
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print("DR {} / 7 local real CPython drills PASS".format(
        report["real_minor_drills_passed"]))
    return 0 if report["status"] == "PASS_LOCAL_DISPOSABLE_DR_ONLY" else 1


if __name__ == "__main__":
    sys.exit(main())
