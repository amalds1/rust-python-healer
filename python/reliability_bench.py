"""Repeatable *trusted-fixture* Python and Rust/Ruff pipeline measurements.

The only executed source is the hardcoded trusted synthetic fixture below.
The Rust repair pipeline compiles (never executes) its own fixed Python input.
This tool is not a sandbox for arbitrary projects and does not independently
prove correctness or production performance of automatically repaired code.
"""

import argparse
import hashlib
import json
import math
import os
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

TRUSTED_PROGRAM = r'''
import hashlib, json, locale, os, pathlib, random, sys, time
mode = os.environ.get("RPH_TRUSTED_MODE", "normal")
round_index = int(os.environ.get("RPH_TRUSTED_ROUND", "0"))
if mode == "always-fail" or (mode == "alternating-fail" and round_index % 2):
    sys.exit(31)
locale.setlocale(locale.LC_ALL, "C")
random.seed(81473)
time.time = lambda: 1700000000.0
pathlib.Path("fixture").mkdir()
p = pathlib.Path("fixture/input.txt")
p.write_bytes(b"trusted-fixed-fixture")
os.utime(str(p), (1700000000, 1700000000))
print(json.dumps({"time": time.time(), "locale": locale.setlocale(locale.LC_ALL),
                  "random": [random.randint(0, 99999) for _ in range(5)],
                  "relative_path": p.as_posix(), "mtime": int(p.stat().st_mtime),
                  "fixture_sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                  "environment": os.environ.get("RPH_TRUSTED_FIXTURE", "MISSING")},
                 sort_keys=True))
'''
REPAIR_SOURCE = b"import os\n\nanswer = 42\n"
MIN_REPEATS = 10
MIN_PIPELINE_ROUNDS = 5
MAX_RUNS = 30
MAX_OUTPUT_BYTES = 100_000
MAX_LATENCY_P95_MS = 30_000  # Fixed in code before measurement; no adaptive weakening.
KNOWN_TRUSTED_OBSERVATION_SHA256 = "de88e399c17e0f03faca07fa424f2763e3ff9c84142e71ea47c3c78653cb2cb6"
FIXTURE_MODES = ("normal", "alternating-fail", "always-fail")
LATENCY_PROFILES = ("baseline", "p95-regression", "median-regression")
MAX_MEASURED_MEDIAN_MS = 300  # Predeclared trusted-process threshold.
MAX_MEASURED_P95_MS = 700  # Predeclared trusted-process threshold.
P95_REGRESSION_DELAY_MS = 1000
MEDIAN_REGRESSION_DELAY_MS = 450
MIN_MEASURED_REPEATS = 10


def _with_native_windows_root(environment):
    """Keep the caller's fixed allowlist; obtain Windows startup root from OS."""
    if type(environment) is not dict or any(type(k) is not str or type(v) is not str for k,v in environment.items()):
        raise ValueError("invalid_fixed_child_environment")
    result=dict(environment)
    if os.name=="nt":
        import ctypes
        get_root=ctypes.WinDLL("kernel32",use_last_error=True).GetSystemWindowsDirectoryW
        get_root.argtypes=[ctypes.c_wchar_p,ctypes.c_uint]
        get_root.restype=ctypes.c_uint
        buffer=ctypes.create_unicode_buffer(32768)
        size=get_root(buffer,len(buffer))
        if not 0<size<len(buffer):
            raise OSError("native_system_windows_directory_unavailable")
        result={k:v for k,v in result.items() if k.casefold() not in ("systemroot","windir")}
        result["SystemRoot"]=buffer.value
    return result


def p95(values):
    if not values:
        return None
    return sorted(values)[math.ceil(0.95 * len(values)) - 1]


def ensure_runs(count, minimum):
    if type(count) is not int or not minimum <= count <= MAX_RUNS:
        raise ValueError("minimum_independent_runs_not_met")


def trusted_environment(directory, fixture_mode="normal", round_index=0):
    """Explicit narrow environment for trusted process fixtures (not a sandbox)."""
    if fixture_mode not in FIXTURE_MODES or type(round_index) is not int or round_index < 0:
        raise ValueError("invalid_trusted_fixture_mode")
    return _with_native_windows_root({"RPH_TRUSTED_FIXTURE": "set-by-test-harness", "PATH": os.environ.get("PATH", ""),
            "LC_ALL": "C", "TZ": "UTC", "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0", "RPH_TRUSTED_MODE": fixture_mode,
            "RPH_TRUSTED_ROUND": str(round_index), "TMPDIR": str(directory)})


def run_trusted_repetitions(python, runs=MIN_REPEATS, fixture_mode="normal"):
    """Run ten real independent processes with frozen time/random/fs/locale/env."""
    ensure_runs(runs, MIN_REPEATS)
    if fixture_mode not in FIXTURE_MODES:
        raise ValueError("unknown_fixture_mode")
    entries = []
    reference = None
    with tempfile.TemporaryDirectory(prefix="rph-repeat-") as temporary:
        for n in range(runs):
            directory = Path(temporary) / f"round-{n:02d}"
            directory.mkdir()
            before = time.perf_counter_ns()
            try:
                proc = subprocess.run([str(python), "-I", "-S", "-B", "-c", TRUSTED_PROGRAM],
                                      cwd=str(directory), env=trusted_environment(directory, fixture_mode, n),
                                      capture_output=True, check=False, timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                entries.append({"run_id": f"R{n:02d}", "status": "NOT_RUN",
                                "retest": n > 0, "duration_ms": None})
                continue
            elapsed = (time.perf_counter_ns() - before) / 1e6
            if proc.returncode or len(proc.stdout) > MAX_OUTPUT_BYTES or proc.stderr:
                entries.append({"run_id": f"R{n:02d}", "status": "FAIL",
                                "exit_code": proc.returncode,
                                "retest": n > 0, "duration_ms": round(elapsed, 5)})
                continue
            try:
                value = json.loads(proc.stdout)
                if (value["time"] != 1700000000.0 or value["locale"] != "C" or
                        value["mtime"] != 1700000000 or
                        value["environment"] != "set-by-test-harness" or
                        value["relative_path"] != "fixture/input.txt" or
                        len(value["random"]) != 5):
                    raise ValueError("trusted_fixture_invariants_failed")
            except (ValueError, KeyError, TypeError):
                entries.append({"run_id": f"R{n:02d}", "status": "FAIL",
                                "retest": n > 0, "duration_ms": round(elapsed, 5)})
                continue
            digest = hashlib.sha256(json.dumps(value, sort_keys=True,
                                              separators=(",", ":")).encode()).hexdigest()
            if reference is None:
                reference = digest
            entries.append({"run_id": f"R{n:02d}",
                            "status": "PASS" if digest == reference == KNOWN_TRUSTED_OBSERVATION_SHA256 else "FAIL",
                            "retest": n > 0, "duration_ms": round(elapsed, 5),
                            "observation_sha256": digest})
    good = [item["duration_ms"] for item in entries if item["status"] == "PASS"]
    measured = [item["duration_ms"] for item in entries if item["duration_ms"] is not None]
    failures = sum(row["status"] == "FAIL" for row in entries)
    missing = sum(row["status"] == "NOT_RUN" for row in entries)
    complete = (len(entries) == runs and len(good) == runs and
                len({row.get("observation_sha256") for row in entries}) == 1)
    if complete and fixture_mode == "normal":
        status = "TRUSTED_TEN_REPEATS_MATCH"
    elif not missing and failures and good:
        status = "FLAKY_DETECTED"
    elif not missing and failures == runs:
        status = "FAIL_DETECTED"
    else:
        status = "INCOMPLETE_OR_DIVERGENT"
    return {
        "schema_version": 1,
        "status": status, "injection_mode": fixture_mode,
        "scope": "FIXED_SAFE_TRUSTED_FIXTURE_ONLY",
        "repetitions_expected": runs, "independent_processes_recorded": len(entries),
        "pass": len(good), "fail": failures,
        "not_run": missing,
        "measured_process_durations": len(measured),
        "p95_process_duration_ms": p95(measured),
        "median_process_duration_ms": statistics.median(measured) if measured else None,
        "deterministic_result_sha256": reference,
        "observations": entries,
        "time_locale_random_filesystem_environment_controlled": complete,
        "untrusted_project_code_executed": False,
        "trusted_fixture_executed": bool(measured),
        "trusted_fixture_passed": bool(good),
        "independent_behavioral_oracle": False,
        "release_authorized": False,
    }


def measure_trusted_latency(python, runs=MIN_MEASURED_REPEATS, profile="baseline"):
    """Measure ten real independent trusted runtimes and enforce fixed p50/p95 SLOs.

    Regression profiles inject a real, bounded sleep into selected children;
    their measured subprocess durations are never estimated or supplied data.
    """
    ensure_runs(runs, MIN_MEASURED_REPEATS)
    if profile not in LATENCY_PROFILES:
        raise ValueError("invalid_latency_profile")
    rows = []
    with tempfile.TemporaryDirectory(prefix="rph-latency-") as temporary:
        for n in range(runs):
            folder = Path(temporary) / f"round-{n:02d}"
            folder.mkdir()
            if profile == "p95-regression" and n == runs - 1:
                delay_ms = P95_REGRESSION_DELAY_MS
            elif profile == "median-regression" and n < math.ceil(0.6 * runs):
                delay_ms = MEDIAN_REGRESSION_DELAY_MS
            else:
                delay_ms = 0
            # Only this fixed inline program is executed; delay is chosen by
            # hardcoded profile policy, never constructed from caller source.
            script = f"import time; time.sleep({delay_ms / 1000.0})"
            before = time.perf_counter_ns()
            try:
                proc = subprocess.run([str(python), "-I", "-S", "-B", "-c", script],
                                      cwd=str(folder), env=trusted_environment(folder),
                                      capture_output=True, check=False, timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                rows.append({"round": n + 1, "status": "NOT_RUN", "duration_ms": None,
                             "injected_delay_ms": delay_ms})
                continue
            duration = (time.perf_counter_ns() - before) / 1e6
            status = "PASS" if not proc.returncode and not proc.stdout and not proc.stderr else "FAIL"
            rows.append({"round": n + 1, "status": status,
                         "duration_ms": round(duration, 5), "injected_delay_ms": delay_ms})
    measured = [row["duration_ms"] for row in rows if row["duration_ms"] is not None]
    all_success = len(measured) == runs and all(row["status"] == "PASS" for row in rows)
    median = statistics.median(measured) if measured else None
    percentile = p95(measured)
    if not all_success:
        result_status = "INCOMPLETE_OR_FAILED_MEASUREMENT"
    elif median > MAX_MEASURED_MEDIAN_MS or percentile > MAX_MEASURED_P95_MS:
        result_status = "MEASURED_REGRESSION"
    else:
        result_status = "MEASURED_THRESHOLDS_PASS"
    return {"schema_version": 1,
            "status": result_status,
            "scope": "FIXED_TRUSTED_PYTHON_STARTUP_AND_BOUNDED_SLEEP_ONLY",
            "profile": profile, "independent_processes_expected": runs,
            "independent_processes_measured": len(measured),
            "passes": sum(row["status"] == "PASS" for row in rows),
            "fails": sum(row["status"] == "FAIL" for row in rows),
            "not_run": sum(row["status"] == "NOT_RUN" for row in rows),
            "median_ms": median, "p95_ms": percentile,
            "predeclared_median_limit_ms": MAX_MEASURED_MEDIAN_MS,
            "predeclared_p95_limit_ms": MAX_MEASURED_P95_MS,
            "measured_real_process_wall_clock": True,
            "thresholds_adaptively_changed": False,
            "observations": rows, "unknown_python_executed": False,
            "production_performance_verified": False,
            "release_authorized": False}


def repair_pipeline_rounds(binary, ruff, python, runs=MIN_PIPELINE_ROUNDS):
    """Benchmark actual Rust->Ruff->compile pipeline in fresh independent dirs."""
    ensure_runs(runs, MIN_PIPELINE_ROUNDS)
    executables = (Path(binary).absolute(), Path(ruff).absolute(), Path(python).absolute())
    if any(not path.is_file() for path in executables):
        return {"status": "NOT_RUN", "reason": "missing_selected_executable",
                "untrusted_project_code_executed": False}
    binary, ruff, python = (str(path) for path in executables)
    expected = None
    rounds = []
    with tempfile.TemporaryDirectory(prefix="rph-pipeline-") as temporary:
        for n in range(runs):
            folder = Path(temporary) / f"round-{n:02d}"
            folder.mkdir()
            source = folder / "fixed.py"
            source.write_bytes(REPAIR_SOURCE)
            candidate = folder / "repaired.py"
            ledger = folder / "evidence.sqlite"
            args = [str(binary), "repair", str(source), "--ruff", str(ruff),
                    "--python", str(python), "--ledger", str(ledger), "--out",
                    str(candidate)]
            before = time.perf_counter_ns()
            try:
                proc = subprocess.run(args, cwd=str(folder), env=trusted_environment(folder), capture_output=True,
                                      check=False, timeout=45)
            except (OSError, subprocess.TimeoutExpired):
                rounds.append({"round": n + 1, "status": "NOT_RUN", "retest": n > 0})
                continue
            elapsed = (time.perf_counter_ns() - before) / 1e6
            if (proc.returncode or len(proc.stdout) > MAX_OUTPUT_BYTES or proc.stderr or
                    not candidate.is_file() or source.read_bytes() != REPAIR_SOURCE):
                rounds.append({"round": n + 1, "status": "FAIL", "retest": n > 0,
                               "duration_ms": round(elapsed, 5)})
                continue
            try:
                answer = json.loads(proc.stdout)
                if (answer["status"] != "CANDIDATE_ONLY" or
                        answer["winner"] != "NONE" or
                        answer["candidate_saved"] != str(candidate)):
                    raise ValueError("repair_semantics_changed")
                built = candidate.read_bytes()
                if not built or built == REPAIR_SOURCE or len(built) > 1_048_576:
                    raise ValueError("repair_candidate_invalid")
            except (ValueError, TypeError, KeyError):
                rounds.append({"round": n + 1, "status": "FAIL", "retest": n > 0,
                               "duration_ms": round(elapsed, 5)})
                continue
            digest = hashlib.sha256(built).hexdigest()
            if expected is None:
                expected = digest
            rounds.append({"round": n + 1, "status": "PASS" if digest == expected else "FAIL",
                           "retest": n > 0, "duration_ms": round(elapsed, 5),
                           "candidate_sha256": digest})
    durations = [run["duration_ms"] for run in rounds if run["status"] == "PASS"]
    all_pass = len(durations) == runs
    percentile = p95(durations)
    threshold_pass = all_pass and percentile <= MAX_LATENCY_P95_MS
    return {"schema_version": 1,
            "status": "TRUSTED_PIPELINE_MEETS_P95" if threshold_pass else
                      "NOT_RUN_OR_PIPELINE_REGRESSION",
            "scope": "FIXED_SAFE_RUST_RUFF_COMPILE_PIPELINE_FIXTURE_ONLY",
            "independent_workdirs": runs, "passes": len(durations),
            "rounds": rounds, "p95_latency_ms": percentile,
            "median_latency_ms": statistics.median(durations) if durations else None,
            "predeclared_p95_limit_ms": MAX_LATENCY_P95_MS,
            "candidate_sha256": expected,
            "source_executed": False, "unknown_project_test_executed": False,
            "full_autonomous_repair_correctness": "NOT_VERIFIED",
            "independent_security_audit": False, "release_authorized": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True)
    parser.add_argument("--mode", choices=("trusted-repeat", "repair-pipeline", "latency-measure"), required=True)
    parser.add_argument("--runs", type=int)
    parser.add_argument("--binary")
    parser.add_argument("--ruff")
    parser.add_argument("--fixture-mode", choices=FIXTURE_MODES, default="normal")
    parser.add_argument("--latency-profile", choices=LATENCY_PROFILES, default="baseline")
    args = parser.parse_args()
    if args.mode == "trusted-repeat":
        if args.binary or args.ruff:
            parser.error("trusted-repeat does not accept arbitrary executables")
        if args.latency_profile != "baseline":
            parser.error("fixture-mode_and_latency-profile_are_separate")
        result = run_trusted_repetitions(args.python, MIN_REPEATS if args.runs is None else args.runs,
                                         args.fixture_mode)
    elif args.mode == "latency-measure":
        if args.binary or args.ruff or args.fixture_mode != "normal":
            parser.error("latency_measure_only_allows_selected_trusted_profile")
        result = measure_trusted_latency(args.python, MIN_MEASURED_REPEATS if args.runs is None else args.runs,
                                        args.latency_profile)
    else:
        if args.fixture_mode != "normal" or args.latency_profile != "baseline":
            parser.error("repair_pipeline_does_not_accept_test_injection")
        if not args.binary or not args.ruff:
            parser.error("repair-pipeline requires selected binary and ruff")
        result = repair_pipeline_rounds(args.binary, args.ruff, args.python,
                                        MIN_PIPELINE_ROUNDS if args.runs is None else args.runs)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
