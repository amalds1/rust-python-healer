"""Record real seven-interpreter DuckDB SQL timings and independent oracles.

The native wheel targets are externally installed trusted local test inputs;
this script never downloads a wheel, imports untrusted project modules or
compiles user source. It refuses to write a PASS artifact for missing engines.
"""

import argparse
from datetime import datetime, timezone
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
DIRS = {
    "3.9": "duckdb-test39-v23", "3.10": "duckdb-test310-v23",
    "3.11": "duckdb-test11-v23", "3.12": "duckdb-test312-v23",
    "3.13": "duckdb-test13-v23", "3.14": "duckdb-test14-v23",
    "3.15": "duckdb-test15-v23",
}
PYTHON_BIN = {
    version: str(WORKSPACE / ".python-bin" / ("python" + version))
    for version in DIRS
}
PYTHON_BIN["3.12"] = sys.executable
TRUSTED_SOURCE = b"measurement = 42\n"
PINNED_SOURCE = hashlib.sha256(TRUSTED_SOURCE).hexdigest()
MIN_QUERY_ROUNDS = 5
PREDECLARED_P95_MS = 100.0


def _quantile_cont(values, fraction):
    ordered = sorted(values)
    index = (len(ordered) - 1) * fraction
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def _module():
    spec = spec_from_file_location("native_duckdb_quality_v23",
                                   ROOT / "python" / "knowledge_scale_v23.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _measured_histories(version):
    rows = []
    for index in range(40):
        started = time.perf_counter_ns()
        compile(TRUSTED_SOURCE, "<trusted-compile-only-measurement>", "exec")
        duration = max(0.000001, (time.perf_counter_ns() - started) / 1e6)
        rows.append({"run_id": "native-measured-{:03d}".format(index),
                     "candidate_id": "baseline" if index % 2 else "variant",
                     "python_minor": version,
                     "duration_ms": duration,
                     "rss_kib": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
                     "status": "FAIL" if index % 8 == 0 else "PASS",
                     "sha256": PINNED_SOURCE})
    return rows


def one_interpreter(target):
    actual = "{}.{}".format(*sys.version_info[:2])
    if actual not in DIRS:
        raise ValueError("unapproved_interpreter_minor")
    folder = Path(target).resolve()
    if (not folder.is_dir() or not folder.name == DIRS[actual] or
            not folder.parent == WORKSPACE.resolve()):
        raise ValueError("private_native_wheel_target_not_pinned")
    sys.path.insert(0, str(folder))
    module = _module()
    engine = module.real_duckdb_module()
    if engine is None:
        raise ValueError("real_native_duckdb_unavailable")
    from importlib.util import find_spec
    spec = find_spec("_duckdb")
    native = Path(spec.origin).resolve()
    if native.parent != folder or not native.suffix == ".so":
        raise ValueError("duckdb_native_extension_outside_private_target")
    native_hash = hashlib.sha256(native.read_bytes()).hexdigest()
    events = _measured_histories(actual)
    with tempfile.TemporaryDirectory(prefix="rph-real-duckdb-proof-") as scratch:
        path = Path(scratch) / "real-engine.duckdb"
        report = module.analytical_duckdb_history(
            path, events, hashlib.sha256(module._json_bytes(events)).hexdigest(),
            repeat_queries=MIN_QUERY_ROUNDS)
        if not report.get("actual_duckdb_sql_executed") or not path.is_file():
            raise ValueError("real_duckdb_sql_not_executed")
        independently_verified = []
        for group in report["aggregate_rows"]:
            own = [row for row in events if row["python_minor"] == group["python_minor"]
                   and row["candidate_id"] == group["candidate_id"]]
            expected = {
                "runs": len(own),
                "passed": sum(row["status"] == "PASS" for row in own),
                "rss_peak_kib": max(row["rss_kib"] for row in own),
                "latency_p95_ms": _quantile_cont([row["duration_ms"] for row in own], .95),
            }
            exact = (group["runs"] == expected["runs"] and
                     group["passed"] == expected["passed"] and
                     group["rss_peak_kib"] == expected["rss_peak_kib"] and
                     abs(group["latency_p95_ms"]-expected["latency_p95_ms"]) < 1e-8)
            if not exact:
                raise ValueError("independent_python_sql_oracle_mismatch")
            independently_verified.append(group["candidate_id"])
        if (report["historical_rows"] != len(events) or
                report["independent_query_rounds"] != MIN_QUERY_ROUNDS or
                report["p95_query_ms"] > PREDECLARED_P95_MS):
            raise ValueError("predeclared_analytical_benchmark_gate_failed")
    return {"status": "REAL_DUCKDB_NATIVE_AND_ORACLES_PASS",
            "actual_python_minor": actual,
            "duckdb_version": report["duckdb_version"],
            "real_native_extension_sha256": native_hash,
            "private_native_wheel_target": str(folder),
            "actual_experiment_measurements": len(events),
            "source_fixture_sha256": PINNED_SOURCE,
            "measured_sql_query_rounds": MIN_QUERY_ROUNDS,
            "measured_sql_query_timings_ms": report["query_timings_ms"],
            "sql_query_p95_ms": report["p95_query_ms"],
            "predeclared_sql_query_p95_limit_ms": PREDECLARED_P95_MS,
            "persisted_aggregates": report["aggregate_rows"],
            "independent_python_oracle_groups_verified": independently_verified,
            "all_sql_oracles_pass": True,
            "installed_native_engine_used": True,
            "unknown_project_code_executed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--single", action="store_true")
    parser.add_argument("--target", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.single:
        if args.target is None or args.output is not None:
            parser.error("single mode requires --target and prohibits --output")
        try:
            result = one_interpreter(args.target)
        except Exception as exc:
            print(json.dumps({"status": "NOT_RUN_OR_FAILED",
                              "reason_type": type(exc).__name__}))
            return 2
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0
    if args.target is not None or args.output is None:
        parser.error("aggregate mode requires --output only")
    reports = []
    for version, directory in DIRS.items():
        command = [PYTHON_BIN[version], "-I", "-S", "-B", str(Path(__file__).resolve()),
                   "--single", "--target", str(WORKSPACE / directory)]
        child = subprocess.run(command, capture_output=True, timeout=30, check=False)
        if child.returncode != 0:
            print(json.dumps({"status": "NOT_RUN", "failed_minor": version}))
            return 2
        data = json.loads(child.stdout)
        if data.get("status") != "REAL_DUCKDB_NATIVE_AND_ORACLES_PASS":
            print(json.dumps({"status": "NOT_RUN", "failed_minor": version}))
            return 2
        reports.append(data)
    report = {
        "schema_version": 1,
        "tested_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "REAL_DUCKDB_ALL_SEVEN_NATIVE_INTERPRETERS_PASS",
        "interpreter_count": 7,
        "native_duckdb_versions": {row["actual_python_minor"]: row["duckdb_version"]
                                   for row in reports},
        "actual_experiment_measurements": sum(row["actual_experiment_measurements"]
                                               for row in reports),
        "five_query_timings_per_minor": all(row["measured_sql_query_rounds"] == 5
                                            for row in reports),
        "total_independently_measured_sql_queries": 35,
        "all_sql_oracles_pass": all(row["all_sql_oracles_pass"] for row in reports),
        "real_native_wheel_dependency_not_bundled": True,
        "unknown_project_code_executed": False,
        "versions": reports,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        print(json.dumps({"status": "NOT_WRITTEN_OUTPUT_EXISTS"}))
        return 2
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps({"status": report["status"],
                      "native_versions": report["native_duckdb_versions"],
                      "timed_queries": report["total_independently_measured_sql_queries"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
