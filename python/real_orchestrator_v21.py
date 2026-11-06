"""Actual bounded trusted-fixture Rust/Ruff orchestration, never general code execution.

Only two hardcoded repair inputs, explicitly allowlisted candidate bytes, fixed
behavioral probes and independently launched CPython versions may be executed.
Every decision is scoped to these fixtures: this is *not* an external safety
audit, autonomous project test runner, or authority to deploy repairs.
"""

import argparse
import hashlib
import json
import math
import os
import secrets
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

FIXTURES = {
    "ruff": {"source": b"import os\n\nanswer = 42\n", "candidate": b"\nanswer = 42\n"},
    "colon": {"source": b"if True\n    answer = 42\n", "candidate": b"if True:\n    answer = 42\n"},
}
EXPECTED_MINORS = ("3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15")
SIX_AXES = ("SAFETY", "CORRECTNESS", "SPEED", "RELIABILITY", "COMPATIBILITY", "FUTURE_READINESS")
LIMITS = {"SAFETY": 0, "CORRECTNESS": 0, "SPEED": 300.0, "RELIABILITY": 10,
          "COMPATIBILITY": 7, "FUTURE_READINESS": 30}
MAX_CANDIDATES = 2
MAX_WORKERS = 4
MAX_BEHAVIOR_REPEATS = 10
MAX_OBSERVATION_BYTES = 100_000
MAX_SOURCE_BYTES = 4096
MAX_MEMORY_BUDGET_KB = 2_000_000
MAX_CPU_BUDGET_MS = 30_000

# Distinct subprocess worker runs the real Rust repair command and measures
# *its own* child resource use (not parent cumulative/cross-thread rusage).
MEASURED_WORKER = r'''
import json,resource,subprocess,sys,time
binary,ruff,python,source,candidate,ledger = sys.argv[1:7]
before=resource.getrusage(resource.RUSAGE_CHILDREN)
started=time.perf_counter_ns()
try:
    proc=subprocess.run([binary,"repair",source,"--ruff",ruff,"--python",python,
                         "--out",candidate,"--ledger",ledger],
                        capture_output=True,check=False,timeout=35)
    data=json.loads(proc.stdout) if not proc.returncode and len(proc.stdout)<=100000 else None
    status="PASS" if proc.returncode==0 and not proc.stderr and data is not None else "FAIL"
except (OSError,subprocess.TimeoutExpired,ValueError):
    status="NOT_RUN";data=None
elapsed=(time.perf_counter_ns()-started)/1000000
after=resource.getrusage(resource.RUSAGE_CHILDREN)
cpu_ms=max(0,(after.ru_utime-before.ru_utime+after.ru_stime-before.ru_stime)*1000)
print(json.dumps({"status":status,"rust_report":data,"wall_ms":round(elapsed,5),
                  "cpu_ms":round(cpu_ms,5),"peak_child_rss_kb":max(0,after.ru_maxrss),
                  "tokens":0,"cloud_cost_usd":0.0},sort_keys=True))
'''

# Candidate path is passed only after exact bytes match the fixture allowlist.
# Expression evaluation never accepts arbitrary project input or code bytes.
TRUSTED_BEHAVIOR_PROGRAM = r'''
import hashlib,json,sys
path,probe,expected_sha = sys.argv[1:4]
namespace={}
with open(path,"rb") as handle:
    source=handle.read(4097)
if len(source)>4096 or hashlib.sha256(source).hexdigest()!=expected_sha:
    sys.exit(47)
exec(compile(source,path,"exec"),namespace)
answer=namespace["answer"]
checks={"eq42":answer==42,"positive":answer>0,"even":answer%2==0,
        "int":type(answer)==int,"lt100":answer<100,
        "eq43":answer==43,"negative":answer<0,"odd":answer%2==1,
        "lt0":answer<0,"gt100":answer>100}
print(json.dumps({"status":"PASS" if checks[probe] else "FAIL"}))
'''
PROBES = ("eq42", "positive", "even", "int", "lt100", "eq43", "negative", "odd", "lt0", "gt100")
REQUIRED_PROBES = PROBES[:5]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def rank_measured_gates(candidates):
    """Six hard gates before scoring; at most one reserve, else NO_WINNER."""
    if type(candidates) is not list or not 1 <= len(candidates) <= MAX_CANDIDATES:
        raise ValueError("invalid_candidate_count")
    passing = []
    decisions = []
    identities = set()
    for candidate in candidates:
        if type(candidate) is not dict or set(candidate) != {"variant_id", "gates", "metrics", "trusted_measured"}:
            raise ValueError("invalid_candidate_schema")
        identity = candidate["variant_id"]
        if type(identity) is not str or not identity or identity in identities:
            raise ValueError("duplicate_or_invalid_candidate")
        identities.add(identity)
        gates, metrics = candidate["gates"], candidate["metrics"]
        if type(gates) is not dict or type(metrics) is not dict or set(gates) != set(SIX_AXES) or set(metrics) != set(SIX_AXES):
            raise ValueError("all_six_axes_required")
        fails = []
        for name in SIX_AXES:
            measurement = metrics[name]
            if type(measurement) not in (int, float) or not math.isfinite(measurement) or measurement < 0:
                raise ValueError("invalid_measured_axis")
            if gates[name] is not True or candidate["trusted_measured"] is not True:
                fails.append(name + "_NOT_PASS")
            elif ((name in ("RELIABILITY", "COMPATIBILITY") and measurement < LIMITS[name]) or
                  (name not in ("RELIABILITY", "COMPATIBILITY") and measurement > LIMITS[name])):
                fails.append(name + "_THRESHOLD_FAIL")
        decisions.append({"variant_id": identity,
                          "status": "QUALIFIED_TRUSTED_ONLY" if not fails else "REJECTED",
                          "failed_gates": fails})
        if not fails:
            passing.append((metrics["CORRECTNESS"], metrics["SAFETY"], -metrics["RELIABILITY"],
                            metrics["SPEED"], -metrics["COMPATIBILITY"], identity))
    passing.sort()
    return {"decision": "TRUSTED_FIXTURE_PRIMARY" if passing else "NO_WINNER",
            "primary_variant": passing[0][-1] if passing else None,
            "reserve_variant": passing[1][-1] if len(passing) > 1 else None,
            "qualified": len(passing), "maximum_reserves": 1,
            "ranked_only_after_all_six_measured_gates": True,
            "external_independent_audit": False, "release_authorized": False,
            "decisions": decisions}


def runtime_environment(folder):
    return {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "TZ": "UTC",
            "TMPDIR": str(folder), "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"}


def _selected_runtime_minor(python, folder):
    try:
        proc = subprocess.run([str(python), "-I", "-S", "-B", "-c",
                               "import sys;print('{}.{}'.format(*sys.version_info[:2]))"],
                              cwd=str(folder), env=runtime_environment(folder),
                              capture_output=True, check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode or proc.stderr or len(proc.stdout) > 15:
        return None
    return proc.stdout.decode("ascii", errors="replace").strip()


def _independent_repair_worker(binary, ruff, python, parent, engine):
    fixture = FIXTURES[engine]
    folder = parent / engine
    folder.mkdir()
    source = folder / "snapshot.py"
    candidate = folder / "candidate.py"
    ledger = folder / "evidence.sqlite"
    source.write_bytes(fixture["source"])
    source.chmod(0o400)
    before_sha = sha(source.read_bytes())
    secret_config_sha = sha(secrets.token_bytes(32))
    args = [str(python), "-I", "-S", "-B", "-c", MEASURED_WORKER,
            str(binary), str(ruff), str(python), str(source), str(candidate), str(ledger)]
    start_ns = time.perf_counter_ns()
    try:
        proc = subprocess.run(args, cwd=str(folder), env=runtime_environment(folder),
                              capture_output=True, check=False, timeout=45)
        answer = json.loads(proc.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        answer = None
    measured = (time.perf_counter_ns() - start_ns) / 1e6
    valid = (answer is not None and proc.returncode == 0 and not proc.stderr and
             answer.get("status") == "PASS" and answer.get("rust_report") is not None and
             answer["rust_report"].get("status") == "CANDIDATE_ONLY" and
             answer["rust_report"].get("winner") == "NONE" and
             answer["rust_report"].get("candidate_saved") == str(candidate) and
             source.is_file() and sha(source.read_bytes()) == before_sha and
             candidate.is_file() and candidate.stat().st_size <= MAX_SOURCE_BYTES and
             candidate.read_bytes() == fixture["candidate"])
    if valid:
        candidate.chmod(0o400)
    return {"engine": engine, "status": "TRUSTED_VARIANT_GENERATED" if valid else "REJECTED_OR_NOT_RUN",
            "variant_id": "V-" + sha((engine + before_sha + secret_config_sha).encode())[:24],
            "config_initialization_sha256": secret_config_sha,
            "immutable_snapshot_sha256": before_sha,
            "candidate_sha256": sha(candidate.read_bytes()) if valid else None,
            "snapshot_preserved": source.is_file() and sha(source.read_bytes()) == before_sha,
            "separate_workdir": str(folder), "candidate_path": str(candidate) if valid else None,
            "worker_wall_ms": round(measured, 5),
            "rust_child_wall_ms": answer.get("wall_ms") if answer else None,
            "cpu_ms": answer.get("cpu_ms") if answer else None,
            "peak_rss_kb": answer.get("peak_child_rss_kb") if answer else None,
            "actual_tokens_used": answer.get("tokens") if answer else None,
            "cloud_cost_usd": answer.get("cloud_cost_usd") if answer else None}


def _trusted_behavior_process(python, folder, candidate, expected_sha, probe):
    if probe not in PROBES:
        raise ValueError("unapproved_trusted_probe")
    before = time.perf_counter_ns()
    try:
        proc = subprocess.run([str(python), "-I", "-S", "-B", "-c", TRUSTED_BEHAVIOR_PROGRAM,
                               str(candidate), probe, expected_sha], cwd=str(folder),
                              env=runtime_environment(folder), capture_output=True,
                              check=False, timeout=5)
        outcome = json.loads(proc.stdout)
        valid = proc.returncode == 0 and not proc.stderr and outcome.get("status") in ("PASS", "FAIL")
        status = outcome["status"] if valid else "NOT_RUN"
    except (OSError, subprocess.TimeoutExpired, ValueError):
        status = "NOT_RUN"
    return {"status": status, "elapsed_ms": round((time.perf_counter_ns() - before) / 1e6, 5),
            "probe": probe, "minor": None}


def _measured_behavioral_matrix(variants, interpreters, worker_cap):
    """Run real independent CPython processes, preserving exact trusted hashes."""
    jobs = []
    outcomes = {row["variant_id"]: {} for row in variants}
    by_minor = {row["variant_id"]: {} for row in variants}
    tasks = []
    for variant in variants:
        for minor in EXPECTED_MINORS:
            for rep in range(MAX_BEHAVIOR_REPEATS):
                tasks.append((variant, minor, "eq42", rep))
        # Fixed negative probes yield descriptive outcome diversity, NOT
        # acceptance failures. Never use expected-negative probes as hard gates.
        for rep, probe in enumerate(PROBES):
            tasks.append((variant, "probe", probe, rep))
    # With both variants repaired, prioritize the longest outstanding test arm
    # of their dependency DAG. Deterministic ties alternate by remaining work.
    remaining = {variant["variant_id"]: sum(task[0]["variant_id"] == variant["variant_id"]
                                             for task in tasks) for variant in variants}
    dispatched = []
    while tasks:
        tasks.sort(key=lambda task: (-remaining[task[0]["variant_id"]], task[0]["variant_id"],
                                     task[1], task[3]))
        selected = tasks.pop(0)
        remaining[selected[0]["variant_id"]] -= 1
        dispatched.append(selected)
    with ThreadPoolExecutor(max_workers=worker_cap) as executor:
        for variant, minor, probe, rep in dispatched:
            python = interpreters[EXPECTED_MINORS[0] if minor == "probe" else minor]
            candidate = variant["candidate_path"]
            jobs.append((variant["variant_id"], minor, probe, rep,
                         executor.submit(_trusted_behavior_process, python,
                                         Path(candidate).parent, candidate,
                                         variant["candidate_sha256"], probe)))
        observations = []
        for identity, minor, probe, rep, future in jobs:
            observed = future.result()
            observed.update({"variant_id": identity, "minor": minor, "retest": rep > 0})
            observations.append(observed)
            if minor == "probe":
                outcomes[identity][probe] = observed["status"]
            else:
                by_minor[identity].setdefault(minor, []).append(observed)
    return observations, by_minor, outcomes


def _measured_phi(left, right):
    cases = sorted(set(left) & set(right))
    if len(cases) != len(PROBES) or any(left[case] not in ("PASS", "FAIL") or
                                       right[case] not in ("PASS", "FAIL") for case in cases):
        return None
    x = [int(left[case] == "PASS") for case in cases]
    y = [int(right[case] == "PASS") for case in cases]
    n, nx, ny = len(cases), sum(x), sum(y)
    den = math.sqrt(nx * (n - nx) * ny * (n - ny))
    return round((n * sum(a * b for a, b in zip(x, y)) - nx * ny) / den, 6) if den else None


def run_trusted_orchestrator(binary, ruff, interpreters, max_workers=4,
                             memory_budget_kb=150_000, cpu_budget_ms=30_000,
                             deliberately_reject=()):
    """Real-worker orchestration; six hard gates only on allowlisted fixed source.

    `deliberately_reject` is a test-only negative-injection list of axis names.
    It can only *remove* PASS, never invent or override missing measurements.
    """
    if type(max_workers) is not int or not 1 <= max_workers <= MAX_WORKERS:
        raise ValueError("invalid_worker_limit")
    if type(memory_budget_kb) is not int or not 1 <= memory_budget_kb <= MAX_MEMORY_BUDGET_KB:
        raise ValueError("invalid_memory_budget")
    if type(cpu_budget_ms) is not int or not 1 <= cpu_budget_ms <= MAX_CPU_BUDGET_MS:
        raise ValueError("invalid_cpu_budget")
    if type(deliberately_reject) not in (tuple, list) or any(x not in SIX_AXES for x in deliberately_reject):
        raise ValueError("invalid_negative_fixture_gate")
    if type(interpreters) is not dict or set(interpreters) != set(EXPECTED_MINORS):
        raise ValueError("seven_explicit_python_minors_required")
    executables = {minor: Path(python).absolute() for minor, python in interpreters.items()}
    binary, ruff = Path(binary).absolute(), Path(ruff).absolute()
    if not binary.is_file() or not ruff.is_file() or any(not value.is_file() for value in executables.values()):
        return {"status": "NOT_RUN_MISSING_SELECTED_BINARY", "decision": "NO_WINNER",
                "release_authorized": False}
    started_at = time.perf_counter_ns()
    with tempfile.TemporaryDirectory(prefix="rph-v21-actual-") as temporary:
        folder = Path(temporary)
        version_proofs = {minor: _selected_runtime_minor(path, folder) for minor, path in executables.items()}
        if any(observed != requested for requested, observed in version_proofs.items()):
            return {"status": "RUNTIME_MINOR_MISMATCH", "decision": "NO_WINNER",
                    "version_proofs": version_proofs, "release_authorized": False}
        # Actual independent worker subprocesses and source snapshots.
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(_independent_repair_worker, binary, ruff,
                                   executables[EXPECTED_MINORS[0]], folder, engine)
                       for engine in FIXTURES]
            variants = [future.result() for future in futures]
        unique_init = len({row["config_initialization_sha256"] for row in variants}) == len(variants)
        if not unique_init:
            return {"status": "DUPLICATE_INITIALIZATION_REJECTED", "decision": "NO_WINNER",
                    "release_authorized": False}
        healthy = [variant for variant in variants if variant["status"] == "TRUSTED_VARIANT_GENERATED"]
        measured_peak_rss_kb = max((row["peak_rss_kb"] or 0 for row in healthy), default=0)
        measured_peak_cpu_ms = max((row["cpu_ms"] or 0 for row in healthy), default=0)
        # Actual measured resource peak from independent worker processes feeds
        # the bounded verification worker pool. No CPU/RAM usage is self-reported.
        memory_slots = memory_budget_kb // max(1, measured_peak_rss_kb)
        cpu_slots = cpu_budget_ms // max(1, math.ceil(measured_peak_cpu_ms))
        adaptive_cap = min(max_workers, max(1, memory_slots), max(1, cpu_slots))
        blocked_by_budget = memory_slots < 1 or cpu_slots < 1
        if healthy and not blocked_by_budget:
            observations, by_minor, probe_outcomes = _measured_behavioral_matrix(
                healthy, executables, adaptive_cap)
        else:
            observations, by_minor, probe_outcomes = [], {}, {}

        candidates = []
        for variant in variants:
            identity = variant["variant_id"]
            minor_results = by_minor.get(identity, {})
            all_checks = [item for results in minor_results.values() for item in results]
            measured_ms = [item["elapsed_ms"] for item in all_checks if item["status"] != "NOT_RUN"]
            correct_checks = sum(item["status"] == "PASS" for item in all_checks)
            passing_minors = sum(len(minor_results.get(minor, [])) == MAX_BEHAVIOR_REPEATS and all(
                item["status"] == "PASS" for item in minor_results[minor]) for minor in EXPECTED_MINORS)
            p95 = (sorted(measured_ms)[math.ceil(0.95 * len(measured_ms)) - 1]
                   if len(measured_ms) == 7 * MAX_BEHAVIOR_REPEATS else 1e9)
            success = variant["status"] == "TRUSTED_VARIANT_GENERATED" and not blocked_by_budget
            metrics = {"SAFETY": 0 if success else 1,
                       "CORRECTNESS": 70 - correct_checks,
                       "SPEED": p95,
                       "RELIABILITY": min((sum(item["status"] == "PASS" for item in minor_results.get(minor, []))
                                            for minor in EXPECTED_MINORS), default=0),
                       "COMPATIBILITY": passing_minors,
                       "FUTURE_READINESS": 0 if success else 31}
            gates = {axis: success and axis not in deliberately_reject for axis in SIX_AXES}
            candidates.append({"variant_id": identity, "gates": gates,
                               "metrics": metrics, "trusted_measured": success})
        decision = rank_measured_gates(candidates)
        if len(healthy) == 2 and all(row["variant_id"] in probe_outcomes for row in healthy):
            correlation = _measured_phi(probe_outcomes[healthy[0]["variant_id"]],
                                        probe_outcomes[healthy[1]["variant_id"]])
        else:
            correlation = None
        duration_ms = (time.perf_counter_ns() - started_at) / 1e6
        measured_paths = {row["engine"]: row["worker_wall_ms"] + max((
            item["elapsed_ms"] for item in observations if item["variant_id"] == row["variant_id"]),
            default=0)
            for row in variants}
        return {"schema_version": 1,
                "status": "TRUSTED_FIXTURE_ORCHESTRATED" if len(healthy) == 2 and not blocked_by_budget
                          else "INCOMPLETE_OR_BUDGET_BLOCKED",
                "decision": decision["decision"], "selection": decision,
                "scope": "TWO_HARDCODED_ALLOWLISTED_REPAIRS_ONLY",
                "python_minor_proofs": version_proofs,
                "variants": [{key: value for key, value in row.items() if key != "candidate_path"}
                             for row in variants],
                "candidate_gates": candidates,
                "actual_child_behavior_observations": len(observations),
                "per_variant_probe_outcomes": probe_outcomes,
                "measured_probe_phi": correlation,
                "repair_independent_processes": len(healthy),
                "independent_initializations": unique_init,
                "resource_peak_rss_kb": measured_peak_rss_kb,
                "resource_peak_cpu_ms": measured_peak_cpu_ms,
                "adaptive_worker_cap_before": max_workers,
                "adaptive_worker_cap_after_real_measurement": adaptive_cap if not blocked_by_budget else 0,
                "declared_memory_budget_kb": memory_budget_kb,
                "declared_cpu_budget_ms": cpu_budget_ms,
                "resource_limit_prevented_dispatch": blocked_by_budget,
                "measured_critical_path_ms": round(max(measured_paths.values(), default=0), 5),
                "critical_path_after_worker_measurement_ms": {key: round(value, 5)
                                                            for key, value in measured_paths.items()},
                "trusted_dag": "snapshot -> independent repair -> ten-per-minor validation -> six gates -> rank",
                "measured_total_wall_ms": round(duration_ms, 5),
                "actual_tokens_used": sum((row["actual_tokens_used"] or 0) for row in variants),
                "actual_cloud_cost_usd": sum((row["cloud_cost_usd"] or 0) for row in variants),
                "model_router_feedback": {row["engine"]: {"cpu_ms": row["cpu_ms"],
                                                          "latency_ms": row["worker_wall_ms"],
                                                          "quality": candidates[n]["metrics"]}
                                          for n, row in enumerate(variants)},
                "external_models_called": False,
                "independent_external_oracle": False,
                "independent_security_audit": False,
                "untrusted_project_code_executed": False,
                "workspace_snapshot_retained": False,
                "release_authorized": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--ruff", required=True)
    parser.add_argument("--runtime-json", required=True, help="JSON object of 3.9..3.15 paths")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--memory-kb", type=int, default=150000)
    parser.add_argument("--cpu-ms", type=int, default=30000)
    args = parser.parse_args()
    try:
        path = Path(args.runtime_json)
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 16_384:
            raise ValueError("bounded_runtime_json_required")
        runtimes = json.loads(path.read_text(encoding="utf-8"))
        report = run_trusted_orchestrator(args.binary, args.ruff, runtimes, args.workers,
                                          args.memory_kb, args.cpu_ms)
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
