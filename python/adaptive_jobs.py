"""Bounded data-only DAG scheduling and independently initialized variant metadata.

No arbitrary Python is imported or executed. The virtual-time simulator uses
trusted supplied costs; the separate bounded live executor executes only a
hardcoded sleep-and-PID subprocess fixture with measured process overlap.
Imported repair outcomes support descriptive correlations, not verified causality.
"""

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MAX_JOBS = 128
MAX_DURATION_MS = 1_000_000
MAX_WORKERS = 32
MAX_MEMORY_MB = 65_536
MAX_VARIANTS = 12
MIN_CORRELATION_CASES = 4
SUPPORTED_REPAIR_ENGINES = frozenset(("ruff-safe", "missing-colon"))
MAX_LIVE_JOBS = 24
MAX_LIVE_WORKERS = 8
MAX_LIVE_TOTAL_SLEEP_MS = 3000
MAX_LIVE_SINGLE_SLEEP_MS = 250
MAX_LIVE_WALL_MS = 10_000
TRUSTED_LIVE_SCRIPT = ("import os,sys,time;time.sleep(float(sys.argv[1]));"
                       "print(str(os.getpid())+' '+str(sys.version_info[0])+'.'+str(sys.version_info[1]))")


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


def _positive_int(value, ceiling, name):
    if type(value) is not int or not 1 <= value <= ceiling:
        raise ValueError("invalid_" + name)
    return value


def _job_graph(jobs):
    if type(jobs) is not list or not 1 <= len(jobs) <= MAX_JOBS:
        raise ValueError("invalid_job_count")
    by_id = {}
    for row in jobs:
        if type(row) is not dict or set(row) != {"id", "duration_ms", "memory_mb", "deps"}:
            raise ValueError("invalid_job_schema")
        name = row["id"]
        if type(name) is not str or not 1 <= len(name) <= 80 or not name.isascii() or not all(
                character.isalnum() or character in "_-" for character in name):
            raise ValueError("invalid_job_id")
        if name in by_id:
            raise ValueError("duplicate_job_id")
        duration = _positive_int(row["duration_ms"], MAX_DURATION_MS, "duration")
        memory = _positive_int(row["memory_mb"], MAX_MEMORY_MB, "memory")
        deps = row["deps"]
        if type(deps) is not list or len(deps) > MAX_JOBS or any(type(d) is not str for d in deps):
            raise ValueError("invalid_dependencies")
        if len(set(deps)) != len(deps):
            raise ValueError("duplicate_dependencies")
        by_id[name] = {"duration_ms": duration, "memory_mb": memory, "deps": tuple(deps)}
    for name, job in by_id.items():
        if any(d not in by_id for d in job["deps"]):
            raise ValueError("unknown_dependency")
        if name in job["deps"]:
            raise ValueError("cyclic_dependency")

    visit = {}
    order = []

    def walk(name):
        if visit.get(name) == "active":
            raise ValueError("cyclic_dependency")
        if name in visit:
            return
        visit[name] = "active"
        for dependency in by_id[name]["deps"]:
            walk(dependency)
        visit[name] = "done"
        order.append(name)

    for name in sorted(by_id):
        walk(name)
    return by_id, order


def schedule_trusted_fixture(jobs, max_workers=4, memory_limit_mb=1024):
    """Adapt workers in a virtual-time DAG; record real decision-wall-clock cost."""
    max_workers = _positive_int(max_workers, MAX_WORKERS, "max_workers")
    memory_limit_mb = _positive_int(memory_limit_mb, MAX_MEMORY_MB, "memory_limit")
    by_id, order = _job_graph(jobs)
    if any(job["memory_mb"] > memory_limit_mb for job in by_id.values()):
        raise ValueError("job_exceeds_memory_limit")

    completed = set()
    active = {}  # job id -> virtual completion time
    finished_at = {}
    events = []
    decision_latencies_ms = []
    now = 0
    highest_worker_count = 0
    worker_counts = set()
    last_critical_path_ms = None

    def critical_paths():
        # Static dependency graph, dynamic durations of *unfinished* jobs.
        downstream = {name: [] for name in by_id}
        for child, job in by_id.items():
            for parent in job["deps"]:
                downstream[parent].append(child)
        critical = {}
        for name in reversed(order):
            if name in completed:
                continue
            own = max(0, active[name] - now) if name in active else by_id[name]["duration_ms"]
            successors = [critical[child] for child in downstream[name] if child in critical]
            critical[name] = own + (max(successors) if successors else 0)
        return critical

    while len(completed) < len(by_id):
        decision_start = time.perf_counter_ns()
        paths = critical_paths()
        ready = [name for name in by_id if name not in completed and name not in active and
                 all(dep in completed for dep in by_id[name]["deps"])]
        ready.sort(key=lambda item: (-paths[item], item))
        free_memory = memory_limit_mb - sum(by_id[name]["memory_mb"] for name in active)
        capacity = max_workers - len(active)
        queue_pressure = len(ready) / float(max(1, capacity))
        # This is a predeclared, bounded queue-pressure policy, not CPU telemetry.
        desired_total = min(max_workers, max(1, math.ceil(len(ready) * 0.75) + len(active)))
        starts = []
        while ready and len(active) < desired_total:
            matching = next((name for name in ready if by_id[name]["memory_mb"] <= free_memory), None)
            if matching is None:
                break
            ready.remove(matching)
            active[matching] = now + by_id[matching]["duration_ms"]
            free_memory -= by_id[matching]["memory_mb"]
            starts.append(matching)
        decision_ms = (time.perf_counter_ns() - decision_start) / 1e6
        decision_latencies_ms.append(decision_ms)
        highest_worker_count = max(highest_worker_count, len(active))
        worker_counts.add(len(active))
        path_remaining = max(paths.values()) if paths else 0
        critical_delta = (last_critical_path_ms - path_remaining
                          if last_critical_path_ms is not None else 0)
        last_critical_path_ms = path_remaining
        events.append({"virtual_at_ms": now, "event": "schedule", "started": starts,
                       "ready_backlog": len(ready), "queue_pressure_before": round(queue_pressure, 6),
                       "adaptive_target_workers": desired_total, "running_workers": len(active),
                       "critical_path_remaining_ms": path_remaining,
                       "critical_path_delta_ms": critical_delta,
                       "wall_decision_ms": round(decision_ms, 6)})
        if not active:
            raise ValueError("no_schedulable_jobs")
        now = min(active.values())
        ended = sorted(name for name in active if active[name] == now)
        for name in ended:
            del active[name]
            completed.add(name)
            finished_at[name] = now
        path_remaining = max(critical_paths().values(), default=0)
        critical_delta = last_critical_path_ms - path_remaining
        last_critical_path_ms = path_remaining
        events.append({"virtual_at_ms": now, "event": "finished", "jobs": ended,
                       "critical_path_remaining_ms": path_remaining,
                       "critical_path_delta_ms": critical_delta})

    total = sum(job["duration_ms"] for job in by_id.values())
    return {"schema_version": 1, "status": "TRUSTED_DATA_ONLY_SIMULATION",
            "execution_type": "VIRTUAL_TIME_NO_TASK_EXECUTION", "untrusted_code_executed": False,
            "fixture_costs_independently_measured": False,
            "actual_parallel_runtime_measured": False,
            "real_scheduler_decision_latency_measured": True,
            "max_workers": max_workers, "memory_limit_mb": memory_limit_mb,
            "observed_worker_counts": sorted(worker_counts),
            "peak_workers": highest_worker_count,
            "simulated_makespan_ms": now, "simulated_serial_ms": total,
            "simulated_speedup": round(total / now, 6),
            "median_real_scheduler_decision_ms": round(sorted(decision_latencies_ms)[len(decision_latencies_ms) // 2], 6),
            "events": events, "jobs_finished_at_ms": finished_at,
            "release_authorized": False}


def _actual_known_trusted_child(python, folder, duration_ms):
    env = _with_native_windows_root({"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "TZ": "UTC",
           "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(folder)})
    started_ns = time.perf_counter_ns()
    try:
        child = subprocess.Popen([str(python), "-I", "-S", "-B", "-c", TRUSTED_LIVE_SCRIPT,
                                  str(duration_ms / 1000.0)], cwd=str(folder), env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        started_ns = time.perf_counter_ns()
        try:
            stdout, stderr = child.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate()
            return {"status": "NOT_RUN", "started_ns": started_ns,
                    "finished_ns": time.perf_counter_ns(), "process_pid": None,
                    "python_minor": None}
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "NOT_RUN", "started_ns": started_ns,
                "finished_ns": time.perf_counter_ns(), "process_pid": None,
                "python_minor": None}
    finished_ns = time.perf_counter_ns()
    try:
        pid_text, python_minor = stdout.decode("ascii").split()
        pid = int(pid_text)
    except (ValueError, TypeError, UnicodeDecodeError):
        pid = None
        python_minor = None
    valid = (child.returncode == 0 and not stderr and pid == child.pid and pid > 0 and
             python_minor is not None and len(python_minor) <= 5 and python_minor.startswith("3."))
    return {"status": "PASS" if valid else "FAIL", "started_ns": started_ns,
            "finished_ns": finished_ns, "process_pid": pid if valid else None,
            "python_minor": python_minor if valid else None}


def live_trusted_subprocess_schedule(jobs, python, max_workers=4, memory_limit_mb=1024):
    """Adapt *actual* concurrent fixed child processes; never run caller code.

    Jobs contain only id, sleep milliseconds, nominal memory budget, and deps.
    Report actual monotonic elapsed times, measured overlapping process slots,
    and real-duration longest-path changes. Memory values are declared fixture
    budgets, *not* measured resident memory and no production speedup is proven.
    """
    max_workers = _positive_int(max_workers, MAX_LIVE_WORKERS, "live_worker_limit")
    memory_limit_mb = _positive_int(memory_limit_mb, MAX_MEMORY_MB, "memory_limit")
    by_id, order = _job_graph(jobs)
    if len(by_id) > MAX_LIVE_JOBS or any(job["duration_ms"] > MAX_LIVE_SINGLE_SLEEP_MS
                                         for job in by_id.values()) or sum(
                                             job["duration_ms"] for job in by_id.values()) > MAX_LIVE_TOTAL_SLEEP_MS:
        raise ValueError("trusted_live_workload_quota_exceeded")
    if any(job["memory_mb"] > memory_limit_mb for job in by_id.values()):
        raise ValueError("job_exceeds_memory_limit")
    executable = Path(python).absolute()
    if not executable.is_file():
        return {"status": "NOT_RUN_MISSING_SELECTED_PYTHON", "trusted_child_executed": False,
                "untrusted_project_code_executed": False, "release_authorized": False}

    completed = set()
    running = {}  # job id -> concurrent.futures.Future
    started_at = {}
    observations = {}
    timeline = []
    runtime_start_ns = time.perf_counter_ns()

    def remaining_critical_path(now_ns):
        paths = {}
        for name in reversed(order):
            if name in completed:
                continue
            elapsed = (now_ns - started_at[name]) / 1e6 if name in started_at else 0
            own = max(0.0, by_id[name]["duration_ms"] - elapsed)
            downstream = [paths[child] for child in paths if name in by_id[child]["deps"]]
            paths[name] = own + (max(downstream) if downstream else 0)
        return max(paths.values(), default=0.0), paths

    failed = False
    with tempfile.TemporaryDirectory(prefix="rph-real-workers-") as temporary:
        folders = {}
        for name in by_id:
            folders[name] = Path(temporary) / name
            folders[name].mkdir()
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            while len(completed) < len(by_id):
                decision_start_ns = time.perf_counter_ns()
                critical_before, scores = remaining_critical_path(decision_start_ns)
                ready = [name for name in by_id if name not in completed and name not in running and
                         all(dep in completed for dep in by_id[name]["deps"])]
                ready.sort(key=lambda item: (-scores[item], item))
                queue_pressure = len(ready) / float(max(1, max_workers - len(running)))
                target = min(max_workers, max(1, len(running) + math.ceil(0.75 * len(ready))))
                free_mb = memory_limit_mb - sum(by_id[name]["memory_mb"] for name in running)
                started = []
                while ready and len(running) < target:
                    fitting = next((name for name in ready if by_id[name]["memory_mb"] <= free_mb), None)
                    if fitting is None:
                        break
                    ready.remove(fitting)
                    started_at[fitting] = time.perf_counter_ns()
                    running[fitting] = executor.submit(_actual_known_trusted_child,
                                                       executable, folders[fitting],
                                                       by_id[fitting]["duration_ms"])
                    free_mb -= by_id[fitting]["memory_mb"]
                    started.append(fitting)
                decision_done_ns = time.perf_counter_ns()
                timeline.append({"event": "dispatch", "wall_elapsed_ms": round(
                    (decision_done_ns - runtime_start_ns) / 1e6, 5),
                    "critical_path_remaining_estimate_ms": round(critical_before, 5),
                    "queue_pressure": round(queue_pressure, 5), "adaptive_target_workers": target,
                    "actual_inflight_worker_slots": len(running), "started": started,
                    "scheduler_decision_wall_ms": round((decision_done_ns - decision_start_ns) / 1e6, 5)})
                if not running:
                    raise ValueError("no_schedulable_jobs")
                timeout_remaining = (MAX_LIVE_WALL_MS - (time.perf_counter_ns() - runtime_start_ns) / 1e6) / 1000
                done, _ = concurrent.futures.wait(tuple(running.values()),
                                                   timeout=max(0, timeout_remaining),
                                                   return_when=concurrent.futures.FIRST_COMPLETED)
                if not done:
                    break
                for name, future in list(running.items()):
                    if future in done:
                        child = future.result()
                        del running[name]
                        child["duration_ms"] = round((child["finished_ns"] - child["started_ns"]) / 1e6, 5)
                        observations[name] = child
                        if child["status"] == "PASS":
                            completed.add(name)
                        else:
                            failed = True
                after_ns = time.perf_counter_ns()
                critical_after, _ = remaining_critical_path(after_ns)
                timeline.append({"event": "complete", "wall_elapsed_ms": round(
                    (after_ns - runtime_start_ns) / 1e6, 5),
                    "critical_path_remaining_estimate_ms": round(critical_after, 5),
                    "critical_path_difference_ms": round(critical_before - critical_after, 5),
                    "remaining_jobs": len(by_id) - len(completed)})
                if failed:
                    break

    real_elapsed_ms = (time.perf_counter_ns() - runtime_start_ns) / 1e6
    all_success = len(observations) == len(by_id) and all(
        item["status"] == "PASS" for item in observations.values())
    overlap_events = []
    for item in observations.values():
        if item["status"] == "PASS":
            overlap_events.extend(((item["started_ns"], 1), (item["finished_ns"], -1)))
    concurrency = 0
    peak_actual_overlap = 0
    for _, delta in sorted(overlap_events, key=lambda item: (item[0], item[1])):
        concurrency += delta
        peak_actual_overlap = max(peak_actual_overlap, concurrency)

    critical_measured = {}
    for name in order:
        parents = [critical_measured[d] for d in by_id[name]["deps"]]
        own = observations[name]["duration_ms"] if name in observations else 0
        critical_measured[name] = own + (max(parents) if parents else 0)
    nominal_paths = {}
    for name in order:
        nominal_paths[name] = by_id[name]["duration_ms"] + max(
            (nominal_paths[parent] for parent in by_id[name]["deps"]), default=0)
    initial_critical = max(nominal_paths.values())
    initial_static = sum(job["duration_ms"] for job in by_id.values())
    # The measured longest path uses actual child wall durations; it is not a
    # comparison with measured serial Rust, Ruff or production repairs.
    critical_real = max(critical_measured.values()) if all_success else None
    return {"schema_version": 1,
            "status": "TRUSTED_REAL_SUBPROCESS_EXECUTOR_PASS" if all_success else
                      "INCOMPLETE_OR_FAILED_TRUSTED_EXECUTOR",
            "scope": "HARDCODED_PYTHON_SLEEP_PID_CHILDREN_ONLY",
            "trusted_child_executed": bool(observations), "untrusted_project_code_executed": False,
            "observed_independent_processes": len(observations), "expected_processes": len(by_id),
            "actual_peak_overlapping_processes": peak_actual_overlap,
            "observed_adaptive_slot_counts": sorted({
                item["actual_inflight_worker_slots"] for item in timeline if item["event"] == "dispatch"}),
            "configured_thread_worker_cap": max_workers,
            "peak_dispatched_worker_slots": max((item["actual_inflight_worker_slots"]
                                                  for item in timeline if item["event"] == "dispatch"),
                                                 default=0),
            "live_makespan_ms": round(real_elapsed_ms, 5),
            "measured_process_critical_path_ms": round(critical_real, 5) if critical_real is not None else None,
            "nominal_single_worker_fixture_ms": initial_static,
            "nominal_critical_path_ms": initial_critical,
            "real_vs_nominal_critical_path_difference_ms": round(critical_real - initial_critical, 5)
            if critical_real is not None else None,
            "memory_is_only_declared_fixture_budget": True,
            "per_job": {name: {"status": item["status"], "duration_ms": item["duration_ms"],
                               "process_pid": item["process_pid"], "python_minor": item["python_minor"]}
                        for name, item in observations.items()},
            "timeline": timeline, "real_cpu_throughput_proven": False,
            "release_authorized": False}


def independently_initialize(source, engines=("ruff-safe", "missing-colon"), quantity=4):
    """Create separate *metadata* for repair trials, not real executed variants."""
    if type(source) is not bytes or len(source) > 4_000_000:
        raise ValueError("invalid_source_bytes")
    quantity = _positive_int(quantity, MAX_VARIANTS, "variant_count")
    if type(engines) not in (tuple, list) or not engines or any(
            type(engine) is not str or engine not in SUPPORTED_REPAIR_ENGINES for engine in engines):
        raise ValueError("unsupported_engine")
    source_sha = hashlib.sha256(source).hexdigest()
    generated = []
    seen = set()
    for n in range(quantity):
        engine = engines[n % len(engines)]
        random_material = secrets.token_bytes(32)
        material_digest = hashlib.sha256(random_material).hexdigest()
        if material_digest in seen:
            raise ValueError("cryptographic_random_collision")
        seen.add(material_digest)
        config_sha = hashlib.sha256((engine + ":" + material_digest).encode()).hexdigest()
        identity = hashlib.sha256((engine + ":" + source_sha + ":" + config_sha).encode()).hexdigest()
        generated.append({"variant_id": "V-" + identity[:24], "engine": engine,
                          "source_sha256": source_sha, "config_sha256": config_sha,
                          "independent_initialization_sha256": material_digest,
                          "trial_index": n})
    return {"status": "INDEPENDENT_METADATA_ONLY", "variants": generated,
            "independent_seeds_created": quantity, "repair_executed": False,
            "independence_of_actual_repair_models_proven": False,
            "outcome_causality_proven": False, "release_authorized": False}


def correlate_imported_outcomes(variants, outcomes):
    """Pearson phi of supplied case-status vectors; never call data verified."""
    if type(variants) is not list or not 2 <= len(variants) <= MAX_VARIANTS or not all(
            type(variant) is dict and type(variant.get("variant_id")) is str for variant in variants):
        raise ValueError("invalid_variants")
    ids = [variant["variant_id"] for variant in variants]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate_variant_id")
    if type(outcomes) is not dict or set(outcomes) != set(ids):
        raise ValueError("outcome_variant_mismatch")
    for item in outcomes.values():
        if type(item) is not dict or not 1 <= len(item) <= MAX_JOBS or any(
                type(case) is not str or not case or type(status) is not str or
                status not in ("PASS", "FAIL") for case, status in item.items()):
            raise ValueError("invalid_supplied_outcomes")

    pairs = []
    for i, left in enumerate(ids):
        for right in ids[i + 1:]:
            common = sorted(set(outcomes[left]) & set(outcomes[right]))
            number = len(common)
            relation = None
            if number >= MIN_CORRELATION_CASES:
                x = [int(outcomes[left][case] == "PASS") for case in common]
                y = [int(outcomes[right][case] == "PASS") for case in common]
                xsum, ysum = sum(x), sum(y)
                denominator = math.sqrt(xsum * (number - xsum) * ysum * (number - ysum))
                if denominator:
                    relation = round((number * sum(a * b for a, b in zip(x, y)) - xsum * ysum) /
                                     denominator, 6)
            pairs.append({"left": left, "right": right, "shared_cases": number,
                          "phi": relation, "agreement_fraction": round(sum(
                              outcomes[left][case] == outcomes[right][case] for case in common) /
                              number, 6) if number else None,
                          "interpretation": "DESCRIPTIVE_ONLY" if relation is not None else
                                            "UNDEFINED_OR_INSUFFICIENT_DATA"})
    return {"status": "IMPORTED_OUTCOMES_UNVERIFIED", "pairs": pairs,
            "minimum_shared_cases_predeclared": MIN_CORRELATION_CASES,
            "outcomes_independently_verified": False,
            "independent_repair_behavior_proven": False,
            "repair_executed": False, "release_authorized": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("schedule", "live", "variants", "correlation"), required=True)
    parser.add_argument("--input", help="JSON data-only input path; never executed")
    parser.add_argument("--python", help="Explicit selected CPython executable for fixed live subprocess fixture")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--memory-mb", type=int, default=1024)
    args = parser.parse_args()
    if not args.input:
        parser.error("explicit_input_required")
    try:
        path = Path(args.input)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 256_000:
            raise ValueError("input_exceeds_256kb_or_missing")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if type(payload) is not dict:
            raise ValueError("expected_json_object")
        if args.mode == "schedule":
            result = schedule_trusted_fixture(payload["jobs"], args.workers, args.memory_mb)
        elif args.mode == "live":
            if not args.python:
                raise ValueError("live_selected_python_required")
            result = live_trusted_subprocess_schedule(payload["jobs"], args.python,
                                                      args.workers, args.memory_mb)
        elif args.mode == "variants":
            source = payload["source_utf8"]
            if type(source) is not str:
                raise ValueError("source_must_be_string")
            result = independently_initialize(source.encode("utf-8"),
                                             payload.get("engines", ["ruff-safe", "missing-colon"]),
                                             payload.get("quantity", 4))
        else:
            result = correlate_imported_outcomes(payload["variants"], payload["outcomes"])
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    json.dump(result, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
