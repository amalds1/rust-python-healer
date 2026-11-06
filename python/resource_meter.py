"""Bounded CPU/RSS measurements of this module's *trusted* Python worker.

Never runs source code being debugged. Uses wait4() for per-child CPU and true
Linux high-water resident size; Windows uses the owned live child HANDLE for
GetProcessTimes and peak working set. Startup baseline is measured separately.
This is NOT an integrated Rust/Python pipeline profile or capacity guarantee.
"""

import argparse
import json
import math
import os
import queue
import select
import subprocess
import sys
import threading
import time


_TRUSTED_WORKER = r'''
import json
import resource
import sys
from time import monotonic_ns

def usage():
    r = resource.getrusage(resource.RUSAGE_SELF)
    return {"user_cpu_s": r.ru_utime, "system_cpu_s": r.ru_stime,
            "peak_rss_kib": r.ru_maxrss, "voluntary_switches": r.ru_nvcsw,
            "involuntary_switches": r.ru_nivcsw}

iterations = int(sys.argv[1])
memory_bytes = int(sys.argv[2])
print(json.dumps({"ready": True, "pid": __import__("os").getpid(),
                  "baseline": usage()}), flush=True)
if sys.stdin.buffer.readline() != b"RUN\n":
    raise SystemExit(12)
start = monotonic_ns()
region = bytearray(memory_bytes)
for pos in range(0, len(region), 4096):
    region[pos] = (pos // 4096) & 255
state = 1469598103934665603
for index in range(iterations):
    state = ((state ^ index) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
print(json.dumps({"fingerprint": "%016x" % state, "allocated_bytes": len(region),
                  "worker_elapsed_ns": monotonic_ns() - start}), flush=True)
'''


_TRUSTED_WINDOWS_WORKER = r'''
import json,os,sys
from time import monotonic_ns
iterations = int(sys.argv[1])
memory_bytes = int(sys.argv[2])
print(json.dumps({"ready": True, "pid": os.getpid()}), flush=True)
if sys.stdin.buffer.readline() != b"RUN\n":
    raise SystemExit(12)
start = monotonic_ns()
region = bytearray(memory_bytes)
for pos in range(0, len(region), 4096):
    region[pos] = (pos // 4096) & 255
state = 1469598103934665603
for index in range(iterations):
    state = ((state ^ index) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
print(json.dumps({"pid": os.getpid(), "fingerprint": "%016x" % state,
                  "allocated_bytes": len(region),
                  "worker_elapsed_ns": monotonic_ns() - start}), flush=True)
# Remain alive with the touched region resident until the parent samples
# this exact process HANDLE, then explicitly acknowledges completion.
if sys.stdin.buffer.readline() != b"ACK\n":
    raise SystemExit(13)
'''


def _positive_int(value, minimum, maximum, field):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid_" + field)
    return value


def _timeout(value):
    if (type(value) not in (int, float) or not math.isfinite(value) or
            not 0.1 <= value <= 60.0):
        raise ValueError("invalid_timeout")
    return float(value)


def _readline_with_deadline(pipe, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not select.select([pipe], [], [], remaining)[0]:
        raise TimeoutError("trusted_worker_startup_timeout")
    data = pipe.readline(4097)
    if not data or len(data) > 4096:
        raise ValueError("invalid_trusted_worker_handshake")
    return json.loads(data.decode("utf-8"))


def _wait_exact_child(process, deadline):
    """Reap exactly our child: no global RUSAGE_CHILDREN aggregation race."""
    while True:
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid == process.pid:
            process.returncode = os.waitstatus_to_exitcode(status)
            return usage
        if time.monotonic() >= deadline:
            raise TimeoutError("trusted_worker_execution_timeout")
        time.sleep(0.004)


def _windows_readline_with_deadline(pipe, deadline, readers):
    """Windows select() cannot wait for anonymous pipes; own one bounded read."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("trusted_worker_execution_timeout")
    result = queue.Queue(maxsize=1)

    def read_line():
        try:
            result.put_nowait((pipe.readline(4097), None))
        except (OSError, ValueError) as error:
            result.put_nowait((None, type(error).__name__))

    thread = threading.Thread(target=read_line, daemon=True,
                              name="owned-resource-pipe-reader")
    readers.append(thread)
    thread.start()
    try:
        data, error = result.get(timeout=max(0.0, deadline - time.monotonic()))
    except queue.Empty:
        raise TimeoutError("trusted_worker_execution_timeout") from None
    if error or not data or len(data) > 4096 or not data.endswith(b"\n"):
        raise ValueError("invalid_trusted_worker_handshake")
    return json.loads(data.decode("utf-8"))


def _windows_child_usage(process, expected_creation=None):
    """Query only the HANDLE owned by this Popen, while its worker is alive."""
    import ctypes
    from ctypes import wintypes

    class FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    class MemoryCounters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
            (name, ctypes.c_size_t) for name in (
                "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]

    def units(value):
        return (int(value.high) << 32) | int(value.low)

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetProcessId.argtypes = [wintypes.HANDLE]
    kernel.GetProcessId.restype = wintypes.DWORD
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(FileTime)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.K32GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(MemoryCounters), wintypes.DWORD]
    kernel.K32GetProcessMemoryInfo.restype = wintypes.BOOL
    handle = wintypes.HANDLE(int(process._handle))
    actual_pid = kernel.GetProcessId(handle)
    if actual_pid != process.pid:
        raise RuntimeError("trusted_worker_owned_handle_pid_mismatch")
    exit_code = wintypes.DWORD()
    if not kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
        raise ctypes.WinError(ctypes.get_last_error())
    if exit_code.value != 259:  # STILL_ACTIVE, required at both handshake samples.
        raise RuntimeError("trusted_worker_not_alive_at_measurement")
    creation, exit_time, kernel_time, user_time = (FileTime() for _ in range(4))
    if not kernel.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time),
                                  ctypes.byref(kernel_time), ctypes.byref(user_time)):
        raise ctypes.WinError(ctypes.get_last_error())
    created = units(creation)
    if created <= 0 or (expected_creation is not None and created != expected_creation):
        raise RuntimeError("trusted_worker_owned_handle_creation_mismatch")
    memory = MemoryCounters()
    memory.cb = ctypes.sizeof(memory)
    if not kernel.K32GetProcessMemoryInfo(handle, ctypes.byref(memory), memory.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    if memory.PeakWorkingSetSize <= 0:
        raise RuntimeError("trusted_worker_peak_resident_unavailable")
    return {"pid": actual_pid, "creation_time_100ns": created,
            "user_cpu_s": units(user_time) / 10_000_000.0,
            "system_cpu_s": units(kernel_time) / 10_000_000.0,
            "peak_rss_kib": memory.PeakWorkingSetSize / 1024.0}


def _cleanup_windows_child(process, readers):
    """Stop/reap exactly the bound child; bounded cleanup, never PID lookup."""
    deadline = time.monotonic() + 2.0
    if process.poll() is None:
        process.kill()  # CPython Windows Popen uses its bound process HANDLE.
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
    for reader in readers:
        reader.join(timeout=max(0.0, deadline - time.monotonic()))
    if any(reader.is_alive() for reader in readers):
        raise RuntimeError("trusted_worker_reader_cleanup_timeout")
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            stream.close()
    process._handle.Close()
    return {"owned_child_reaped": process.returncode is not None,
            "pipe_readers_joined": True, "streams_closed": True,
            "process_handle_closed": process._handle.closed}


def _measure_windows_worker(iterations, memory_bytes, timeout_s):
    deadline = time.monotonic() + timeout_s
    process = subprocess.Popen(
        [sys.executable, "-I", "-S", "-B", "-c", _TRUSTED_WINDOWS_WORKER,
         str(iterations), str(memory_bytes)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    readers = []
    report = None
    try:
        ready = _windows_readline_with_deadline(process.stdout, deadline, readers)
        if (type(ready) is not dict or set(ready) != {"ready", "pid"}
                or ready.get("ready") is not True or type(ready.get("pid")) is not int
                or ready["pid"] != process.pid):
            raise ValueError("trusted_worker_pid_handshake_failed")
        baseline = _windows_child_usage(process)
        start = time.monotonic_ns()
        process.stdin.write(b"RUN\n")
        process.stdin.flush()
        outcome = _windows_readline_with_deadline(process.stdout, deadline, readers)
        if (type(outcome) is not dict or set(outcome) != {
                "pid", "fingerprint", "allocated_bytes", "worker_elapsed_ns"}
                or type(outcome.get("pid")) is not int or outcome["pid"] != process.pid
                or type(outcome.get("fingerprint")) is not str
                or len(outcome["fingerprint"]) != 16
                or any(c not in "0123456789abcdef" for c in outcome["fingerprint"])
                or type(outcome.get("allocated_bytes")) is not int
                or outcome["allocated_bytes"] != memory_bytes
                or type(outcome.get("worker_elapsed_ns")) is not int
                or outcome["worker_elapsed_ns"] < 0):
            raise ValueError("trusted_worker_bad_output")
        final = _windows_child_usage(process, baseline["creation_time_100ns"])
        elapsed_s = (time.monotonic_ns() - start) / 1e9
        user_delta = final["user_cpu_s"] - baseline["user_cpu_s"]
        system_delta = final["system_cpu_s"] - baseline["system_cpu_s"]
        peak_delta = final["peak_rss_kib"] - baseline["peak_rss_kib"]
        if min(user_delta, system_delta, peak_delta) < 0:
            raise RuntimeError("trusted_worker_resource_counters_decreased")
        process.stdin.write(b"ACK\n")
        process.stdin.close()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("trusted_worker_execution_timeout")
        process.wait(timeout=remaining)
        error = process.stderr.read(4097)
        if process.returncode != 0 or error:
            raise RuntimeError("trusted_worker_exited_nonzero_or_stderr")
        report = {
            "status": "MEASURED_TRUSTED_SUBPROCESS_NOT_PIPELINE",
            "python_minor": "{}.{}".format(*sys.version_info[:2]),
            "pid": process.pid, "subprocess_exit_code": process.returncode,
            "iterations": iterations, "requested_memory_bytes": memory_bytes,
            "fingerprint": outcome["fingerprint"],
            "startup_baseline_cpu_user_s": baseline["user_cpu_s"],
            "startup_baseline_cpu_system_s": baseline["system_cpu_s"],
            "startup_baseline_peak_rss_kib": baseline["peak_rss_kib"],
            "child_cpu_user_s": final["user_cpu_s"],
            "child_cpu_system_s": final["system_cpu_s"],
            "child_cpu_total_s": final["user_cpu_s"] + final["system_cpu_s"],
            "workload_delta_cpu_user_s": user_delta,
            "workload_delta_cpu_system_s": system_delta,
            "workload_delta_cpu_total_s": user_delta + system_delta,
            "child_peak_rss_kib": final["peak_rss_kib"],
            "workload_peak_rss_growth_kib": peak_delta,
            "wall_elapsed_s": elapsed_s,
            "worker_elapsed_s": outcome["worker_elapsed_ns"] / 1e9,
            "voluntary_context_switches": None,
            "involuntary_context_switches": None,
            "context_switches_status": "NOT_RUN_WINDOWS_COUNTER_NOT_AVAILABLE",
            "source_executed": False, "all_pipeline_processes_measured": False,
            "measurement_origin": "windows_owned_handle_GetProcessTimes_K32GetProcessMemoryInfo",
            "maxrss_unit": "KiB_windows_PeakWorkingSetSize_bytes_div_1024",
            "bound_handle_pid_verified": True,
            "child_creation_time_100ns": baseline["creation_time_100ns"],
            "samples_taken_while_child_alive": True,
            "cpu_sample_scope": "startup and workload-completion before ACK, not post-exit total",
        }
        return report
    finally:
        cleanup = _cleanup_windows_child(process, readers)
        if report is not None:
            report["cleanup"] = cleanup


def measure_worker(iterations=300_000, memory_bytes=8_388_608, timeout_s=15.0):
    """Measure one trusted deterministic worker's CPU and peak resident RSS.

    Worker source is the literal above, never caller-provided code. The process
    CPU measurements are exact wait4() per-PID rusage on Linux, or Windows
    counters sampled from the owned live child HANDLE before completion ACK.
    RSS is a process high-water mark in KiB, not a whole-pipeline profile.
    """
    _positive_int(iterations, 1, 2_000_000, "iterations")
    _positive_int(memory_bytes, 0, 64 * 1024 * 1024, "memory_bytes")
    timeout_s = _timeout(timeout_s)
    if sys.platform == "win32":
        return _measure_windows_worker(iterations, memory_bytes, timeout_s)
    if not sys.platform.startswith("linux") or not callable(getattr(os, "wait4", None)):
        raise RuntimeError("linux_wait4_required_for_exact_child_memory")
    deadline = time.monotonic() + timeout_s
    process = subprocess.Popen(
        [sys.executable, "-I", "-S", "-B", "-c", _TRUSTED_WORKER,
         str(iterations), str(memory_bytes)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    try:
        ready = _readline_with_deadline(process.stdout, deadline)
        if ready.get("ready") is not True or ready.get("pid") != process.pid:
            raise ValueError("trusted_worker_pid_handshake_failed")
        baseline = ready["baseline"]
        start = time.monotonic_ns()
        process.stdin.write(b"RUN\n")
        process.stdin.close()
        usage = _wait_exact_child(process, deadline)
        elapsed_s = (time.monotonic_ns() - start) / 1e9
        final = process.stdout.read(4097)
        error = process.stderr.read(4097)
        if process.returncode != 0 or error:
            raise RuntimeError("trusted_worker_exited_nonzero_or_stderr")
        outcome = json.loads(final.decode("utf-8"))
        if (type(outcome.get("fingerprint")) is not str or
                outcome.get("allocated_bytes") != memory_bytes):
            raise ValueError("trusted_worker_bad_output")
        user_delta = max(0.0, usage.ru_utime - baseline["user_cpu_s"])
        system_delta = max(0.0, usage.ru_stime - baseline["system_cpu_s"])
        peak_delta = max(0, usage.ru_maxrss - baseline["peak_rss_kib"])
        return {
            "status": "MEASURED_TRUSTED_SUBPROCESS_NOT_PIPELINE",
            "python_minor": "{}.{}".format(sys.version_info.major, sys.version_info.minor),
            "pid": process.pid, "subprocess_exit_code": process.returncode,
            "iterations": iterations, "requested_memory_bytes": memory_bytes,
            "fingerprint": outcome["fingerprint"],
            "startup_baseline_cpu_user_s": baseline["user_cpu_s"],
            "startup_baseline_cpu_system_s": baseline["system_cpu_s"],
            "startup_baseline_peak_rss_kib": baseline["peak_rss_kib"],
            "child_cpu_user_s": usage.ru_utime,
            "child_cpu_system_s": usage.ru_stime,
            "child_cpu_total_s": usage.ru_utime + usage.ru_stime,
            "workload_delta_cpu_user_s": user_delta,
            "workload_delta_cpu_system_s": system_delta,
            "workload_delta_cpu_total_s": user_delta + system_delta,
            "child_peak_rss_kib": usage.ru_maxrss,
            "workload_peak_rss_growth_kib": peak_delta,
            "wall_elapsed_s": elapsed_s,
            "worker_elapsed_s": outcome["worker_elapsed_ns"] / 1e9,
            "voluntary_context_switches": usage.ru_nvcsw,
            "involuntary_context_switches": usage.ru_nivcsw,
            "source_executed": False,
            "all_pipeline_processes_measured": False,
            "measurement_origin": "os.wait4_exact_child_linux_rusage",
            "maxrss_unit": "KiB_linux_ru_maxrss",
        }
    finally:
        if process.poll() is None:
            process.kill()
            try:
                os.wait4(process.pid, 0)
            except ChildProcessError:
                pass
            process.returncode = -9
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def _percentile(values, percent):
    if not values:
        return 0.0
    ordered = sorted(values)
    position = max(0, math.ceil(len(ordered) * percent / 100) - 1)
    return ordered[position]


def measure_synthetic_queue(workers=2, jobs=20, hold_ms=10):
    """Trusted no-op scheduler pressure, explicitly not production queue data."""
    _positive_int(workers, 1, 16, "workers")
    _positive_int(jobs, 1, 256, "jobs")
    _positive_int(hold_ms, 0, 100, "hold_ms")
    tasks = queue.Queue(maxsize=jobs)
    waits = []
    locks = threading.Lock()
    completed = [0]
    peak_backlog = [0]
    gate = threading.Event()

    def runner():
        while True:
            item = tasks.get()
            try:
                if item is None:
                    return
                received_at, _job_id = item
                started_at = time.monotonic_ns()
                gate.wait(hold_ms / 1000)
                with locks:
                    waits.append((started_at - received_at) / 1e6)
                    completed[0] += 1
            finally:
                tasks.task_done()

    pool = [threading.Thread(target=runner, daemon=True) for _ in range(workers)]
    for thread in pool:
        thread.start()
    start = time.monotonic_ns()
    for job in range(jobs):
        tasks.put((time.monotonic_ns(), job))
        peak_backlog[0] = max(peak_backlog[0], tasks.qsize())
    tasks.join()
    wall_s = (time.monotonic_ns() - start) / 1e9
    for _ in pool:
        tasks.put(None)
    tasks.join()
    for thread in pool:
        thread.join(timeout=2)
    return {
        "status": "MEASURED_SYNTHETIC_SCHEDULER_NOT_PRODUCTION",
        "jobs_submitted": jobs, "jobs_completed": completed[0],
        "workers": workers, "hold_ms": hold_ms,
        "throughput_jobs_per_second": completed[0] / max(1e-9, wall_s),
        "queue_wait_p50_ms": _percentile(waits, 50),
        "queue_wait_p95_ms": _percentile(waits, 95),
        "queue_wait_max_ms": max(waits),
        "queue_depth_peak_observed": peak_backlog[0],
        "wall_elapsed_s": wall_s,
        "production_scheduler_instrumented": False,
        "source_executed": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    worker = sub.add_parser("worker")
    worker.add_argument("--iterations", type=int, default=300_000)
    worker.add_argument("--memory-bytes", type=int, default=8_388_608)
    worker.add_argument("--timeout-s", type=float, default=15.0)
    synthetic = sub.add_parser("synthetic-queue")
    synthetic.add_argument("--workers", type=int, default=2)
    synthetic.add_argument("--jobs", type=int, default=20)
    synthetic.add_argument("--hold-ms", type=int, default=10)
    args = parser.parse_args()
    if args.action == "worker":
        report = measure_worker(args.iterations, args.memory_bytes, args.timeout_s)
    else:
        report = measure_synthetic_queue(args.workers, args.jobs, args.hold_ms)
    print(json.dumps(report, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
