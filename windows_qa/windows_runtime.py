"""Trusted, bounded Windows x64 CPython qualification probe (3.9--3.15).

The probe never imports a supplied project, evaluates user code, touches
production files, claims GPU availability or treats subprocesses as sandboxed.
On non-Windows hosts it returns NOT_RUN, *not* a synthetic Windows PASS.
"""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time


SUPPORTED = tuple("3.{}".format(n) for n in range(9, 16))
FIXED_CHILD = (
    "import json,os,sys;"
    "print(json.dumps({'pid':os.getpid(),"
    "'version':list(sys.version_info[:2]),"
    "'implementation':sys.implementation.name}))"
)


def inspect_runtime(expected_minor):
    """Execute only the trusted interpreter identity fixture with a timeout."""
    if type(expected_minor) is not str or expected_minor not in SUPPORTED:
        raise ValueError("invalid_expected_minor")
    edition = "UNAVAILABLE"
    build_number = None
    if sys.platform == "win32" and os.name == "nt":
        try:
            edition = platform.win32_edition()
            build_number = sys.getwindowsversion().build
        except (AttributeError, OSError):
            # No edition evidence is safer than inferring Windows Home from
            # a Windows Server GitHub runner.
            pass
    exact_home = (edition in ("Core", "CoreSingleLanguage") and
                  type(build_number) is int and build_number >= 22000)
    base = {
        "schema_version": 1,
        "requested_minor": expected_minor,
        "host_os": platform.system(),
        "host_architecture": platform.machine(),
        "windows_edition": edition,
        "windows_build": build_number,
        "exact_windows_11_home_host_verified": exact_home,
        "unknown_project_code_executed": False,
        "sandbox_isolation_proven": False,
        "nvidia_gpu_runtime": "NOT_RUN_DEDICATED_GPU_RUNNER_REQUIRED",
        "production_update_qualified": False,
        "windows_executable_compatibility": "NOT_RUN",
    }
    if sys.platform != "win32" or os.name != "nt":
        return dict(base, status="NOT_RUN", reason="REAL_WINDOWS_HOST_REQUIRED")
    if platform.machine().lower() not in ("amd64", "x86_64"):
        return dict(base, status="NOT_RUN", reason="ACTUAL_WINDOWS_X64_REQUIRED")
    actual_minor = "{}.{}".format(*sys.version_info[:2])
    if sys.implementation.name != "cpython" or actual_minor != expected_minor:
        return dict(base, status="FAIL", reason="ACTUAL_CPYTHON_VERSION_MISMATCH")
    started = time.perf_counter()
    try:
        result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", FIXED_CHILD],
                                timeout=8, check=False, capture_output=True)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return dict(base, status="NOT_RUN", reason=type(exc).__name__)
    duration_ms = round((time.perf_counter() - started) * 1000, 3)
    if (result.returncode != 0 or len(result.stdout) > 1024 or
            len(result.stderr) > 1024):
        return dict(base, status="FAIL", reason="FIXED_CHILD_PROCESS_FAILED",
                    duration_ms=duration_ms)
    try:
        identity = json.loads(result.stdout)
    except (UnicodeError, ValueError):
        return dict(base, status="FAIL", reason="FIXED_CHILD_JSON_INVALID",
                    duration_ms=duration_ms)
    if (type(identity) is not dict or identity.get("version") != list(sys.version_info[:2]) or
            identity.get("implementation") != "cpython" or
            type(identity.get("pid")) is not int or identity["pid"] == os.getpid()):
        return dict(base, status="FAIL", reason="CHILD_IDENTITY_MISMATCH",
                    duration_ms=duration_ms)
    return dict(base, status="SCOPED_WINDOWS_PROCESS_PASS",
                reason="TRUSTED_IDENTITY_ONLY_NOT_SANDBOX_OR_FULL_COMPATIBILITY",
                process_identity="distinct_pid_verified",
                child_stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
                duration_ms=duration_ms)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-minor", choices=SUPPORTED, required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = inspect_runtime(args.expected_minor)
    with open(args.output, "x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "reason": report.get("reason")}))
    return 0 if report["status"] == "SCOPED_WINDOWS_PROCESS_PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
