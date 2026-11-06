"""F167 Windows-only trusted spawn qualification; no arbitrary project targets.

Native unsupported methods are negative oracles, never fork/forkserver PASS.
This fixture cannot certify an independent security audit or stable CPython3.16.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import time

SOURCE = Path(__file__).resolve().with_name("concurrency_probe.py")
sys.path.insert(0, str(SOURCE.parent))
import concurrency_probe as core  # noqa: E402 -- exact bundled source directory

MINORS = ("3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15")
REVIEWED_PREVIEW_MINOR = "3.16"
# Exact executable from python.org's primary-pinned 3.16.0a1 Windows archive.
# The parent acquisition runner also holds and validates every archive member.
REVIEWED_PREVIEW_SHA256 = "dcfb24adf231ad861c774daec76c56d8dd6d9bf8d5d59f9818bdc7a50bb2cf79"
REPEATS = 3
MAX_PROBE_MS = 5000


def cleanup_pass(row):
    return (row.get("cleanup_verified") is True
            and row.get("cleanup", {}).get("alive_after_cleanup") is False)


def qualify(expected_minor, *, allow_reviewed_preview=False):
    if type(allow_reviewed_preview) is not bool:
        raise ValueError("preview_consent_must_be_boolean")
    is_preview = expected_minor == REVIEWED_PREVIEW_MINOR
    if expected_minor not in MINORS and not is_preview:
        raise ValueError("unsupported_requested_minor")
    if is_preview != allow_reviewed_preview:
        raise ValueError("reviewed_preview_requires_separate_opt_in")
    actual = "{}.{}".format(*sys.version_info[:2])
    base = {"feature_id": "F167", "python_minor": actual,
            "python_version": platform.python_version(),
            "implementation": sys.implementation.name,
            "interpreter": sys.executable,
            "interpreter_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
            "runtime_releaselevel": sys.version_info.releaselevel,
            "runtime_serial": sys.version_info.serial,
            "preview_opt_in": allow_reviewed_preview,
            "os": platform.system(), "architecture": platform.machine(),
            "windows_edition": platform.win32_edition() if sys.platform == "win32" else None,
            "windows_build": sys.getwindowsversion().build if sys.platform == "win32" else None,
            "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "thresholds": {"repeat_count_minimum": REPEATS,
                           "each_probe_wall_time_max_ms": MAX_PROBE_MS,
                           "timeout_fixture_wait_seconds": 1.0},
            "unknown_project_executed": False, "security_sandbox_claimed": False,
            "independent_security_qualification": "NOT_RUN",
            "future_stable_3_16_qualification": "NOT_RUN",
            "complete_F167_qualification": False}
    if (sys.platform != "win32" or os.name != "nt"
            or platform.machine().lower() not in ("amd64", "x86_64")):
        return dict(base, status="NOT_RUN", reason="REAL_WINDOWS_X64_REQUIRED")
    if actual != expected_minor or sys.implementation.name != "cpython":
        return dict(base, status="FAIL", reason="ACTUAL_INTERPRETER_MISMATCH")
    if is_preview and (tuple(sys.version_info[:3]) != (3, 16, 0)
                       or sys.version_info.releaselevel != "alpha"
                       or sys.version_info.serial != 1
                       or base["interpreter_sha256"] != REVIEWED_PREVIEW_SHA256):
        return dict(base, status="FAIL", reason="REVIEWED_PREVIEW_IDENTITY_MISMATCH")
    methods = core.multiprocessing.get_all_start_methods()
    default = core.multiprocessing.get_start_method()
    gates = [{"requirement": "native_windows_spawn_default",
              "status": "PASS" if methods == ["spawn"] and default == "spawn" else "FAIL",
              "available_start_methods": methods, "actual_default": default}]
    gates.append({"requirement": "selected_windows_11_home_host",
                  "status": "PASS" if base["windows_edition"] in ("Core", "CoreSingleLanguage")
                  and base["windows_build"] >= 22000 else "FAIL"})
    negatives = []
    for method in ("fork", "forkserver"):
        row = core.inspect_method(method)
        valid = (row["status"] == "UNSUPPORTED_ON_PLATFORM"
                 and row.get("child_started") is False
                 and row.get("child_executed_fixed_fixture") is False)
        negatives.append({"method": method, "observed": row,
                          "negative_oracle_status": "PASS" if valid else "FAIL"})
    gates.append({"requirement": "unsupported_methods_never_execute",
                  "status": "PASS" if all(r["negative_oracle_status"] == "PASS"
                                          for r in negatives) else "FAIL"})
    scenarios = []
    for fixture in ("timeout", "invalid_identity", "worker_error"):
        row = core.inspect_method("spawn", fixture=fixture, timeout_seconds=1.0)
        if fixture == "timeout":
            valid = (row["status"] == "NOT_RUN"
                     and row.get("reason") == "worker_result_timeout"
                     and row.get("ready_identity_verified") is True
                     and row.get("cleanup", {}).get("terminate_used") is True)
        elif fixture == "invalid_identity":
            valid = (row["status"] == "FAIL"
                     and row.get("reason") == "worker_exit_or_identity_invalid")
        else:
            valid = (row["status"] == "FAIL" and row.get("reason") == "worker_pipe_eof"
                     and row.get("cleanup", {}).get("child_exitcode") not in (None, 0))
        valid = valid and cleanup_pass(row)
        scenarios.append({"fixture": fixture, "observed": row,
                          "negative_oracle_status": "PASS" if valid else "FAIL"})
    gates.append({"requirement": "timeout_identity_error_and_owned_cleanup",
                  "status": "PASS" if all(r["negative_oracle_status"] == "PASS"
                                          for r in scenarios) else "FAIL"})
    # These policies exercise distinct paths on Windows: default spawn vs
    # unavailable forkserver followed by separately authorized native spawn.
    configurations = [
        {"variant_id": "F167-WIN-SPAWN-STRICT-03", "requested": None,
         "fallback_intent": None},
        {"variant_id": "F167-WIN-UNSUPPORTED-FALLBACK-04", "requested": "forkserver",
         "fallback_intent": core.EXPLICIT_SPAWN_FALLBACK_INTENT},
    ]
    variants = []
    combinations = set()
    for config in configurations:
        fingerprint = hashlib.sha256(json.dumps(
            {"source": base["source_sha256"], "configuration": {
                "requested": config["requested"], "fallback_intent": config["fallback_intent"]}},
            sort_keys=True).encode()).hexdigest()
        if fingerprint in combinations:
            raise ValueError("duplicate_process_configuration")
        combinations.add(fingerprint)
        samples = []
        for number in range(REPEATS):
            started = time.perf_counter()
            row = core.qualify_start_method(config["requested"], config["fallback_intent"])
            elapsed = (time.perf_counter() - started) * 1000
            if config["fallback_intent"] is None:
                effective = row["primary"]
                valid = (row["status"] == "PRIMARY_PASS" and row["requested_method"] == "spawn"
                         and row["fallback"] is None)
            else:
                effective = row["fallback"] or {}
                valid = (row["status"] == "EXPLICIT_SPAWN_FALLBACK_PASS"
                         and row["primary"]["status"] == "UNSUPPORTED_ON_PLATFORM"
                         and row["primary"].get("child_started") is False
                         and row["explicit_fallback_consent"] is True)
            valid = (valid and row["effective_method"] == "spawn"
                     and effective.get("status") == "PASS"
                     and effective.get("parent_identity_verified") is True
                     and effective.get("child_pid_different") is True and cleanup_pass(effective)
                     and row["untrusted_source_executed"] is False
                     and row["implicit_security_sandbox"] is False)
            samples.append({"run": number + 1, "run_kind": "INITIAL" if number == 0 else "RETEST",
                            "status": "PASS" if valid else "FAIL", "elapsed_ms": elapsed,
                            "speed_status": "PASS" if elapsed <= MAX_PROBE_MS else "FAIL",
                            "observed": row})
        variants.append({"configuration": config, "combination_sha256": fingerprint,
                         "samples": samples,
                         "scoped_status": "PASS" if all(s["status"] == "PASS"
                                                        and s["speed_status"] == "PASS"
                                                        for s in samples) else "FAIL",
                         "eligible_for_product_ranking": False})
    gates.append({"requirement": "three_repeats_correctness_reliability_speed_each_policy",
                  "status": "PASS" if all(v["scoped_status"] == "PASS" for v in variants)
                  else "FAIL"})
    return dict(base, status="PASS" if all(g["status"] == "PASS" for g in gates) else "FAIL",
                scope="Windows x64 fixed spawn IPC, negative method/timeout/identity/exit and cleanup fixtures",
                gates=gates, unsupported_method_oracles=negatives,
                negative_scenarios=scenarios, variants=variants,
                winner=None, verified_reserve=None,
                warning="Scoped fixture PASS does not satisfy independent security or future3.16 gates")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-minor", choices=MINORS + (REVIEWED_PREVIEW_MINOR,), required=True)
    parser.add_argument("--allow-reviewed-preview", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (args.expected_minor == REVIEWED_PREVIEW_MINOR) != args.allow_reviewed_preview:
        parser.error("reviewed preview requires explicit --allow-reviewed-preview only for 3.16")
    report = qualify(args.expected_minor, allow_reviewed_preview=args.allow_reviewed_preview)
    report["timestamp_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"feature_id": "F167", "status": report["status"],
                      "python_minor": report["python_minor"], "output": str(args.output),
                      "complete_F167_qualification": False}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
