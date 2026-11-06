"""Isolated candidate registry + six-gate benchmark for F167 process policy.

The candidates use distinct policies and only trusted, literal child workers.
Nothing qualifies macOS, Windows, arbitrary Python code or future CPython.
NO EVIDENCE = NO PASS; no experimental variant is called a winner.
"""

import argparse
import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path

try:
    import resource
except ImportError:  # pragma: no cover - Windows runners lack resource module
    resource = None
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "candidate_registry_v27.json"
REQUIRED_GATES = ("VEILIGHEID", "CORRECTHEID", "SNELHEID", "BETROUWBAARHEID",
                  "COMPATIBILITEIT", "TOEKOMSTBESTENDIGHEID")
ALLOWED_STATUSES = ("PASS", "FAIL", "NOT_RUN")


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1_048_576), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_registry(registry):
    if registry.get("schema_version") != 1:
        raise ValueError("unsupported_registry_schema")
    thresholds = registry.get("thresholds")
    if not isinstance(thresholds, dict):
        raise TypeError("missing_thresholds")
    if (type(thresholds.get("repeat_count_minimum")) is not int or
            thresholds["repeat_count_minimum"] < 3 or
            type(thresholds.get("each_probe_wall_time_max_ms")) is not int or
            thresholds["each_probe_wall_time_max_ms"] <= 0):
        raise ValueError("unsafe_thresholds")
    if sorted(thresholds.get("required_os", [])) != ["Darwin", "Linux", "Windows"]:
        raise ValueError("required_os_changed")
    if thresholds.get("future_stable_python_minor_required") != "3.16":
        raise ValueError("future_version_gate_removed")
    entries = registry.get("candidates")
    if not isinstance(entries, list) or len(entries) < 2:
        raise ValueError("independent_candidates_required")
    seen_ids, seen_configurations = set(), set()
    for entry in entries:
        identifier = entry.get("variant_id")
        source = entry.get("source")
        if not isinstance(identifier, str) or not identifier.startswith("F167-"):
            raise ValueError("candidate_id_invalid")
        if identifier in seen_ids:
            raise ValueError("duplicate_candidate_id")
        seen_ids.add(identifier)
        if source != "python/concurrency_probe.py":
            raise ValueError("untrusted_executable_source")
        if entry.get("source_sha256") != sha256(ROOT / source):
            raise ValueError("unreviewed_source_change")
        configuration = entry.get("configuration")
        if (not isinstance(configuration, dict) or
                configuration.get("requested") != "default" or
                configuration.get("fallback_intent") not in
                (None, "ALLOW_TRUSTED_SPAWN_FALLBACK")):
            raise ValueError("unreviewed_configuration")
        fingerprint = (entry["source_sha256"], json.dumps(configuration, sort_keys=True))
        if fingerprint in seen_configurations:
            raise ValueError("duplicate_candidate_combination")
        seen_configurations.add(fingerprint)
    return thresholds


def probe_one(executable, candidate, timeout_seconds=8):
    command = [str(executable), "-I", "-S", str(ROOT / "python" / "concurrency_probe.py"),
               "--qualify-default"]
    if candidate["configuration"]["fallback_intent"] is not None:
        command.append("--allow-spawn-fallback")
    before_usage = resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None
    start = time.monotonic_ns()
    try:
        proc = subprocess.run(command, cwd=str(ROOT), capture_output=True,
                              timeout=timeout_seconds, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"status": "NOT_RUN", "reason": type(error).__name__,
                "elapsed_ms": round((time.monotonic_ns() - start) / 1_000_000, 3),
                "source_executed": "fixed_trusted_worker_only"}
    elapsed = round((time.monotonic_ns() - start) / 1_000_000, 3)
    after_usage = resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None
    result = {"elapsed_ms": elapsed, "process_returncode": proc.returncode,
              "stdout_sha256": hashlib.sha256(proc.stdout).hexdigest(),
              "stderr_sha256": hashlib.sha256(proc.stderr).hexdigest(),
              "source_executed": "fixed_trusted_worker_only"}
    if before_usage and after_usage:
        result["child_cpu_user_ms"] = round(1000 * (
            after_usage.ru_utime - before_usage.ru_utime), 3)
        result["child_cpu_system_ms"] = round(1000 * (
            after_usage.ru_stime - before_usage.ru_stime), 3)
        result["child_peak_rss_observed_kib"] = after_usage.ru_maxrss
        result["rss_interpretation"] = "cumulative_peak_of_children_not_isolated_sample"
    else:
        result["resources_status"] = "NOT_RUN_resource_meter_unavailable"
    if proc.returncode or len(proc.stdout) > 8192 or len(proc.stderr) > 8192:
        return dict(result, status="FAIL", reason="child_process_or_output_invalid")
    try:
        payload = json.loads(proc.stdout)
    except (UnicodeError, ValueError):
        return dict(result, status="FAIL", reason="child_json_invalid")
    if (not isinstance(payload, dict) or payload.get("untrusted_source_executed") is not False or
            payload.get("implicit_security_sandbox") is not False or
            payload.get("explicit_fallback_consent") !=
            (candidate["configuration"]["fallback_intent"] is not None)):
        return dict(result, status="FAIL", reason="trust_or_consent_contract_broken")
    primary = payload.get("primary", {})
    effective = payload.get("effective_method")
    if payload.get("status") == "PRIMARY_PASS":
        valid = primary.get("status") == "PASS" and effective == payload.get("requested_method")
    elif payload.get("status") == "EXPLICIT_SPAWN_FALLBACK_PASS":
        valid = (candidate["configuration"]["fallback_intent"] is not None and
                 primary.get("status") != "PASS" and effective == "spawn" and
                 payload.get("fallback", {}).get("status") == "PASS")
    elif payload.get("status") == "NOT_RUN":
        return dict(result, status="NOT_RUN", reason="primary_or_fallback_unavailable",
                    requested=payload.get("requested_method"),
                    primary_status=primary.get("status"), effective_method=None)
    else:
        valid = False
    if not valid:
        return dict(result, status="FAIL", reason="unproven_effective_method")
    return dict(result, status="PASS", requested=payload["requested_method"],
                primary_status=primary["status"], effective_method=effective,
                used_explicit_fallback=payload["status"] == "EXPLICIT_SPAWN_FALLBACK_PASS")


def gates_for_runs(runs, thresholds, observed_os):
    statuses = [sample["status"] for row in runs for sample in row["samples"]]
    measured = [sample["elapsed_ms"] for row in runs for sample in row["samples"]]
    all_pass = bool(statuses) and all(state == "PASS" for state in statuses)
    any_fail = any(state == "FAIL" for state in statuses)
    max_latency = thresholds["each_probe_wall_time_max_ms"]
    max_allowed = all(ms <= max_latency for ms in measured)
    gates = {
        "VEILIGHEID": {"status": "NOT_RUN", "reason": "independent_threat_audit_and_OS_sandbox_not_verified"},
        "CORRECTHEID": {"status": "PASS" if all_pass else "FAIL" if any_fail else "NOT_RUN",
                        "scope": "only_trusted_fixed_worker_fixture"},
        "SNELHEID": {"status": "PASS" if measured and max_allowed else "FAIL" if measured else "NOT_RUN",
                     "threshold_each_probe_wall_time_max_ms": max_latency,
                     "observed_max_ms": max(measured) if measured else None},
        "BETROUWBAARHEID": {"status": "PASS" if all_pass else "FAIL" if any_fail else "NOT_RUN",
                             "minimum_repeats_each_minor": thresholds["repeat_count_minimum"]},
        "COMPATIBILITEIT": {"status": "NOT_RUN", "reason": "missing_actual_Windows_and_macOS_runners",
                             "observed_os": observed_os},
        "TOEKOMSTBESTENDIGHEID": {"status": "NOT_RUN", "reason": "future_stable_3_16_not_qualified"}
    }
    assert set(gates) == set(REQUIRED_GATES)
    assert all(row["status"] in ALLOWED_STATUSES for row in gates.values())
    return gates


def collect(registry, bin_dir):
    thresholds = validate_registry(registry)
    versions = thresholds["required_python_minor"]
    candidates = []
    for candidate in registry["candidates"]:
        runs = []
        for minor in versions:
            executable = bin_dir / ("python" + minor)
            if not executable.is_file():
                runs.append({"python_minor": minor, "samples": [
                    {"status": "NOT_RUN", "reason": "interpreter_missing"}]})
                continue
            samples = [probe_one(executable, candidate) for _ in range(
                thresholds["repeat_count_minimum"])]
            runs.append({"python_minor": minor, "interpreter_sha256": sha256(executable),
                         "samples": samples})
        gates = gates_for_runs(runs, thresholds, platform.system())
        elapsed = sorted(sample["elapsed_ms"] for row in runs for sample in row["samples"]
                         if "elapsed_ms" in sample)
        total = len(elapsed)
        candidates.append({"variant_id": candidate["variant_id"],
                           "source_sha256": candidate["source_sha256"],
                           "configuration": candidate["configuration"],
                           "runs": runs, "gates": gates,
                           "performance": {
                               "samples": total,
                               "throughput_probes_per_second":
                               round(1000 * total / sum(elapsed), 3) if elapsed and sum(elapsed) else None,
                               "p50_ms": elapsed[(total - 1) // 2] if total else None,
                               "p95_ms": elapsed[(total * 95 - 1) // 100] if total else None,
                               "max_ms": elapsed[-1] if total else None},
                           "full_qualification": all(row["status"] == "PASS" for row in gates.values())})
    qualified = [row for row in candidates if row["full_qualification"]]
    qualified.sort(key=lambda x: (x["performance"]["p95_ms"], x["variant_id"]))
    return {"schema_version": 1, "collected_at_utc": datetime.now(timezone.utc).isoformat(),
            "registry_sha256": sha256(CONFIG), "platform": platform.platform(),
            "thresholds": thresholds, "candidates": candidates,
            "winner": qualified[0]["variant_id"] if qualified else None,
            "verified_reserve": qualified[1]["variant_id"] if len(qualified) > 1 else None,
            "no_evidence_no_pass": True,
            "cost_measurement": {"status": "NOT_RUN", "reason": "no_comparable_external_agent_or_model_billing_available"},
            "resource_measurement": {"status": "RECORDED_CHILD_CPU_AND_AGGREGATE_RSS" if resource else "NOT_RUN",
                                     "rss_individual_process_isolation_qualified": False},
            "independent_external_audit_performed": False,
            "complete_F167_all_OS_qualification": False,
            "unsafe_arbitrary_code_executed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-bin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = collect(json.loads(CONFIG.read_text(encoding="utf-8")), args.python_bin)
        with args.output.open("x", encoding="utf-8") as destination:
            json.dump(report, destination, sort_keys=True, indent=2)
            destination.write("\n")
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({"status": "NOT_RUN", "reason": type(error).__name__}))
        return 2
    print(json.dumps({"winner": report["winner"], "verified_reserve": report["verified_reserve"],
                      "variant_gates": {item["variant_id"]: {key: value["status"]
                                         for key, value in item["gates"].items()}
                                        for item in report["candidates"]}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
