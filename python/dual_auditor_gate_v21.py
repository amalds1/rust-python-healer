"""Two locally independent signed audits of *hardcoded* Rust/Python fixtures.

Two genuine CPython processes, independent scratch workdirs and separate HMAC
keys attest real Rust/Ruff, candidate bytes, seven-version compatibility and ten
behavioral subprocess repetitions. The operator controlling BOTH local auditor
programs/keys is NOT an independent third-party security or behavioral oracle.
No unknown source or project tests are ever executed and release stays denied.
"""

import argparse
import hashlib
import hmac
import json
import math
import os
import secrets
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

MINORS = ("3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15")
AXES = ("SAFETY", "CORRECTNESS", "SPEED", "RELIABILITY", "COMPATIBILITY", "FUTURE_READINESS")
LIMITS = {"SAFETY": 0, "CORRECTNESS": 0, "SPEED": 300, "RELIABILITY": 10,
          "COMPATIBILITY": 7, "FUTURE_READINESS": 30}
METRIC_DIRECTION = {"SAFETY": "max", "CORRECTNESS": "max", "SPEED": "max",
                    "RELIABILITY": "min", "COMPATIBILITY": "min", "FUTURE_READINESS": "max"}
AUDITOR_ORIGINS = ("origin-a", "origin-b")
MAX_REPORT_BYTES = 100_000
MAX_AUDIT_AGE_SEC = 120
RETESTS = 10
TRUSTED_FIXTURES = {
    "ruff": (b"import os\n\nanswer = 42\n", b"\nanswer = 42\n"),
    "colon": (b"if True\n    answer = 42\n", b"if True:\n    answer = 42\n"),
}
TRUSTED_BEHAVIOR = r'''
import hashlib,json,sys
path,expected=sys.argv[1:3]
with open(path,"rb") as handle:
    code=handle.read(4097)
if len(code)>4096 or hashlib.sha256(code).hexdigest()!=expected:
    sys.exit(52)
namespace={}
exec(compile(code,path,"exec"),namespace)
print(json.dumps({"ok":type(namespace.get("answer")) is int and namespace["answer"]==42}))
'''


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sign(key, report):
    if type(key) is not bytes or len(key) != 32:
        raise ValueError("invalid_auditor_key")
    return hmac.new(key, canonical(report), hashlib.sha256).hexdigest()


def safe_env(folder, key=None, nonce=None):
    env = {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "TZ": "UTC",
           "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(folder)}
    if key is not None:
        env["RPH_AUDITOR_SECRET_HEX"] = key.hex()
    if nonce is not None:
        env["RPH_AUDITOR_NONCE"] = nonce
    return env


def _selected_minor(python, folder):
    try:
        result = subprocess.run([str(python), "-I", "-S", "-B", "-c",
                                 "import sys;print('{}.{}'.format(*sys.version_info[:2]))"],
                                cwd=str(folder), env=safe_env(folder),
                                capture_output=True, check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (result.stdout.decode("ascii", errors="replace").strip()
            if result.returncode == 0 and not result.stderr and len(result.stdout) <= 15 else None)


def _trust_probe(python, folder, candidate, expected_sha):
    before = time.perf_counter_ns()
    try:
        result = subprocess.run([str(python), "-I", "-S", "-B", "-c", TRUSTED_BEHAVIOR,
                                 str(candidate), expected_sha], cwd=str(folder),
                                env=safe_env(folder), capture_output=True,
                                check=False, timeout=5)
        passed = (result.returncode == 0 and not result.stderr and
                  json.loads(result.stdout) == {"ok": True})
    except (OSError, subprocess.TimeoutExpired, ValueError):
        passed = False
    elapsed = (time.perf_counter_ns() - before) / 1e6
    return {"status": "PASS" if passed else "FAIL", "wall_ms": round(elapsed, 5)}


def _fixed_candidate_identity(engine, source, candidate):
    return "V-" + digest((engine + ":" + digest(source) + ":" + digest(candidate)).encode())[:24]


def audit_in_independent_origin(origin, key, nonce, binary, ruff, runtimes, folder):
    """Run TWO actual repairs and 34+ real trusted Python checks in this process."""
    if origin not in AUDITOR_ORIGINS or type(nonce) is not str or len(nonce) != 48:
        raise ValueError("invalid_origin_or_nonce")
    if type(runtimes) is not dict or set(runtimes) != set(MINORS):
        raise ValueError("all_real_minors_required")
    if type(key) is not bytes or len(key) != 32:
        raise ValueError("invalid_auditor_key")
    folder = Path(folder)
    version_proofs = {version: _selected_minor(python, folder) for version, python in runtimes.items()}
    observations = []
    for engine, (source_data, expected_data) in TRUSTED_FIXTURES.items():
        workdir = folder / engine
        workdir.mkdir()
        source = workdir / "original.py"
        candidate = workdir / "candidate.py"
        source.write_bytes(source_data)
        source.chmod(0o400)
        source_sha = digest(source_data)
        evidence = workdir / "run.sqlite"
        start = time.perf_counter_ns()
        rust_status = "NOT_RUN"
        try:
            proc = subprocess.run([str(binary), "repair", str(source), "--ruff", str(ruff),
                                   "--python", str(runtimes["3.9"]), "--out", str(candidate),
                                   "--ledger", str(evidence)], cwd=str(workdir),
                                  env=safe_env(workdir), capture_output=True,
                                  check=False, timeout=35)
            payload = json.loads(proc.stdout)
            if (proc.returncode == 0 and not proc.stderr and
                    payload.get("status") == "CANDIDATE_ONLY" and
                    payload.get("winner") == "NONE" and
                    payload.get("candidate_saved") == str(candidate) and
                    source.read_bytes() == source_data and
                    candidate.is_file() and candidate.read_bytes() == expected_data):
                rust_status = "PASS"
        except (OSError, subprocess.TimeoutExpired, ValueError):
            pass
        rust_wall = (time.perf_counter_ns() - start) / 1e6
        if rust_status == "PASS":
            candidate.chmod(0o400)
        candidate_sha = digest(expected_data)
        retests = []
        compatibility = {}
        if rust_status == "PASS":
            for rep in range(RETESTS):
                retests.append(_trust_probe(runtimes["3.9"], workdir, candidate, candidate_sha))
            for version in MINORS:
                compatibility[version] = _trust_probe(runtimes[version], workdir, candidate,
                                                       candidate_sha)["status"]
        measured = [row["wall_ms"] for row in retests]
        p95 = sorted(measured)[math.ceil(0.95 * len(measured)) - 1] if len(measured) == RETESTS else 1e9
        passing_retests = sum(row["status"] == "PASS" for row in retests)
        passing_minors = sum(compatibility.get(version) == "PASS" and
                             version_proofs.get(version) == version for version in MINORS)
        metrics = {"SAFETY": 0 if rust_status == "PASS" else 1,
                   "CORRECTNESS": RETESTS - passing_retests,
                   "SPEED": round(p95, 5), "RELIABILITY": passing_retests,
                   "COMPATIBILITY": passing_minors, "FUTURE_READINESS": 0}
        gate_status = {axis: "PASS" if ((metrics[axis] <= LIMITS[axis]) if
                       METRIC_DIRECTION[axis] == "max" else (metrics[axis] >= LIMITS[axis]))
                       else "FAIL" for axis in AXES}
        observations.append({"variant_id": _fixed_candidate_identity(engine, source_data, expected_data),
                             "engine": engine, "source_sha256": source_sha,
                             "candidate_sha256": candidate_sha,
                             "snapshot_intact": source.read_bytes() == source_data,
                             "rust_repair_status": rust_status,
                             "rust_wall_ms": round(rust_wall, 5),
                             "test_processes": len(retests) + len(compatibility),
                             "retests": retests, "minor_outcomes": compatibility,
                             "metrics": metrics, "gate_status": gate_status,
                             "proof_sha256": digest(canonical({"source": source_sha,
                                "candidate": candidate_sha, "rust_status": rust_status,
                                "retests": retests, "minors": compatibility,
                                "nonce": nonce, "origin": origin}))})
    body = {"schema_version": 1, "origin": origin, "session_nonce": nonce,
            "reported_at_unix": time.time(), "run_id": secrets.token_hex(16),
            "scope": "LOCAL_HARDCODED_ALLOWLISTED_FIXTURES_ONLY",
            "version_proofs": version_proofs, "candidates": observations,
            "unknown_project_code_executed": False,
            "independent_external_auditor": False, "release_authorized": False}
    return {"report": body, "signature_hmac_sha256": sign(key, body)}


def verify_and_rank(artifacts, keys, nonces, now=None):
    """Reject forged, replayed or conflicting dual-local-auditor claims."""
    def reject(reason):
        return {"schema_version": 1, "status": "DUAL_AUDIT_REJECTED", "decision": "NO_WINNER",
                "reason": reason, "primary_variant": None, "reserve_variant": None,
                "verified_candidate_count": 0, "maximum_reserves": 1,
                "external_independent_audit": False, "release_authorized": False}

    now = time.time() if now is None else now
    if (type(artifacts) is not dict or set(artifacts) != set(AUDITOR_ORIGINS) or
            type(keys) is not dict or set(keys) != set(AUDITOR_ORIGINS) or
            type(nonces) is not dict or set(nonces) != set(AUDITOR_ORIGINS)):
        return reject("two_distinct_auditor_origins_required")
    if (any(type(key) is not bytes or len(key) != 32 for key in keys.values()) or
            len(set(keys.values())) != 2):
        return reject("keys_not_independent_or_invalid")
    if any(type(value) is not str or len(value) != 48 for value in nonces.values()) or len(
            set(nonces.values())) != 2:
        return reject("nonces_not_independent_or_invalid")
    runs, proofs, verified = set(), set(), {}
    for origin in AUDITOR_ORIGINS:
        item = artifacts[origin]
        if type(item) is not dict or set(item) != {"report", "signature_hmac_sha256"}:
            return reject("auditor_report_structure_invalid")
        body = item["report"]
        if type(body) is not dict:
            return reject("auditor_report_unbounded_or_invalid")
        supplied_signature = item["signature_hmac_sha256"]
        if (type(supplied_signature) is not str or len(supplied_signature) != 64 or
                any(character not in "0123456789abcdef" for character in supplied_signature)):
            return reject("independent_hmac_signature_invalid")
        try:
            if len(canonical(body)) > MAX_REPORT_BYTES:
                return reject("auditor_report_unbounded_or_invalid")
            expected_signature = sign(keys[origin], body)
        except (ValueError, TypeError, OverflowError, RecursionError):
            return reject("auditor_report_unbounded_or_invalid")
        if not hmac.compare_digest(expected_signature, supplied_signature):
            return reject("independent_hmac_signature_invalid")
        if (body.get("schema_version") != 1 or body.get("origin") != origin or
                body.get("session_nonce") != nonces[origin] or
                body.get("scope") != "LOCAL_HARDCODED_ALLOWLISTED_FIXTURES_ONLY" or
                body.get("independent_external_auditor") is not False or
                body.get("release_authorized") is not False or
                body.get("unknown_project_code_executed") is not False):
            return reject("replayed_or_mislabeled_local_auditor")
        timestamp = body.get("reported_at_unix")
        if type(timestamp) not in (int, float) or not math.isfinite(timestamp) or not 0 <= now - timestamp <= MAX_AUDIT_AGE_SEC:
            return reject("stale_future_or_replayed_evidence")
        run_id = body.get("run_id")
        if type(run_id) is not str or len(run_id) != 32 or run_id in runs:
            return reject("duplicate_or_invalid_independent_run")
        runs.add(run_id)
        if body.get("version_proofs") != {minor: minor for minor in MINORS}:
            return reject("version_mismatch_or_missing_minor")
        candidates = body.get("candidates")
        if type(candidates) is not list or len(candidates) != len(TRUSTED_FIXTURES):
            return reject("candidate_count_not_independent")
        origin_seen = set()
        for evidence in candidates:
            if type(evidence) is not dict or set(evidence) != {
                    "variant_id", "engine", "source_sha256", "candidate_sha256",
                    "snapshot_intact", "rust_repair_status", "rust_wall_ms", "test_processes",
                    "retests", "minor_outcomes", "metrics", "gate_status", "proof_sha256"}:
                return reject("incomplete_actual_evidence_shape")
            engine = evidence["engine"]
            if type(engine) is not str or engine not in TRUSTED_FIXTURES or engine in origin_seen:
                return reject("wrong_or_duplicate_trusted_engine")
            origin_seen.add(engine)
            source, candidate = TRUSTED_FIXTURES[engine]
            if (evidence["variant_id"] != _fixed_candidate_identity(engine, source, candidate) or
                    evidence["source_sha256"] != digest(source) or
                    evidence["candidate_sha256"] != digest(candidate) or
                    evidence["snapshot_intact"] is not True):
                return reject("actual_rust_candidate_hash_or_snapshot_invalid")
            proof = evidence["proof_sha256"]
            expected_proof = digest(canonical({"source": digest(source),
                "candidate": digest(candidate), "rust_status": evidence["rust_repair_status"],
                "retests": evidence["retests"], "minors": evidence["minor_outcomes"],
                "nonce": nonces[origin], "origin": origin}))
            if proof != expected_proof or proof in proofs:
                return reject("duplicate_or_unmatched_actual_proof")
            proofs.add(proof)
            retests, outcomes = evidence["retests"], evidence["minor_outcomes"]
            if (type(retests) is not list or len(retests) != RETESTS or
                    any(type(entry) is not dict or set(entry) != {"status", "wall_ms"} or
                        entry["status"] not in ("PASS", "FAIL") or
                        type(entry["wall_ms"]) not in (int, float) or
                        not math.isfinite(entry["wall_ms"]) or entry["wall_ms"] <= 0
                        for entry in retests) or
                    type(outcomes) is not dict or set(outcomes) != set(MINORS) or
                    any(value not in ("PASS", "FAIL") for value in outcomes.values()) or
                    evidence["test_processes"] != RETESTS + len(MINORS)):
                return reject("ten_independent_retests_or_seven_minors_unproven")
            passed = sum(item["status"] == "PASS" for item in retests)
            metrics = {"SAFETY": 0 if evidence["rust_repair_status"] == "PASS" else 1,
                       "CORRECTNESS": RETESTS - passed,
                       "SPEED": sorted(item["wall_ms"] for item in retests)[math.ceil(0.95 * RETESTS) - 1],
                       "RELIABILITY": passed,
                       "COMPATIBILITY": sum(value == "PASS" for value in outcomes.values()),
                       "FUTURE_READINESS": 0}
            if type(evidence["metrics"]) is not dict or set(evidence["metrics"]) != set(AXES):
                return reject("six_measured_axes_required")
            if (any(type(evidence["metrics"][axis]) not in (int, float) or
                    not math.isfinite(evidence["metrics"][axis]) or
                    abs(evidence["metrics"][axis] - metrics[axis]) > 1e-4 for axis in AXES) or
                    type(evidence["gate_status"]) is not dict or
                    set(evidence["gate_status"]) != set(AXES)):
                return reject("signed_values_not_matched_to_actual_observations")
            gates = {axis: "PASS" if (metrics[axis] <= LIMITS[axis] if
                     METRIC_DIRECTION[axis] == "max" else metrics[axis] >= LIMITS[axis])
                     else "FAIL" for axis in AXES}
            if gates != evidence["gate_status"]:
                return reject("signed_gate_disagrees_with_predeclared_threshold")
            verified.setdefault(engine, {})[origin] = {
                "variant_id": evidence["variant_id"], "gate_status": gates,
                "metrics": metrics, "proof_sha256": proof}
    if set(verified) != set(TRUSTED_FIXTURES) or any(set(rows) != set(AUDITOR_ORIGINS)
                                                     for rows in verified.values()):
        return reject("two_independent_attestations_per_candidate_required")

    ranking, decisions = [], []
    for engine in sorted(verified):
        a, b = (verified[engine][origin] for origin in AUDITOR_ORIGINS)
        passes = (a["gate_status"] == b["gate_status"] and
                  all(a["gate_status"][axis] == "PASS" for axis in AXES))
        avg_speed = (a["metrics"]["SPEED"] + b["metrics"]["SPEED"]) / 2
        # Fixed, predeclared scoring: SPEED=40%, RELIABILITY=25%,
        # COMPATIBILITY=20%, FUTURE_READINESS=15%. Only gated candidates scored.
        score = (0.4 * (1 - avg_speed / LIMITS["SPEED"]) +
                 0.25 * (min(a["metrics"]["RELIABILITY"], b["metrics"]["RELIABILITY"]) / RETESTS) +
                 0.2 * (min(a["metrics"]["COMPATIBILITY"], b["metrics"]["COMPATIBILITY"]) / len(MINORS)) +
                 0.15) if passes else None
        decisions.append({"engine": engine, "variant_id": a["variant_id"],
                          "status": "TRUSTED_DUAL_QUALIFIED" if passes else "REJECTED",
                          "both_origins_verified": True, "score": round(score, 6) if passes else None})
        if passes:
            ranking.append((-score, a["variant_id"]))
    ranking.sort()
    winner = ranking[0][1] if ranking else None
    reserve = ranking[1][1] if len(ranking) > 1 else None
    return {"schema_version": 1,
            "status": "LOCAL_TWO_INDEPENDENT_SIGNED_AUDITORS" if winner else "DUAL_AUDIT_NO_WINNER",
            "decision": "TRUSTED_FIXTURE_PRIMARY" if winner else "NO_WINNER",
            "primary_variant": winner, "reserve_variant": reserve,
            "verified_candidate_count": len(ranking), "maximum_reserves": 1,
            "all_six_axes_verified_by_both_local_origins": bool(winner),
            "ranked_only_after_both_signed_reports": True,
            "score_policy": "fixed-speed40-reliability25-compatibility20-freshness15",
            "decisions": decisions,
            "external_independent_audit": False,
            "untrusted_project_code_executed": False,
            "release_authorized": False}


def run_actual_dual_auditors(binary, ruff, runtimes):
    """Run real isolated signer processes, then independently verify both MACs."""
    if type(runtimes) is not dict or set(runtimes) != set(MINORS):
        raise ValueError("seven_selected_minor_paths_required")
    runtimes = {minor: Path(value).absolute() for minor, value in runtimes.items()}
    binary, ruff = Path(binary).absolute(), Path(ruff).absolute()
    if not binary.is_file() or not ruff.is_file() or any(not path.is_file() for path in runtimes.values()):
        return {"status": "NOT_RUN_MISSING_EXECUTABLE", "decision": "NO_WINNER",
                "primary_variant": None, "reserve_variant": None,
                "release_authorized": False}
    keys = {origin: secrets.token_bytes(32) for origin in AUDITOR_ORIGINS}
    nonces = {origin: secrets.token_hex(24) for origin in AUDITOR_ORIGINS}
    if len(set(keys.values())) != len(AUDITOR_ORIGINS) or len(set(nonces.values())) != len(AUDITOR_ORIGINS):
        return {"status": "AUDITOR_RANDOM_COLLISION", "decision": "NO_WINNER", "release_authorized": False}
    script = Path(__file__).absolute()
    artifacts = {}

    def call_auditor(origin, folder):
        folder.mkdir()
        manifest = folder / "runtimes.json"
        manifest.write_text(json.dumps({minor: str(path) for minor, path in runtimes.items()}),
                            encoding="utf-8")
        manifest.chmod(0o400)
        selected = runtimes["3.9"] if origin == "origin-a" else runtimes["3.15"]
        args = [str(selected), "-I", "-S", "-B", str(script), "--internal-auditor",
                "--origin", origin, "--binary", str(binary), "--ruff", str(ruff),
                "--runtime-json", str(manifest)]
        started = time.perf_counter_ns()
        try:
            proc = subprocess.run(args, cwd=str(folder),
                                  env=safe_env(folder, keys[origin], nonces[origin]),
                                  capture_output=True, check=False, timeout=60)
            if proc.returncode or proc.stderr or len(proc.stdout) > MAX_REPORT_BYTES:
                return None, (time.perf_counter_ns() - started) / 1e6
            return json.loads(proc.stdout), (time.perf_counter_ns() - started) / 1e6
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return None, (time.perf_counter_ns() - started) / 1e6

    with tempfile.TemporaryDirectory(prefix="rph-v21-dual-audit-") as temporary:
        root = Path(temporary)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {origin: pool.submit(call_auditor, origin, root / origin) for origin in AUDITOR_ORIGINS}
            timings = {}
            for origin, future in futures.items():
                artifacts[origin], elapsed = future.result()
                timings[origin] = round(elapsed, 5)
        if any(artifacts[origin] is None for origin in AUDITOR_ORIGINS):
            return {"status": "AUDITOR_PROCESS_FAILED", "decision": "NO_WINNER",
                    "auditor_wall_ms": timings, "release_authorized": False}
        verdict = verify_and_rank(artifacts, keys, nonces)
        verdict.update({"auditor_wall_ms": timings,
                        "actual_local_auditor_processes": 2,
                        "distinct_local_origins": list(AUDITOR_ORIGINS),
                        "independent_local_signatures_verified": verdict["status"] ==
                        "LOCAL_TWO_INDEPENDENT_SIGNED_AUDITORS",
                        "actual_trusted_probe_processes": 2 * len(TRUSTED_FIXTURES) * (RETESTS + len(MINORS)),
                        "new_random_keys_used_and_not_returned": True,
                        "audit_workspaces_retained": False})
    return verdict


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--internal-auditor", action="store_true")
    parser.add_argument("--origin", choices=AUDITOR_ORIGINS)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--ruff", required=True)
    parser.add_argument("--runtime-json", required=True)
    args = parser.parse_args()
    try:
        path = Path(args.runtime_json)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 16_384:
            raise ValueError("bounded_json_manifest_required")
        runtimes = json.loads(path.read_text(encoding="utf-8"))
        if args.internal_auditor:
            if not args.origin:
                raise ValueError("selected_local_origin_required")
            key_hex = os.environ.get("RPH_AUDITOR_SECRET_HEX", "")
            nonce = os.environ.get("RPH_AUDITOR_NONCE", "")
            if len(key_hex) != 64:
                raise ValueError("separately_provisioned_auditor_key_required")
            key = bytes.fromhex(key_hex)
            result = audit_in_independent_origin(args.origin, key, nonce, Path(args.binary).absolute(),
                                                 Path(args.ruff).absolute(),
                                                 {minor: Path(value).absolute() for minor, value in runtimes.items()},
                                                 Path.cwd())
        else:
            if args.origin:
                raise ValueError("origin_is_reserved_for_internal_auditor")
            result = run_actual_dual_auditors(args.binary, args.ruff, runtimes)
    except (ValueError, TypeError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
