"""Fail-closed six-axis candidate qualification on independently supplied reports.

This is a policy enforcement / decision logging component, NOT a sandbox,
autonomous correctness oracle, or proof that an auditor ran its claimed tests.
The trust file must be protected independently by the operator: an attacker
who controls BOTH a trust key and the evidence can forge any reported result.
No candidate source, package, or test is executed by this helper.
"""

import argparse
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat


AXES = (
    "SAFETY", "CORRECTNESS", "SPEED", "RELIABILITY",
    "COMPATIBILITY", "FUTURE_READINESS",
)
METRICS = {
    "SAFETY": ("critical_findings", "max"),
    "CORRECTNESS": ("failing_oracle_checks", "max"),
    "SPEED": ("p95_millis", "max"),
    "RELIABILITY": ("passing_repetitions", "min"),
    "COMPATIBILITY": ("passing_python_minors", "min"),
    "FUTURE_READINESS": ("metadata_age_days", "max"),
}
MIN_SAFETY = {"SAFETY": 0, "CORRECTNESS": 0}
MAX_SIZE = 512_000
MAX_CANDIDATES = 64
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")


def canonical(payload):
    """Canonical, unambiguous JSON bytes with no NaN/Infinity."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(payload):
    return hashlib.sha256(canonical(payload)).hexdigest()


def identity(engine, code_hash, config_hash):
    if not isinstance(engine, str) or not IDENT.fullmatch(engine):
        raise ValueError("invalid_engine")
    if any(not isinstance(value, str) or not HEX64.fullmatch(value)
           for value in (code_hash, config_hash)):
        raise ValueError("invalid_variant_hash")
    value = hashlib.sha256((engine + ":" + code_hash + ":" + config_hash)
                           .encode("ascii")).hexdigest()
    return "V-" + value[:16]


def validate_policy(policy):
    if not isinstance(policy, dict) or policy.get("schema_version") != 1:
        raise ValueError("invalid_policy")
    name = policy.get("policy_id")
    if not isinstance(name, str) or not IDENT.fullmatch(name):
        raise ValueError("invalid_policy_identity")
    thresholds = policy.get("thresholds")
    if not isinstance(thresholds, dict) or set(thresholds) != set(AXES):
        raise ValueError("six_thresholds_required")
    for axis in AXES:
        entry = thresholds[axis]
        if not isinstance(entry, dict) or set(entry) != {"metric", "comparison", "limit"}:
            raise ValueError("invalid_threshold_definition")
        if (entry["metric"], entry["comparison"]) != METRICS[axis]:
            raise ValueError("axis_metric_mismatch")
        limit = entry["limit"]
        if type(limit) not in (int, float) or not math.isfinite(limit) or not 0 <= limit <= 1e6:
            raise ValueError("invalid_threshold_limit")
        if axis in MIN_SAFETY and limit != 0:
            raise ValueError("critical_failures_must_be_zero")
        # No silent weakening of the stated policy minimums.
        if (axis == "RELIABILITY" and limit < 10 or
                axis == "COMPATIBILITY" and limit < 7 or
                axis == "SPEED" and limit > 50 or
                axis == "FUTURE_READINESS" and limit > 30):
            raise ValueError("threshold_weaker_than_policy_floor")
    if policy.get("maximum_reserves") != 1:
        raise ValueError("exactly_one_reserve_limit_required")
    return thresholds


def validate_trust(trust):
    if not isinstance(trust, dict) or trust.get("schema_version") != 1:
        raise ValueError("invalid_trust_schema")
    auditors = trust.get("auditors")
    if not isinstance(auditors, dict) or not 6 <= len(auditors) <= 32:
        raise ValueError("six_distinct_auditors_required")
    seen_keys = set()
    for key, value in auditors.items():
        if not isinstance(key, str) or not IDENT.fullmatch(key):
            raise ValueError("invalid_auditor_id")
        if not isinstance(value, dict) or set(value) != {"key_hex", "axes"}:
            raise ValueError("invalid_trust_record")
        secret, allowed = value["key_hex"], value["axes"]
        if not isinstance(secret, str) or not HEX64.fullmatch(secret):
            raise ValueError("invalid_auditor_secret")
        if (not isinstance(allowed, list) or not allowed or
                any(not isinstance(axis, str) or axis not in AXES for axis in allowed)):
            raise ValueError("invalid_auditor_scope")
        if secret in seen_keys:
            raise ValueError("auditors_must_have_distinct_signing_keys")
        seen_keys.add(secret)
    return auditors


def record_payload(policy_hash, variant, record):
    return {
        "policy_sha256": policy_hash,
        "variant_id": variant["variant_id"],
        "engine": variant["engine"],
        "code_sha256": variant["code_sha256"],
        "config_sha256": variant["config_sha256"],
        "axis": record["axis"],
        "metric": record["metric"],
        "value": record["value"],
        "status": record["status"],
        "auditor_id": record["auditor_id"],
        "evidence_sha256": record["evidence_sha256"],
        "run_id": record["run_id"],
    }


def sign_for_test(policy, variant, record, key_hex):
    """Deterministic signing helper for trusted test fixtures only.

    Production audit signers must run out-of-process with secret-protected keys.
    The verifier never signs or generates verdicts itself.
    """
    return hmac.new(bytes.fromhex(key_hex), canonical(record_payload(digest(policy),
                                                               variant, record)),
                    hashlib.sha256).hexdigest()


def verify_record(policy_hash, variant, record, auditors):
    if not isinstance(record, dict) or set(record) != {
            "axis", "metric", "value", "status", "auditor_id", "evidence_sha256",
            "signature", "run_id"}:
        raise ValueError("invalid_audit_record")
    axis, auditor_id = record["axis"], record["auditor_id"]
    if axis not in AXES or auditor_id not in auditors:
        raise ValueError("unknown_axis_or_auditor")
    if axis not in auditors[auditor_id]["axes"]:
        raise ValueError("auditor_outside_authorized_scope")
    if record["metric"] != METRICS[axis][0]:
        raise ValueError("unexpected_axis_metric")
    if type(record["value"]) not in (int, float) or not math.isfinite(record["value"]):
        raise ValueError("nonfinite_axis_metric")
    if not 0 <= record["value"] <= 1e9:
        raise ValueError("axis_metric_out_of_bounds")
    if record["status"] not in ("PASS", "FAIL", "NOT_RUN"):
        raise ValueError("invalid_axis_status")
    if not isinstance(record["run_id"], str) or not IDENT.fullmatch(record["run_id"]):
        raise ValueError("invalid_run_id")
    if any(not isinstance(record[key], str) or not HEX64.fullmatch(record[key])
           for key in ("evidence_sha256", "signature")):
        raise ValueError("invalid_signed_hash")
    expected = hmac.new(bytes.fromhex(auditors[auditor_id]["key_hex"]),
                        canonical(record_payload(policy_hash, variant, record)),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(record["signature"], expected):
        raise ValueError("audit_signature_invalid")


def qualify(policy, trust, evidence):
    """Evaluate ALL six independently attested gates before any ranking."""
    thresholds = validate_policy(policy)
    auditors = validate_trust(trust)
    if not isinstance(evidence, dict) or evidence.get("schema_version") != 1:
        raise ValueError("invalid_evidence")
    variants = evidence.get("candidates")
    if not isinstance(variants, list) or not 0 < len(variants) <= MAX_CANDIDATES:
        raise ValueError("invalid_candidate_count")
    policy_hash = digest(policy)
    identities = set()
    all_evidence_hashes = set()
    all_run_ids = set()
    qualified, decisions = [], []
    for variant in variants:
        if not isinstance(variant, dict) or set(variant) != {
                "variant_id", "engine", "code_sha256", "config_sha256", "observations"}:
            raise ValueError("invalid_variant_structure")
        variant_id = variant["variant_id"]
        if variant_id != identity(variant["engine"], variant["code_sha256"],
                                  variant["config_sha256"]):
            raise ValueError("variant_identity_hash_mismatch")
        if variant_id in identities:
            raise ValueError("duplicate_variant_requires_explicit_retest")
        identities.add(variant_id)
        observations = variant["observations"]
        if not isinstance(observations, list) or len(observations) > 6:
            raise ValueError("invalid_observation_count")
        measured = {}
        used_auditors = set()
        used_evidence = set()
        seen_runs = set()
        for record in observations:
            verify_record(policy_hash, variant, record, auditors)
            axis, auditor_id, run_id = record["axis"], record["auditor_id"], record["run_id"]
            if (axis in measured or auditor_id in used_auditors or
                    run_id in seen_runs or record["evidence_sha256"] in used_evidence):
                raise ValueError("duplicated_axis_auditor_run_or_evidence")
            if run_id in all_run_ids or record["evidence_sha256"] in all_evidence_hashes:
                raise ValueError("cross_variant_evidence_reused")
            measured[axis] = record
            used_auditors.add(auditor_id)
            seen_runs.add(run_id)
            used_evidence.add(record["evidence_sha256"])
            all_run_ids.add(run_id)
            all_evidence_hashes.add(record["evidence_sha256"])
        failures = []
        for axis in AXES:
            if axis not in measured:
                failures.append(axis + "_NOT_RUN")
                continue
            entry, threshold = measured[axis], thresholds[axis]
            if entry["status"] != "PASS":
                failures.append(axis + "_NOT_PASS")
                continue
            value, limit = entry["value"], threshold["limit"]
            if not (value <= limit if threshold["comparison"] == "max" else value >= limit):
                failures.append(axis + "_THRESHOLD_FAIL")
        accepted = not failures
        row = {"variant_id": variant_id, "decision": "POLICY_QUALIFIED" if accepted else
               "REJECTED", "failed_gates": failures,
               "gates_checked": len(measured), "source_executed": False}
        decisions.append(row)
        if accepted:
            metrics = {axis: measured[axis]["value"] for axis in AXES}
            qualified.append((
                (metrics["SAFETY"], metrics["CORRECTNESS"],
                 -metrics["RELIABILITY"], metrics["SPEED"],
                 -metrics["COMPATIBILITY"], metrics["FUTURE_READINESS"],
                 variant_id), variant_id))
    qualified.sort()
    winner = qualified[0][1] if qualified else None
    reserve = qualified[1][1] if len(qualified) > 1 else None
    report = {
        "schema_version": 1,
        "status": "POLICY_EVALUATED_NOT_BEHAVIORALLY_PROVEN",
        "decision": "POLICY_PRIMARY_EXISTS" if winner else "NO_WINNER",
        "primary_variant": winner,
        "reserve_variant": reserve,
        "qualified_variants": len(qualified),
        "unqualified_variants": len(decisions) - len(qualified),
        "maximum_reserves": 1,
        "policy_sha256": policy_hash,
        "evidence_sha256": digest(evidence),
        "decision_log": decisions,
        "audit_record_sha256": digest(decisions),
        "ranked_by": "DETERMINISTIC_SIX_AXIS_POLICY_ON_AUTHENTICATED_SELF_REPORTS",
        "source_executed": False,
        "independent_execution_verified": False,
        "release_authorized": False,
        "note": "Trusted HMAC reporters are configured by the operator; "
                "signature checks do not independently prove that claims or tests were true",
    }
    return report


def bounded_file(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("symlink_policy_input_refused")
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_SIZE:
            raise ValueError("policy_input_not_unique_bounded_file")
        raw = handle.read(MAX_SIZE + 1)
        after = os.fstat(handle.fileno())
    if (len(raw) > MAX_SIZE or
            (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) !=
            (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns)):
        raise ValueError("policy_input_modified_or_oversized")
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                      parse_constant=lambda _:
                      (_ for _ in ()).throw(ValueError("invalid_json_number")))


def inspect_files(policy_path, trust_path, evidence_path):
    return qualify(bounded_file(policy_path), bounded_file(trust_path),
                   bounded_file(evidence_path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--trust", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(inspect_files(args.policy, args.trust, args.evidence)))


if __name__ == "__main__":
    main()
