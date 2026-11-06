"""Bounded, fail-closed privacy envelope for diagnostic and process logs.

This module deliberately refuses arbitrary object serialization.  Unknown
Python code, exceptions, paths, token values and process output are never
rendered into the returned record; only fixed labels, lengths and digests
survive.  It is a reusable local adapter, NOT a claim that every caller of
Rust Python Healer has been instrumented or independently audited.
"""

import hashlib
import hmac
import importlib.util
import json
import re
from pathlib import Path

MAX_LOG_BYTES = 65_536
MAX_CONTEXT_BYTES = 8_192
MAX_EVENT_BYTES = 4_096
CHANNELS = frozenset(("RUST_CLI", "UPDATER", "TRACE", "REPAIR",
                     "KNOWLEDGE", "MODEL", "AUDIT"))
OUTCOMES = frozenset(("PASS", "FAIL", "NOT_RUN", "BLOCKED", "UNKNOWN"))
HEX_SHA256 = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_ADAPTER_PATH = Path(__file__).resolve().with_name("security_integrations_v23.py")


class PrivacyRedactionRejected(ValueError):
    """Input is unsafe to serialize, or exceeds the bounded redaction policy."""


def _bounded_bytes(raw, limit):
    """Do not use str(), bytes(), JSON hooks, or caller-defined conversions."""
    if type(raw) is bytes:
        if len(raw) > limit:
            raise PrivacyRedactionRejected("UNBOUNDED_PRIVATE_BYTES")
        return raw
    if type(raw) is str:
        if len(raw) > limit:
            raise PrivacyRedactionRejected("UNBOUNDED_PRIVATE_TEXT")
        try:
            encoded = raw.encode("utf-8", "strict")
        except UnicodeError:
            raise PrivacyRedactionRejected("UNENCODABLE_PRIVATE_TEXT") from None
        if len(encoded) > limit:
            raise PrivacyRedactionRejected("UNBOUNDED_PRIVATE_TEXT")
        return encoded
    raise PrivacyRedactionRejected("UNTRUSTED_LOG_OBJECT_TYPE")


def _bounded_label(value, allowed, error):
    if type(value) is not str or value not in allowed:
        raise PrivacyRedactionRejected(error)
    return value


def redact_event(channel, outcome, raw, *, context=None):
    """Return a closed-schema, deterministic, privacy-safe evidence record.

    Context is deliberately opaque and hashed; it may contain paths, PII,
    source excerpts or credentials, so no context value is ever returned.
    No external logging or telemetry takes place.
    """
    channel = _bounded_label(channel, CHANNELS, "UNREGISTERED_LOG_CHANNEL")
    outcome = _bounded_label(outcome, OUTCOMES, "INVALID_EVENT_OUTCOME")
    content = _bounded_bytes(raw, MAX_LOG_BYTES)
    metadata = _bounded_bytes(context if context is not None else b"",
                              MAX_CONTEXT_BYTES)
    data = {"schema_version": 1, "status": "PRIVATE_DIGEST_ONLY",
            "channel": channel, "outcome": outcome,
            "raw_sha256": hashlib.sha256(content).hexdigest(),
            "raw_bytes": len(content),
            "context_sha256": hashlib.sha256(metadata).hexdigest(),
            "context_bytes": len(metadata),
            "raw_values_returned": False, "raw_source_executed": False,
            "user_source_mutated": False, "filesystem_writes_audited": False,
            "network_contacted": False,
            "independent_privacy_audit_attested": False,
            "all_application_log_paths_covered": False}
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("ascii")
    data["evidence_sha256"] = hashlib.sha256(canonical).hexdigest()
    if len(canonical) >= MAX_EVENT_BYTES:
        raise PrivacyRedactionRejected("PRIVACY_ENVELOPE_EXCEEDED_LIMIT")
    return data


def verify_redaction(record):
    """Fail closed on changed, extended, or forged envelope metadata.

    This detects *accidental corruption*, not a malicious producer with
    unrestricted control of the metadata. It is not an external signature.
    """
    if type(record) is not dict:
        raise PrivacyRedactionRejected("INVALID_EVENT_ENVELOPE")
    required = {"schema_version", "status", "channel", "outcome", "raw_sha256",
                "raw_bytes", "context_sha256", "context_bytes", "raw_values_returned",
                "raw_source_executed", "user_source_mutated",
                "filesystem_writes_audited", "network_contacted",
                "independent_privacy_audit_attested",
                "all_application_log_paths_covered", "evidence_sha256"}
    if any(type(key) is not str for key in record) or set(record) != required:
        raise PrivacyRedactionRejected("UNEXPECTED_PRIVACY_FIELDS")
    if type(record["schema_version"]) is not int or record["schema_version"] != 1:
        raise PrivacyRedactionRejected("INVALID_EVENT_SCHEMA")
    if type(record["status"]) is not str or record["status"] != "PRIVATE_DIGEST_ONLY":
        raise PrivacyRedactionRejected("INVALID_PRIVACY_STATUS")
    _bounded_label(record["channel"], CHANNELS, "UNREGISTERED_LOG_CHANNEL")
    _bounded_label(record["outcome"], OUTCOMES, "INVALID_EVENT_OUTCOME")
    for key in ("raw_sha256", "context_sha256", "evidence_sha256"):
        if type(record[key]) is not str or not HEX_SHA256.fullmatch(record[key]):
            raise PrivacyRedactionRejected("INVALID_PRIVACY_DIGEST")
    for key, limit in (("raw_bytes", MAX_LOG_BYTES),
                       ("context_bytes", MAX_CONTEXT_BYTES)):
        number = record[key]
        if type(number) is not int or number < 0 or number > limit:
            raise PrivacyRedactionRejected("INVALID_PRIVATE_BYTE_COUNT")
    for key in ("raw_values_returned", "raw_source_executed",
                "user_source_mutated", "filesystem_writes_audited", "network_contacted",
                "independent_privacy_audit_attested", "all_application_log_paths_covered"):
        if type(record[key]) is not bool or record[key]:
            raise PrivacyRedactionRejected("UNVERIFIED_PRIVACY_CLAIM")
    canonical = dict(record)
    claim = canonical.pop("evidence_sha256")
    actual = hashlib.sha256(json.dumps(
        canonical, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True).encode("ascii")).hexdigest()
    if not hmac.compare_digest(claim, actual):
        raise PrivacyRedactionRejected("PRIVATE_EVENT_TAMPERED")
    return {"status": "LOCAL_METADATA_INTEGRITY_VERIFIED_ONLY",
            "event_sha256": claim, "external_audit_attested": False}


def redact_verified_cli_process(stdout, stderr, returncode, command):
    """Integrate the existing v0.23 real Rust CLI output-hashing adapter.

    The adapter performs its original strict allowlist and quota checks; the
    new wrapper never echoes the process output or any external paths.
    """
    # The file is a project-maintained, trusted module beside this file.
    spec = importlib.util.spec_from_file_location(
        "rph_trusted_security_integrations_v23", str(_ADAPTER_PATH))
    if spec is None or spec.loader is None:
        raise PrivacyRedactionRejected("EXISTING_LOG_ADAPTER_UNAVAILABLE")
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    original = adapter.redact_process_result(stdout, stderr, returncode, command)
    if type(original) is not dict or original.get("status") != "REDACTED_CLI_RESULT":
        raise PrivacyRedactionRejected("EXISTING_ADAPTER_NOT_CONFIRMED")
    joined = b"\0".join((stdout, stderr))
    outcome = "PASS" if returncode == 0 else "FAIL"
    # The public command label is already validated against a fixed list.
    envelope = redact_event("RUST_CLI", outcome, joined, context=command)
    return {"adapter_status": "REDACTED_CLI_RESULT",
            "adapter_stdout_sha256": original["stdout_sha256"],
            "adapter_stderr_sha256": original["stderr_sha256"],
            "privacy_event": envelope,
            "all_rust_cli_log_paths_covered": False,
            "external_privacy_audit_attested": False}
