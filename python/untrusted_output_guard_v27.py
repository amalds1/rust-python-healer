"""F208: bounded local data-only gate for untrusted tool-output bytes.

This is a subprocess-testable, operator-keyed *local* integrity boundary.
It does not run proposed tool calls, execute downloaded code, pass tool text to
an LLM, prove resistance of any external model, or provide external attestation.
All content is returned as hashes and fixed vocabulary only.
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import importlib.util
from functools import lru_cache
import json
import os
import re
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit

MAX_PAYLOAD_BYTES = 65_536
MAX_REQUEST_BYTES = 160_000
MAX_SOURCES = 64
SHA256 = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
HEX_HMAC = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
SOURCE_FIELDS = frozenset(("source_id", "uri", "revision", "sha256"))
RECORD_FIELDS = SOURCE_FIELDS | {"payload_b64", "approval_hmac"}
POLICY_FIELDS = frozenset(("schema_version", "generation", "sources", "policy_hmac"))
POLICY_CORE = POLICY_FIELDS - {"policy_hmac"}
RECEIPT_FIELDS = frozenset(
    (
        "schema",
        "status",
        "source_id",
        "uri_sha256",
        "revision",
        "policy_generation",
        "sha256",
        "payload_bytes",
        "repeat_type",
        "raw_payload_exposed",
        "tool_actions_executed",
        "untrusted_roles_ignored",
        "suspected_injection_classes",
        "receipt_hmac",
    )
)
RECEIPT_CORE = RECEIPT_FIELDS - {"receipt_hmac"}
SIGN_DOMAIN = b"RPH-F208-SOURCE-APPROVAL-V1\0"
POLICY_DOMAIN = b"RPH-F208-TRUST-POLICY-V1\0"
RECEIPT_DOMAIN = b"RPH-F208-RECEIPT-V1\0"

_INDICATORS = (
    (
        "ROLE_SPOOF",
        re.compile(
            r"(?:\brole['\"]?\s*[:=]\s*['\"]?(?:system|developer|assistant)\b|<\|(?:system|developer|assistant)\|>|\[inst\])",
            re.IGNORECASE,
        ),
    ),
    (
        "INSTRUCTION_OVERRIDE",
        re.compile(
            r"(?:ignore\s+(?:all\s+|the\s+)?(?:previous|prior|above|system)\s+instructions|disregard\s+(?:your\s+)?instructions|you\s+are\s+now\s+the\s+system)",
            re.IGNORECASE,
        ),
    ),
    (
        "TOOL_CALL_PROPOSAL",
        re.compile(
            r"(?:\btool[_ -]?calls?\b|\bfunction_call\b|\bexecute_untrusted_source\b|\bsubprocess\.run\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "EXFILTRATION_PROPOSAL",
        re.compile(
            r"(?:\b(?:reveal|steal|exfiltrate)\s+(?:your\s+)?(?:passwords?|secrets?|keys?|tokens?)\b|\bcurl\s+https?://|\bsend\b.{0,60}\b(?:secret|token|password|api[_ -]?key)\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "DESTRUCTIVE_PROPOSAL",
        re.compile(
            r"(?:\brm\s+-rf\b|\b(?:shutil\.rmtree|os\.system)\s*\(|\bdelete\s+all\s+files\b)",
            re.IGNORECASE,
        ),
    ),
)
_INDICATOR_NAMES = frozenset(name for name, _ in _INDICATORS) | {"BIDI_CONTROL"}


class UntrustedOutputRejected(ValueError):
    """Safe, constant rejection code; never append hostile input to errors."""


def _reject(reason):
    raise UntrustedOutputRejected(reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(obj):
    try:
        return json.dumps(
            obj,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError):
        _reject("CANONICAL_FORMAT_INVALID")


def _hmac(key, domain, obj):
    return hmac.new(key, domain + _canonical(obj), hashlib.sha256).hexdigest()


def _valid_key(key):
    if type(key) is not bytes or len(key) < 32 or len(key) > 128:
        _reject("OPERATOR_KEY_INVALID")


def _exact_keys(obj, expected, error):
    if type(obj) is not dict or frozenset(obj) != expected:
        _reject(error)


def _valid_int(value):
    return type(value) is int and 0 <= value < 1_000_000_000


def _valid_sha(value):
    return type(value) is str and SHA256.fullmatch(value) is not None


def _valid_uri(uri):
    if (
        type(uri) is not str
        or not 12 <= len(uri) <= 2048
        or not uri.isascii()
        or any(ord(c) <= 32 or ord(c) == 127 for c in uri)
    ):
        _reject("SOURCE_URI_INVALID")
    try:
        parts = urlsplit(uri)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or not parts.netloc
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or parts.port not in (None, 443)
            or parts.hostname.endswith(".")
            or not parts.path.startswith("/")
            or "\\" in uri
            or ".." in parts.path.split("/")
        ):
            _reject("SOURCE_URI_INVALID")
    except ValueError:
        _reject("SOURCE_URI_INVALID")


def _validate_source(entry):
    _exact_keys(entry, SOURCE_FIELDS, "SOURCE_RECORD_INVALID")
    if type(entry["source_id"]) is not str or not SOURCE_ID.fullmatch(
        entry["source_id"]
    ):
        _reject("SOURCE_ID_INVALID")
    _valid_uri(entry["uri"])
    if not _valid_int(entry["revision"]) or not _valid_sha(entry["sha256"]):
        _reject("SOURCE_RECORD_INVALID")


def _validate_policy_structure(policy):
    _exact_keys(policy, POLICY_FIELDS, "POLICY_SCHEMA_INVALID")
    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != 1
        or not _valid_int(policy["generation"])
        or type(policy["sources"]) is not list
        or not 1 <= len(policy["sources"]) <= MAX_SOURCES
    ):
        _reject("POLICY_SCHEMA_INVALID")
    pins = {}
    for entry in policy["sources"]:
        _validate_source(entry)
        identity = (entry["source_id"], entry["uri"], entry["revision"])
        if identity in pins:
            _reject("DUPLICATE_SOURCE_PIN")
        pins[identity] = entry["sha256"]
    return pins


def sign_trust_policy(policy, key):
    """Trusted operator-side policy MAC; provenance pins cannot self-authorize."""
    _valid_key(key)
    _validate_policy_structure(policy)
    return _hmac(key, POLICY_DOMAIN, {name: policy[name] for name in POLICY_CORE})


def _validate_policy(policy, key):
    pins = _validate_policy_structure(policy)
    signature = policy["policy_hmac"]
    if type(signature) is not str or not HEX_HMAC.fullmatch(signature):
        _reject("POLICY_SIGNATURE_INVALID")
    expected = _hmac(key, POLICY_DOMAIN, {name: policy[name] for name in POLICY_CORE})
    if not hmac.compare_digest(expected, signature):
        _reject("POLICY_SIGNATURE_DENIED")
    return pins


def sign_operator_approval(source, key):
    """Trusted operator-side helper: MAC over exactly one pinned source revision.

    Never derive trusted policy from instructions embedded in source content.
    """
    _valid_key(key)
    _validate_source(source)
    return _hmac(key, SIGN_DOMAIN, source)


def package_tool_bytes(raw, source, key):
    """Encode fixture bytes; this function does not authorize their instructions."""
    if type(raw) is not bytes or not 0 <= len(raw) <= MAX_PAYLOAD_BYTES:
        _reject("PAYLOAD_TOO_LARGE_OR_INVALID")
    _validate_source(source)
    if _sha(raw) != source["sha256"]:
        _reject("SOURCE_DIGEST_MISMATCH")
    return dict(
        source,
        payload_b64=base64.b64encode(raw).decode("ascii"),
        approval_hmac=sign_operator_approval(source, key),
    )


def _validate_receipt(prior, key):
    _exact_keys(prior, RECEIPT_FIELDS, "PRIOR_RECEIPT_INVALID")
    signed = {name: prior[name] for name in RECEIPT_CORE}
    if (
        prior["schema"] != 1
        or prior["status"] != "DATA_ONLY_PASS"
        or type(prior["source_id"]) is not str
        or not SOURCE_ID.fullmatch(prior["source_id"])
        or not _valid_sha(prior["uri_sha256"])
        or not _valid_sha(prior["sha256"])
        or not _valid_int(prior["revision"])
        or not _valid_int(prior["policy_generation"])
        or type(prior["payload_bytes"]) is not int
        or not 0 <= prior["payload_bytes"] <= MAX_PAYLOAD_BYTES
        or prior["repeat_type"] not in ("NEW", "RETEST")
        or prior["raw_payload_exposed"] is not False
        or prior["tool_actions_executed"] is not False
        or prior["untrusted_roles_ignored"] is not True
        or type(prior["suspected_injection_classes"]) is not list
        or any(
            type(x) is not str or x not in _INDICATOR_NAMES
            for x in prior["suspected_injection_classes"]
        )
        or type(prior["receipt_hmac"]) is not str
        or not HEX_HMAC.fullmatch(prior["receipt_hmac"])
    ):
        _reject("PRIOR_RECEIPT_INVALID")
    if not hmac.compare_digest(
        _hmac(key, RECEIPT_DOMAIN, signed), prior["receipt_hmac"]
    ):
        _reject("PRIOR_RECEIPT_TAMPERED")


def _indicators(raw):
    text = raw.decode("utf-8", "replace")
    found = [name for name, expression in _INDICATORS if expression.search(text)]
    if any(c in text for c in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"):
        found.append("BIDI_CONTROL")
    return found


def verify_data_only(record, trust_policy, operator_key, prior_receipt=None):
    """Verify pinned provenance, anti-rollback and return ONLY an opaque receipt.

    No returned field contains raw tool bytes, requested commands, role text or
    attacker-supplied URLs. The optional prior receipt is HMAC-verified first.
    """
    _valid_key(operator_key)
    pins = _validate_policy(trust_policy, operator_key)
    _exact_keys(record, RECORD_FIELDS, "TOOL_RECORD_INVALID")
    source = {field: record[field] for field in SOURCE_FIELDS}
    _validate_source(source)
    identity = (source["source_id"], source["uri"], source["revision"])
    if identity not in pins:
        _reject("SOURCE_URI_OR_REVISION_NOT_PINNED")
    if pins[identity] != source["sha256"]:
        _reject("SOURCE_NOT_HASH_PINNED")
    signature = record["approval_hmac"]
    if type(signature) is not str or not HEX_HMAC.fullmatch(signature):
        _reject("SOURCE_APPROVAL_INVALID")
    if not hmac.compare_digest(_hmac(operator_key, SIGN_DOMAIN, source), signature):
        _reject("SOURCE_APPROVAL_DENIED")
    encoded = record["payload_b64"]
    if type(encoded) is not str or len(encoded) > ((MAX_PAYLOAD_BYTES + 2) // 3) * 4:
        _reject("PAYLOAD_ENCODING_INVALID")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError, UnicodeError):
        _reject("PAYLOAD_ENCODING_INVALID")
    if len(raw) > MAX_PAYLOAD_BYTES or _sha(raw) != source["sha256"]:
        _reject("SOURCE_DIGEST_MISMATCH")

    repeat_type = "NEW"
    if prior_receipt is not None:
        _validate_receipt(prior_receipt, operator_key)
        if prior_receipt["source_id"] != source["source_id"] or prior_receipt[
            "uri_sha256"
        ] != _sha(source["uri"].encode("ascii")):
            _reject("SOURCE_CHAIN_IDENTITY_CHANGED")
        if trust_policy["generation"] < prior_receipt["policy_generation"]:
            _reject("POLICY_GENERATION_ROLLBACK")
        if source["revision"] < prior_receipt["revision"]:
            _reject("SOURCE_REVISION_ROLLBACK")
        if source["revision"] == prior_receipt["revision"]:
            if source["sha256"] != prior_receipt["sha256"]:
                _reject("SOURCE_REVISION_REUSED_DIFFERENT_CONTENT")
            repeat_type = "RETEST"

    core = {
        "schema": 1,
        "status": "DATA_ONLY_PASS",
        "source_id": source["source_id"],
        "uri_sha256": _sha(source["uri"].encode("ascii")),
        "revision": source["revision"],
        "policy_generation": trust_policy["generation"],
        "sha256": source["sha256"],
        "payload_bytes": len(raw),
        "repeat_type": repeat_type,
        "raw_payload_exposed": False,
        "tool_actions_executed": False,
        "untrusted_roles_ignored": True,
        "suspected_injection_classes": _indicators(raw),
    }
    return dict(core, receipt_hmac=_hmac(operator_key, RECEIPT_DOMAIN, core))


def _strict_json(blob):
    if type(blob) is not bytes or len(blob) > MAX_REQUEST_BYTES:
        _reject("REQUEST_TOO_LARGE_OR_INVALID")

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _reject("DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def reject_constant(_value):
        _reject("NONFINITE_JSON_NUMBER")

    try:
        return json.loads(
            blob.decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
    except UntrustedOutputRejected:
        raise
    except (ValueError, UnicodeError, RecursionError):
        _reject("REQUEST_JSON_INVALID")


@lru_cache(maxsize=1)
def _windows_privacy():
    sibling = Path(__file__).resolve().parent / "windows_private_paths.py"
    spec = importlib.util.spec_from_file_location("rph_f208_windows_privacy", sibling)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_private_operator_key(path):
    """Read one private, single-link owner-key on its actual no-follow fd.

    POSIX keeps 0600+uid checks; Windows uses the current-owner/DACL checked
    HANDLE and denies leaf write/delete sharing. This is not ancestor or
    external human-identity attestation.
    """
    if type(path) is not str or not 1 <= len(path) <= 4096:
        _reject("OPERATOR_KEY_FILE_UNSAFE")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    try:
        pre = os.lstat(path)
        if not stat.S_ISREG(pre.st_mode) or pre.st_nlink != 1 or not 32 <= pre.st_size <= 128:
            _reject("OPERATOR_KEY_FILE_UNSAFE")
        fd = (_windows_privacy().open_private_readonly(os.path.abspath(path))
              if os.name == "nt" else os.open(path, flags))
        try:
            opened = os.fstat(fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (pre.st_dev, pre.st_ino, pre.st_size, pre.st_mtime_ns) !=
                   (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                or opened.st_nlink != 1
                or (os.name != "nt" and stat.S_IMODE(opened.st_mode) != 0o600)
                or (os.name != "nt" and hasattr(os, "getuid") and opened.st_uid != os.getuid())
                or not 32 <= opened.st_size <= 128
            ):
                _reject("OPERATOR_KEY_FILE_UNSAFE")
            if os.name == "nt":
                _windows_privacy().assert_private_file_descriptor(fd)
            key = os.read(fd, 129)
            if os.name == "nt":
                _windows_privacy().assert_private_file_descriptor(fd)
            last = os.fstat(fd)
            if (len(key) != opened.st_size or last.st_nlink != 1
                    or not stat.S_ISREG(last.st_mode)
                    or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) !=
                       (last.st_dev, last.st_ino, last.st_size, last.st_mtime_ns)):
                _reject("OPERATOR_KEY_FILE_UNSAFE")
        finally:
            os.close(fd)
    except (OSError, ValueError, TypeError):
        _reject("OPERATOR_KEY_FILE_UNSAFE")
    _valid_key(key)
    return key


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="F208 local data-only tool-output verifier"
    )
    parser.add_argument("--key-file", required=True)
    args = parser.parse_args(argv)
    try:
        key = read_private_operator_key(args.key_file)
        request = _strict_json(sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1))
        if type(request) is not dict or frozenset(request) not in (
            frozenset(("record", "policy")),
            frozenset(("record", "policy", "prior_receipt")),
        ):
            _reject("REQUEST_SCHEMA_INVALID")
        result = verify_data_only(
            request["record"], request["policy"], key, request.get("prior_receipt")
        )
        sys.stdout.write(_canonical(result).decode("ascii") + "\n")
        return 0
    except UntrustedOutputRejected as rejected:
        sys.stdout.write(
            _canonical(
                {
                    "status": "REJECTED",
                    "reason": str(rejected),
                    "raw_payload_exposed": False,
                    "tool_actions_executed": False,
                }
            ).decode("ascii")
            + "\n"
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
