"""Tightly scoped, one-use operator gate for an actual local canary swap.

All SOURCE_MODIFY, PACKAGE_INSTALL, arbitrary binary releases and unknown
mutation adapters remain denied. Only a bounded, signed local JSON-canary
fixture in an owner-private directory is supported. No human identity, remote
release channel or Rust-wide mutation-hook coverage is asserted.
"""

import hashlib
import hmac
import importlib.util
import json
import os
import re
import stat
from pathlib import Path

SHA = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,55}\Z", re.ASCII)
HEX32 = re.compile(r"[a-f0-9]{32}\Z", re.ASCII)
SCOPES = frozenset(("LOCAL_JSON_CANARY",))
SCOPE_FIELDS = frozenset((
    "schema", "operation", "action", "directory_sha256", "active_name",
    "candidate_name", "old_sha256", "candidate_sha256", "actor_id", "nonce"))
_LOCAL_DIR = Path(__file__).resolve().parent


class MutationGateRejected(ValueError):
    """The target, reviewer intent or independent operation scope is invalid."""


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _trusted_module(name):
    if name not in ("human_approval", "release_canary_v21",
                    "security_integrations_v23", "platform_privacy_v028"):
        raise MutationGateRejected("UNTRUSTED_MUTATION_ADAPTER")
    path = _LOCAL_DIR / (name + ".py")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size < 100 or info.st_size > 1_000_000:
        raise MutationGateRejected("MUTATION_ADAPTER_UNAVAILABLE")
    spec = importlib.util.spec_from_file_location("rph_v26_" + name, str(path))
    if spec is None or spec.loader is None:
        raise MutationGateRejected("MUTATION_ADAPTER_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _scope_key(key):
    if type(key) is not bytes or len(key) < 32 or len(key) > 128:
        raise MutationGateRejected("SCOPE_KEY_INVALID")
    return key


def sign_scope_for_test(scope, key):
    """Fixture signer only; possession of a key is not verified human identity."""
    if type(scope) is not dict or set(scope) != SCOPE_FIELDS:
        raise MutationGateRejected("INVALID_MUTATION_SCOPE")
    return hmac.new(_scope_key(key), _canonical(scope), hashlib.sha256).hexdigest()


def _check_private_directory(folder):
    if type(folder) not in (str, type(Path())):
        raise MutationGateRejected("CANARY_DIRECTORY_INVALID")
    root = Path(folder)
    if not root.is_absolute() or root != root.resolve():
        raise MutationGateRejected("CANARY_DIRECTORY_ALIAS_REFUSED")
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise MutationGateRejected("CANARY_DIRECTORY_NOT_PRIVATE")
    if os.name == "nt":
        try:
            _trusted_module("platform_privacy_v028").private_directory(root, "CANARY_DIRECTORY_NOT_PRIVATE")
        except (ValueError, OSError) as problem:
            raise MutationGateRejected("CANARY_DIRECTORY_NOT_PRIVATE") from problem
    elif stat.S_IMODE(info.st_mode) & 0o077:
        raise MutationGateRejected("CANARY_DIRECTORY_NOT_PRIVATE")
    return root


def _check_name(value):
    if type(value) is not str or not NAME.fullmatch(value) or value.startswith("."):
        raise MutationGateRejected("CANARY_FILENAME_SCOPE_INVALID")
    return value


def _hash_source(path, canary):
    content = canary._bounded_file(path, canary.MAX_RELEASE_BYTES)
    return hashlib.sha256(content).hexdigest()


def local_canary_with_scope(folder, active_name, candidate_name, ledger,
                            scope, scope_signature, scope_key,
                            approval_token, approval_key, actor,
                            manifest, manifest_signature, manifest_key,
                            *, inject_failure=False):
    """Consume a scoped one-use approval, then actually promote/rollback JSON.

    This wraps the original v0.23 real mutation path, with an additional
    signed directory/name/nonce scope and preflight before nonce consumption.
    The existing adapter rechecks the source hashes before the actual swap.
    """
    root = _check_private_directory(folder)
    active_name = _check_name(active_name)
    candidate_name = _check_name(candidate_name)
    if active_name == candidate_name:
        raise MutationGateRejected("SAME_CANARY_SOURCE_AND_TARGET")
    if (type(scope) is not dict or set(scope) != SCOPE_FIELDS
            or type(scope_signature) is not str or not SHA.fullmatch(scope_signature)
            or type(actor) is not str or not NAME.fullmatch(actor)
            or type(manifest) is not dict or type(approval_token) is not dict
            or type(inject_failure) is not bool):
        raise MutationGateRejected("INVALID_MUTATION_ARGUMENTS")
    if (type(scope["schema"]) is not int or
            any(type(scope[name]) is not str for name in SCOPE_FIELDS - {"schema"})):
        raise MutationGateRejected("INVALID_MUTATION_SCOPE_TYPES")
    _scope_key(scope_key)
    if (type(approval_key) is not dict or
            type(approval_key.get("key_hex")) is not str or
            not SHA.fullmatch(approval_key["key_hex"])):
        raise MutationGateRejected("APPROVAL_KEY_INVALID")
    if hmac.compare_digest(scope_key, bytes.fromhex(approval_key["key_hex"])):
        raise MutationGateRejected("SCOPE_AND_REVIEW_KEYS_MUST_DIFFER")
    if (type(manifest_key) is not bytes or len(manifest_key) < 16
            or hmac.compare_digest(scope_key, manifest_key)):
        raise MutationGateRejected("CANARY_SIGNER_KEY_NOT_SEPARATE")
    if (type(approval_token.get("nonce")) is not str or
            not HEX32.fullmatch(approval_token["nonce"])):
        raise MutationGateRejected("APPROVAL_NONCE_INVALID")
    canary = _trusted_module("release_canary_v21")
    if (set(manifest) != {"schema", "operation", "old_sha256",
                          "candidate_sha256", "release", "actor"}
            or type(manifest["schema"]) is not int or manifest["schema"] != 1
            or type(manifest["operation"]) is not str
            or manifest["operation"] != "local_canary"
            or type(manifest["release"]) is not str
            or not canary.LABEL.fullmatch(manifest["release"])
            or type(manifest["actor"]) is not str
            or not canary.LABEL.fullmatch(manifest["actor"])):
        raise MutationGateRejected("CANARY_MANIFEST_UNSAFE")
    if (type(manifest_signature) is not str or not SHA.fullmatch(manifest_signature)
            or not hmac.compare_digest(
                canary.canary_signature(manifest, manifest_key), manifest_signature)):
        raise MutationGateRejected("CANARY_SIGNATURE_INVALID")
    active = root / active_name
    candidate = root / candidate_name
    if (type(manifest.get("old_sha256")) is not str
            or type(manifest.get("candidate_sha256")) is not str
            or not SHA.fullmatch(manifest["old_sha256"])
            or not SHA.fullmatch(manifest["candidate_sha256"])):
        raise MutationGateRejected("CANARY_MANIFEST_HASH_INVALID")
    expected = {"schema": 1, "operation": "LOCAL_JSON_CANARY",
                "action": "BINARY_RELEASE",
                "directory_sha256": hashlib.sha256(str(root).encode("utf-8")).hexdigest(),
                "active_name": active_name, "candidate_name": candidate_name,
                "old_sha256": manifest["old_sha256"],
                "candidate_sha256": manifest["candidate_sha256"],
                "actor_id": actor, "nonce": approval_token["nonce"]}
    if scope != expected:
        raise MutationGateRejected("APPROVED_MUTATION_SCOPE_MISMATCH")
    expected_signature = sign_scope_for_test(scope, scope_key)
    if not hmac.compare_digest(expected_signature, scope_signature):
        raise MutationGateRejected("MUTATION_SCOPE_SIGNATURE_INVALID")
    # This is deliberately BEFORE one-use intent consumption. The original
    # mutation path independently verifies these digests again at execution.
    if (_hash_source(active, canary) != manifest["old_sha256"] or
            _hash_source(candidate, canary) != manifest["candidate_sha256"]):
        raise MutationGateRejected("CANARY_CHANGED_BEFORE_HUMAN_APPROVAL")
    if type(ledger) not in (str, type(Path())) or Path(ledger).parent != root:
        raise MutationGateRejected("APPROVAL_LEDGER_OUTSIDE_PRIVATE_SCOPE")
    if os.name == "nt" and Path(ledger).exists():
        try:
            privacy = _trusted_module("platform_privacy_v028").windows_privacy()
            descriptor = privacy.open_private_readonly(Path(ledger))
            try:
                privacy.assert_private_file_descriptor(descriptor)
            finally:
                os.close(descriptor)
        except (ValueError, OSError) as problem:
            raise MutationGateRejected("APPROVAL_LEDGER_NOT_PRIVATE") from problem
    if (type(approval_token.get("action")) is not str or
            approval_token["action"] != "BINARY_RELEASE"):
        raise MutationGateRejected("UNSUPPORTED_REAL_MUTATION_CLASS")
    # The local v0.23 adapter consumes the nonce in SQLite and invokes an
    # actual content swap and trusted compile-free JSON health subprocess.
    integration = _trusted_module("security_integrations_v23")
    outcome = integration.authorized_local_canary(
        ledger, approval_token, approval_key, actor, active, candidate,
        manifest, manifest_signature, manifest_key,
        inject_failure=inject_failure)
    if (type(outcome) is not dict or
            outcome.get("status") != "APPROVAL_GATED_LOCAL_CANARY_REHEARSAL" or
            outcome.get("approval_consumed") is not True):
        raise MutationGateRejected("MUTATION_ADAPTER_DID_NOT_CONFIRM")
    return {"status": "SCOPED_ONE_USE_LOCAL_MUTATION_REHEARSAL",
            "action": "BINARY_RELEASE", "scope_sha256": hashlib.sha256(
                _canonical(scope)).hexdigest(),
            "scope_signature_verified": True, "nonce_consumed": True,
            "mutation_performed": outcome["canary_status"] == "CANARY_HEALTH_PASS_LOCAL_ONLY",
            "canary_status": outcome["canary_status"],
            "automatic_rollback_verified": outcome["automatic_rollback_verified"],
            "source_code_executed": False, "production_release_qualified": False,
            "all_rust_mutations_covered": False,
            "human_identity_independently_verified": False,
            "external_approval_service_verified": False}
