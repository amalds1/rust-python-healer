"""Local, one-use HMAC intent gate for risky actions; performs NO mutation.

This is a *component*, not proof of human identity or completed authorization:
operator keys must be independently protected, the actual mutation must check
the artifact hashes again at execution time, and Rust action paths must call
this gate BEFORE changing a source file, installing a package or releasing a
binary. Without those integrations F239 remains PARTIAL.
"""

import argparse
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from urllib.parse import quote


MAX_INPUT_BYTES = 32_768
MAX_DATABASE_BYTES = 10_000_000
MAX_TOKEN_LIFETIME = 300
MAX_CLOCK_SKEW = 30
MAX_CONSUMED_NONCES = 100_000
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
HEX32 = re.compile(r"[a-f0-9]{32}\Z")
ACTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,95}\Z")
ACTIONS = frozenset(("SOURCE_MODIFY", "PACKAGE_INSTALL", "BINARY_RELEASE"))
TOKEN_FIELDS = frozenset((
    "schema_version", "policy_id", "nonce", "issued_at", "expires_at",
    "actor_id", "approver_id", "action", "artifact_sha256", "target_sha256",
    "signature",
))


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def checked_key(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "key_hex"}:
        raise ValueError("invalid_approval_key_schema")
    if data["schema_version"] != 1 or not isinstance(data["key_hex"], str) or not HEX64.fullmatch(data["key_hex"]):
        raise ValueError("invalid_approval_key")
    return bytes.fromhex(data["key_hex"])


def unsigned_token(token):
    return {field: token[field] for field in sorted(TOKEN_FIELDS - {"signature"})}


def sign_for_test(token, key):
    """Fixture-only signing; production approvals need external human signer."""
    return hmac.new(checked_key(key), canonical(unsigned_token(token)),
                    hashlib.sha256).hexdigest()


def checked_context(actor_id, action, artifact_sha256, target_sha256):
    if not isinstance(actor_id, str) or not ACTOR.fullmatch(actor_id):
        raise ValueError("invalid_request_actor")
    if action not in ACTIONS:
        raise ValueError("invalid_risky_action")
    for value in (artifact_sha256, target_sha256):
        if not isinstance(value, str) or not HEX64.fullmatch(value):
            raise ValueError("invalid_request_artifact_hash")
    return {"actor_id": actor_id, "action": action,
            "artifact_sha256": artifact_sha256, "target_sha256": target_sha256}


def checked_token(token, key, context, now):
    if not isinstance(token, dict) or set(token) != TOKEN_FIELDS:
        raise ValueError("invalid_approval_token_structure")
    if token["schema_version"] != 1 or token["policy_id"] != "human-v1":
        raise ValueError("unsupported_approval_policy")
    if not isinstance(token["nonce"], str) or not HEX32.fullmatch(token["nonce"]):
        raise ValueError("invalid_approval_nonce")
    for name in ("actor_id", "approver_id"):
        if not isinstance(token[name], str) or not ACTOR.fullmatch(token[name]):
            raise ValueError("invalid_approval_identity")
    if token["actor_id"] == token["approver_id"]:
        # The signer/approver must not be the same named requester.
        raise ValueError("self_approval_refused")
    if token["action"] not in ACTIONS:
        raise ValueError("invalid_token_action")
    for name in ("artifact_sha256", "target_sha256"):
        if not isinstance(token[name], str) or not HEX64.fullmatch(token[name]):
            raise ValueError("invalid_token_artifact_hash")
    if type(token["issued_at"]) is not int or type(token["expires_at"]) is not int:
        raise ValueError("invalid_approval_timestamp")
    if not 0 < token["issued_at"] < token["expires_at"] < 10**11:
        raise ValueError("invalid_approval_window")
    if token["expires_at"] - token["issued_at"] > MAX_TOKEN_LIFETIME:
        raise ValueError("approval_window_too_long")
    if not isinstance(token["signature"], str) or not HEX64.fullmatch(token["signature"]):
        raise ValueError("invalid_approval_signature")
    if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
        raise ValueError("invalid_gate_clock")
    # Explicitly compare all context fields: a valid token for one artifact,
    # actor or action cannot authorize any other operation.
    if any(token[name] != context[name] for name in context):
        raise ValueError("approval_context_mismatch")
    expected = hmac.new(key, canonical(unsigned_token(token)), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, token["signature"]):
        raise ValueError("approval_signature_invalid")
    if now < token["issued_at"] - MAX_CLOCK_SKEW:
        raise ValueError("approval_not_yet_valid")
    if now >= token["expires_at"]:
        raise ValueError("approval_expired")
    return token


def guarded_path(path, create):
    target = Path(path)
    if target.is_symlink():
        raise ValueError("approval_ledger_symlink_refused")
    if target.exists():
        info = target.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_DATABASE_BYTES:
            raise ValueError("approval_ledger_file_refused")
    elif not create:
        raise ValueError("approval_ledger_missing")
    elif not target.parent.is_dir() or target.parent.is_symlink():
        raise ValueError("approval_ledger_parent_refused")
    return target


def open_ledger(path, create):
    target = guarded_path(path, create)
    if create:
        connection = sqlite3.connect(str(target), timeout=5, isolation_level=None)
    else:
        connection = sqlite3.connect("file:" + quote(str(target.resolve()), safe="/") +
                                     "?mode=ro", uri=True, timeout=5)
        connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA busy_timeout=5000")
    return connection


def install_schema(connection):
    connection.execute("""CREATE TABLE IF NOT EXISTS consumed_approvals (
        nonce TEXT PRIMARY KEY,
        intent_sha256 TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        action TEXT NOT NULL,
        artifact_sha256 TEXT NOT NULL,
        target_sha256 TEXT NOT NULL,
        consumed_at INTEGER NOT NULL
    )""")
    connection.execute("""CREATE TRIGGER IF NOT EXISTS approval_no_update
        BEFORE UPDATE ON consumed_approvals
        BEGIN SELECT RAISE(ABORT, 'approval_ledger_immutable'); END""")
    connection.execute("""CREATE TRIGGER IF NOT EXISTS approval_no_delete
        BEFORE DELETE ON consumed_approvals
        BEGIN SELECT RAISE(ABORT, 'approval_ledger_immutable'); END""")


def consume(ledger_path, token, key_data, actor_id, action,
            artifact_sha256, target_sha256, now=None):
    """Consume a previously signed human-intent token exactly once.

    Does NOT perform the approved action or guarantee atomically pairing the
    SQLite nonce commit with an external file/package/binary mutation.
    """
    key = checked_key(key_data)
    context = checked_context(actor_id, action, artifact_sha256, target_sha256)
    current_time = time.time() if now is None else now
    checked_token(token, key, context, current_time)
    connection = open_ledger(ledger_path, True)
    try:
        connection.execute("BEGIN IMMEDIATE")
        install_schema(connection)
        row = connection.execute("SELECT intent_sha256 FROM consumed_approvals WHERE nonce=?",
                                 (token["nonce"],)).fetchone()
        if row is not None:
            raise ValueError("approval_nonce_replay_refused")
        count = connection.execute("SELECT COUNT(*) FROM consumed_approvals").fetchone()[0]
        if count >= MAX_CONSUMED_NONCES:
            raise ValueError("approval_ledger_quota_exceeded")
        fingerprint = digest(unsigned_token(token))
        connection.execute(
            "INSERT INTO consumed_approvals (nonce,intent_sha256,actor_id,action,"
            "artifact_sha256,target_sha256,consumed_at) VALUES (?,?,?,?,?,?,?)",
            (token["nonce"], fingerprint, actor_id, action, artifact_sha256,
             target_sha256, int(current_time)))
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    return {"schema_version": 1,
            "status": "APPROVAL_CONSUMED_ACTION_NOT_PERFORMED",
            "approved_action": action,
            "actor_id": actor_id,
            "intent_sha256": fingerprint,
            "artifact_sha256": artifact_sha256,
            "target_sha256": target_sha256,
            "nonce_consumed": True,
            "expires_at": token["expires_at"],
            "source_executed": False,
            "mutation_performed": False,
            "release_authorized_by_this_tool": False,
            "human_identity_independently_verified": False,
            "note": "Operator-signed intent only; Rust action must enforce this gate "
                    "and recheck hashes at mutation time"}


def read_json(path):
    target = Path(path)
    if target.is_symlink():
        raise ValueError("approval_input_symlink_refused")
    descriptor = os.open(str(target), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_INPUT_BYTES:
            raise ValueError("approval_input_not_unique_bounded_file")
        raw = stream.read(MAX_INPUT_BYTES + 1)
        after = os.fstat(stream.fileno())
    if (len(raw) > MAX_INPUT_BYTES or
            (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) !=
            (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns)):
        raise ValueError("approval_input_changed_or_oversized")

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_approval_json_key")
            result[key] = value
        return result

    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                      parse_constant=lambda _:
                      (_ for _ in ()).throw(ValueError("invalid_json_number")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--token", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--target-sha256", required=True)
    args = parser.parse_args()
    try:
        result = consume(args.ledger, read_json(args.token), read_json(args.key_file),
                         args.actor, args.action, args.artifact_sha256,
                         args.target_sha256)
        print(json.dumps(result))
    except (ValueError, OSError, TypeError, KeyError, sqlite3.Error) as exc:
        reason = str(exc)
        if not re.fullmatch(r"[a-z0-9_]+", reason):
            reason = "approval_denied_closed"
        print(json.dumps({"status": "DENIED", "reason": reason,
                          "mutation_performed": False,
                          "human_identity_independently_verified": False}))
        raise SystemExit(2)


if __name__ == "__main__":
    main()
