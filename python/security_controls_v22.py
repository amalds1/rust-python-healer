"""Fail-closed, offline, narrowly scoped hardening for F105/F201/F203/F207/F208/F210.

No arbitrary Python source is executed.  A descriptor-bound scanner verifies
regular files, the threat register does not self-attest an external audit,
untrusted text stays inert data, and sys.addaudithook is observability ONLY.
This is not an OS sandbox, complete confidentiality proof, or generic tool policy.
"""

import argparse
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


MAX_PATH_DEPTH = 16
MAX_SCAN_FILES = 512
MAX_SCAN_BYTES = 16_000_000
MAX_SOURCE_BYTES = 1_000_000
MAX_UNTRUSTED_BYTES = 1_000_000
THREAT_DOMAINS = frozenset(("python_code", "packages", "ai_tooling", "updater"))
THREAT_STATES = frozenset(("OPEN", "MITIGATED_WITH_LOCAL_EVIDENCE"))
SEVERITIES = frozenset(("LOW", "MEDIUM", "HIGH", "CRITICAL"))
EVENT_KINDS = frozenset(("compile", "scan", "repair", "update", "dependency"))
EVENT_OUTCOMES = frozenset(("PASS", "FAIL", "NOT_RUN", "BLOCKED"))
SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
THREAT_ID = re.compile(r"[A-Z][A-Z0-9_]{2,47}\Z", re.ASCII)
MINOR = re.compile(r"3\.(?:9|1[0-5])\Z", re.ASCII)


class SecurityPolicyRejected(ValueError):
    """A static policy boundary refused ambiguous input."""


def _windows_security():
    embedded = globals().get("_RPH_WINDOWS_SECURITY")
    if embedded is not None:
        return embedded
    spec = importlib.util.spec_from_file_location("rph_windows_security", Path(__file__).with_name("windows_descriptor_security_v029.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _bounded_json_data(value, depth=0, budget=None, ancestors=None):
    """Never call a caller-defined __str__/__iter__/__json__ in log handling."""
    if budget is None:
        budget = [0]
    if ancestors is None:
        ancestors = set()
    budget[0] += 1
    if depth > 8 or budget[0] > 512:
        raise SecurityPolicyRejected("DIAGNOSTIC_STRUCTURE_BUDGET")
    if value is None or type(value) in (bool, int, float):
        return value
    if type(value) is str:
        if len(value) > MAX_UNTRUSTED_BYTES:
            raise SecurityPolicyRejected("DIAGNOSTIC_TEXT_BUDGET")
        return value
    if type(value) not in (dict, list):
        raise SecurityPolicyRejected("DIAGNOSTIC_UNTRUSTED_OBJECT")
    if id(value) in ancestors:
        raise SecurityPolicyRejected("DIAGNOSTIC_CYCLE")
    ancestors.add(id(value))
    try:
        if type(value) is list:
            return [_bounded_json_data(row, depth + 1, budget, ancestors) for row in value]
        if any(type(key) is not str for key in value):
            raise SecurityPolicyRejected("DIAGNOSTIC_INVALID_KEY")
        return {key: _bounded_json_data(row, depth + 1, budget, ancestors)
                for key, row in value.items()}
    finally:
        ancestors.remove(id(value))


def _same_inode(a, b):
    return (a.st_dev, a.st_ino, a.st_mode) == (b.st_dev, b.st_ino, b.st_mode)


def _assert_descriptor_platform():
    if (os.name != "posix" or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_DIRECTORY") or os.open not in os.supports_dir_fd
            or os.stat not in os.supports_dir_fd):
        raise SecurityPolicyRejected("NO_SAFE_DIRECTORY_DESCRIPTOR_PLATFORM")


def _name(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 190 or value in (".", "..")
            or any(x in value for x in ("/", "\\", ":", "\x00"))
            or any(ord(x) < 32 for x in value)):
        raise SecurityPolicyRejected("UNSAFE_RELATIVE_COMPONENT")
    return value


def _components(relative):
    if not isinstance(relative, str) or not relative or relative.startswith("/"):
        raise SecurityPolicyRejected("UNSAFE_RELATIVE_PATH")
    pieces = relative.split("/")
    if len(pieces) > MAX_PATH_DEPTH:
        raise SecurityPolicyRejected("PATH_DEPTH_LIMIT")
    return tuple(_name(part) for part in pieces)


def _open_directory(parent_fd, name, root_dev):
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(before.st_mode) or before.st_dev != root_dev:
        raise SecurityPolicyRejected("UNSAFE_DIRECTORY_OR_CROSS_DEVICE")
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                 getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
    after = os.fstat(fd)
    if not _same_inode(before, after) or after.st_dev != root_dev:
        os.close(fd)
        raise SecurityPolicyRejected("DIRECTORY_CHANGED")
    return fd


def _open_root(root):
    _assert_descriptor_platform()
    root = Path(root)
    try:
        before = root.lstat()
        if not stat.S_ISDIR(before.st_mode):
            raise SecurityPolicyRejected("UNSAFE_PROJECT_ROOT")
        fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                     getattr(os, "O_CLOEXEC", 0))
        after = os.fstat(fd)
        if not _same_inode(before, after):
            os.close(fd)
            raise SecurityPolicyRejected("ROOT_CHANGED")
    except SecurityPolicyRejected:
        raise
    except (OSError, ValueError, TypeError):
        raise SecurityPolicyRejected("UNSAFE_PROJECT_ROOT") from None
    return root, fd, after


def _read_regular(dirfd, name, root_dev, max_bytes, race_hook=None):
    before = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
            before.st_dev != root_dev or before.st_size > max_bytes):
        raise SecurityPolicyRejected("UNSAFE_FILE_OR_HARDLINK")
    if race_hook is not None:
        race_hook()
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                 getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0),
                 dir_fd=dirfd)
    try:
        opened = os.fstat(fd)
        if not _same_inode(before, opened) or opened.st_nlink != 1:
            raise SecurityPolicyRejected("FILE_REPLACED_BEFORE_OPEN")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            payload = stream.read(max_bytes + 1)
        after = os.fstat(fd)
        if (len(payload) > max_bytes or not _same_inode(before, after)
                or before.st_size != after.st_size or
                before.st_mtime_ns != after.st_mtime_ns):
            raise SecurityPolicyRejected("FILE_CHANGED_DURING_READ")
        return payload
    finally:
        os.close(fd)


def read_project_file(root, relative, max_bytes=MAX_SOURCE_BYTES, race_hook=None):
    """No-follow and no-hardlink read using directory descriptors, not path joins."""
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_SOURCE_BYTES:
        raise SecurityPolicyRejected("FILE_BYTE_LIMIT_INVALID")
    pieces = _components(relative)
    if os.name == "nt":
        try:
            return _windows_security().read_project_file(root, pieces, max_bytes, race_hook)
        except (OSError, ValueError) as error:
            reason = str(error)
            if reason == "blob_not_unique_regular_bounded_file":
                reason = "UNSAFE_FILE_OR_HARDLINK"
            raise SecurityPolicyRejected(reason) from None
    base, rootfd, rootstat = _open_root(root)
    opened = [rootfd]
    try:
        for part in pieces[:-1]:
            opened.append(_open_directory(opened[-1], part, rootstat.st_dev))
        result = _read_regular(opened[-1], pieces[-1], rootstat.st_dev,
                               max_bytes, race_hook)
        if not _same_inode(base.lstat(), rootstat):
            raise SecurityPolicyRejected("ROOT_REPLACED_DURING_READ")
        return result
    except SecurityPolicyRejected:
        raise
    except (OSError, ValueError, TypeError):
        raise SecurityPolicyRejected("FILE_IO_REJECTED") from None
    finally:
        for fd in reversed(opened):
            os.close(fd)


def scan_python_project(root, max_files=MAX_SCAN_FILES, max_bytes=MAX_SCAN_BYTES):
    """Descriptor-relative scan that never follows an external symlink."""
    if (type(max_files) is not int or not 1 <= max_files <= MAX_SCAN_FILES or
            type(max_bytes) is not int or not 1 <= max_bytes <= MAX_SCAN_BYTES):
        raise SecurityPolicyRejected("SCAN_BUDGET_INVALID")
    if os.name == "nt":
        try:
            return _windows_security().scan_project(root, max_files, max_bytes, MAX_PATH_DEPTH)
        except (OSError, ValueError) as error:
            raise SecurityPolicyRejected(str(error)) from None
    base, rootfd, rootstat = _open_root(root)
    summary = {"status": "SAFE_DESCRIPTOR_SCAN_LOCAL_ONLY", "python_files": 0,
               "bytes_scanned": 0, "skipped_symlinks": 0,
               "no_external_symlink_followed": True,
               "unknown_source_executed": False, "cross_platform_proven": False}

    def walk(fd, depth):
        if depth > MAX_PATH_DEPTH:
            raise SecurityPolicyRejected("PATH_DEPTH_LIMIT")
        entries = os.listdir(fd)
        if len(entries) > max_files * 4:
            raise SecurityPolicyRejected("SCAN_ENTRY_BUDGET")
        for entry in sorted(entries):
            _name(entry)
            if entry in (".git", ".venv", "venv", "__pycache__", "build", "target"):
                continue
            before = os.stat(entry, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                summary["skipped_symlinks"] += 1
                continue
            if stat.S_ISDIR(before.st_mode):
                childfd = _open_directory(fd, entry, rootstat.st_dev)
                try:
                    walk(childfd, depth + 1)
                finally:
                    os.close(childfd)
            elif stat.S_ISREG(before.st_mode) and entry.endswith(".py"):
                summary["python_files"] += 1
                if summary["python_files"] > max_files:
                    raise SecurityPolicyRejected("SCAN_FILE_BUDGET")
                remaining = max_bytes - summary["bytes_scanned"]
                data = _read_regular(fd, entry, rootstat.st_dev,
                                     min(MAX_SOURCE_BYTES, remaining))
                summary["bytes_scanned"] += len(data)
            elif not stat.S_ISREG(before.st_mode):
                raise SecurityPolicyRejected("UNSAFE_PROJECT_ENTRY")

    try:
        walk(rootfd, 0)
        if not _same_inode(base.lstat(), rootstat):
            raise SecurityPolicyRejected("ROOT_REPLACED_DURING_SCAN")
        return summary
    except SecurityPolicyRejected:
        raise
    except (OSError, ValueError, TypeError):
        raise SecurityPolicyRejected("SCAN_IO_REJECTED") from None
    finally:
        os.close(rootfd)


def _model_body(python_minor, revision, threats):
    if type(python_minor) is not str or not MINOR.fullmatch(python_minor):
        raise SecurityPolicyRejected("THREAT_PYTHON_MINOR_INVALID")
    if type(revision) is not int or revision < 1:
        raise SecurityPolicyRejected("THREAT_REVISION_INVALID")
    if type(threats) is not list or not 4 <= len(threats) <= 64:
        raise SecurityPolicyRejected("THREAT_COUNT_INVALID")
    normalized = []
    seen = set()
    domains = set()
    for row in threats:
        if type(row) is not dict or set(row) != {
                "id", "domain", "severity", "state", "mitigation", "evidence_sha256"}:
            raise SecurityPolicyRejected("THREAT_SCHEMA_INVALID")
        tid, domain, severity, state = (row[k] for k in
                                        ("id", "domain", "severity", "state"))
        if (type(tid) is not str or type(domain) is not str or
                type(severity) is not str or type(state) is not str or
                not THREAT_ID.fullmatch(tid)
                or tid in seen or domain not in THREAT_DOMAINS
                or severity not in SEVERITIES or state not in THREAT_STATES):
            raise SecurityPolicyRejected("THREAT_ENUM_OR_DUPLICATE")
        seen.add(tid)
        domains.add(domain)
        mitigation = row["mitigation"]
        evidence = row["evidence_sha256"]
        if (type(mitigation) is not str or not 3 <= len(mitigation) <= 120
                or not mitigation.isascii() or not all(32 <= ord(c) <= 126 for c in mitigation)):
            raise SecurityPolicyRejected("THREAT_MITIGATION_INVALID")
        if state == "MITIGATED_WITH_LOCAL_EVIDENCE":
            if type(evidence) is not str or not SHA.fullmatch(evidence):
                raise SecurityPolicyRejected("THREAT_EVIDENCE_MISSING")
        elif evidence is not None:
            raise SecurityPolicyRejected("OPEN_THREAT_CANNOT_CLAIM_EVIDENCE")
        normalized.append({k: row[k] for k in sorted(row)})
    if domains != THREAT_DOMAINS:
        raise SecurityPolicyRejected("THREAT_DOMAIN_MISSING")
    return {"schema": 1, "python_minor": python_minor,
            "revision": revision, "threats": sorted(normalized, key=lambda x: x["id"]),
            "independent_security_audit": False, "production_qualified": False}


def versioned_threatmodel(python_minor, revision, threats, previous=None):
    """Versioned, strict local threat ledger; no implicit mitigation promotion."""
    body = _model_body(python_minor, revision, threats)
    if previous is not None:
        if (type(previous) is not dict or previous.get("schema") != 1 or
                previous.get("python_minor") != python_minor or
                previous.get("revision") != revision - 1 or
                previous.get("sha256") != _digest(json.dumps(
                    {k: previous[k] for k in ("schema", "python_minor", "revision", "threats",
                                           "independent_security_audit", "production_qualified")},
                    sort_keys=True, separators=(",", ":")).encode("ascii"))):
            raise SecurityPolicyRejected("PREVIOUS_THREAT_REGISTER_UNVERIFIED")
        old = {r["id"]: r for r in previous["threats"]}
        new = {r["id"]: r for r in body["threats"]}
        if not set(old).issubset(new):
            raise SecurityPolicyRejected("THREAT_REMOVED_DURING_REVISION")
        for tid, row in old.items():
            if row["state"] == "OPEN" and new[tid]["state"] != "OPEN":
                if new[tid]["evidence_sha256"] is None:
                    raise SecurityPolicyRejected("THREAT_PROMOTION_WITHOUT_EVIDENCE")
    body["sha256"] = _digest(json.dumps(body, sort_keys=True,
                                       separators=(",", ":")).encode("ascii"))
    return body


def _validate_snapshot(snapshot):
    if type(snapshot) is not dict or set(snapshot) != {
            "schema", "python_minor", "revision", "threats",
            "independent_security_audit", "production_qualified", "sha256"}:
        raise SecurityPolicyRejected("THREAT_SNAPSHOT_SCHEMA_INVALID")
    if (snapshot["schema"] != 1 or snapshot["independent_security_audit"] is not False
            or snapshot["production_qualified"] is not False):
        raise SecurityPolicyRejected("THREAT_SNAPSHOT_FALSE_ATTESTATION")
    regenerated = versioned_threatmodel(snapshot["python_minor"],
                                       snapshot["revision"], snapshot["threats"])
    if regenerated != snapshot:
        raise SecurityPolicyRejected("THREAT_SNAPSHOT_HASH_OR_CONTENT_MISMATCH")
    return regenerated


def write_threat_snapshot(folder, name, snapshot):
    """Persist a private, immutable-by-creation JSON snapshot, never overwrite."""
    validated = _validate_snapshot(snapshot)
    _name(name)
    if not name.endswith(".json"):
        raise SecurityPolicyRejected("THREAT_FILE_EXTENSION_INVALID")
    if os.name == "nt":
        payload = (json.dumps(validated, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        try:
            durability = _windows_security().write_private_snapshot(folder, name, payload)
        except (OSError, ValueError) as error:
            label = "THREAT_DIRECTORY_MUST_BE_PRIVATE" if "privacy" in str(error) or "windows_" in str(error) else str(error)
            raise SecurityPolicyRejected(label) from None
        return {"status": "LOCAL_THREAT_SNAPSHOT_PERSISTED", "sha256": validated["sha256"],
                "local_only": True, "external_audit_attested": False, **durability}
    _assert_descriptor_platform()
    directory = Path(folder)
    root, rootfd, rootstat = _open_root(directory)
    try:
        if rootstat.st_mode & 0o077:
            raise SecurityPolicyRejected("THREAT_DIRECTORY_MUST_BE_PRIVATE")
        payload = (json.dumps(validated, sort_keys=True,
                              separators=(",", ":")) + "\n").encode("ascii")
        if len(payload) > 64_000:
            raise SecurityPolicyRejected("THREAT_SNAPSHOT_SIZE_BUDGET")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=rootfd)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(rootfd)
        if not _same_inode(root.lstat(), rootstat):
            raise SecurityPolicyRejected("THREAT_DIRECTORY_CHANGED")
        return {"status": "LOCAL_THREAT_SNAPSHOT_PERSISTED",
                "sha256": validated["sha256"], "local_only": True,
                "external_audit_attested": False}
    except SecurityPolicyRejected:
        raise
    except (OSError, ValueError):
        raise SecurityPolicyRejected("THREAT_SNAPSHOT_WRITE_REJECTED") from None
    finally:
        os.close(rootfd)


def load_threat_snapshot(folder, name):
    _name(name)
    if not name.endswith(".json"):
        raise SecurityPolicyRejected("THREAT_FILE_EXTENSION_INVALID")
    payload = read_project_file(folder, name, max_bytes=64_000)
    try:
        decoded = json.loads(payload)
    except (UnicodeError, ValueError):
        raise SecurityPolicyRejected("THREAT_SNAPSHOT_UNREADABLE") from None
    return _validate_snapshot(decoded)


def redact_diagnostic(event):
    """Emit only fixed-schema fields; discard ALL unbounded freeform strings."""
    if type(event) is not dict:
        raise SecurityPolicyRejected("DIAGNOSTIC_INPUT_INVALID")
    safe = _bounded_json_data(event)
    kind, outcome = safe.get("kind"), safe.get("outcome")
    if (type(kind) is not str or type(outcome) is not str
            or kind not in EVENT_KINDS or outcome not in EVENT_OUTCOMES):
        raise SecurityPolicyRejected("DIAGNOSTIC_CLASSIFICATION_INVALID")
    try:
        input_payload = json.dumps(safe, sort_keys=True, separators=(",", ":"),
                                   allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError):
        raise SecurityPolicyRejected("DIAGNOSTIC_SERIALIZATION_INVALID") from None
    if len(input_payload) > MAX_UNTRUSTED_BYTES:
        raise SecurityPolicyRejected("DIAGNOSTIC_INPUT_BUDGET")
    return {"status": "REDACTED_DATA_ONLY", "kind": kind, "outcome": outcome,
            "sensitive_fields_emitted": False,
            "all_untrusted_values_removed": True,
            "event_sha256": _digest(input_payload),
            "unverified_total_log_privacy": True}


def isolated_untrusted_evidence(payload, expected_sha256, channel="documentation"):
    """Treat untrusted documentation/tool replies as hash-pinned INERT bytes."""
    if (type(payload) is not bytes or not 1 <= len(payload) <= MAX_UNTRUSTED_BYTES
            or type(expected_sha256) is not str or not SHA.fullmatch(expected_sha256)
            or type(channel) is not str or channel not in (
                "documentation", "tool_output", "package_metadata")):
        raise SecurityPolicyRejected("UNTRUSTED_EVIDENCE_INVALID")
    actual = _digest(payload)
    if not hmac.compare_digest(actual, expected_sha256):
        raise SecurityPolicyRejected("UNTRUSTED_EVIDENCE_HASH_MISMATCH")
    return {"status": "PINNED_DATA_ONLY_NEVER_INSTRUCTIONS",
            "channel": channel, "source_sha256": actual,
            "bytes": len(payload), "instructions_executed": False,
            "tools_invoked_from_evidence": False, "raw_evidence_disclosed": False,
            "no_general_llm_prompt_injection_proof": True}


def approve_trusted_proposal(proposal_id, source_sha256, signature, key):
    """Only a separate operator HMAC, NEVER source text, may approve review."""
    if (type(proposal_id) is not str or not THREAT_ID.fullmatch(proposal_id)
            or type(source_sha256) is not str or not SHA.fullmatch(source_sha256)
            or type(key) is not bytes or len(key) < 24 or
            type(signature) is not str or not SHA.fullmatch(signature)):
        raise SecurityPolicyRejected("APPROVAL_INVALID")
    canonical = (proposal_id + ":" + source_sha256).encode("ascii")
    expected = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise SecurityPolicyRejected("APPROVAL_NOT_TRUSTED")
    return {"status": "LOCAL_REVIEW_APPROVED_NOT_RELEASED",
            "proposal_id": proposal_id, "source_sha256": source_sha256,
            "unknown_code_executed": False, "release_authorized": False}


AUDIT_CHILD = (
    "import json,os,sys\n"
    "seen={}\n"
    "def hook(name,args):\n"
    "    if name in ('compile','exec','open'):\n"
    "        seen[name]=min(seen.get(name,0)+1,1000)\n"
    "sys.addaudithook(hook)\n"
    "fixed=compile('21+21','<immutable-trusted-audit-fixture>','eval')\n"
    "result=eval(fixed)\n"
    "with open(os.devnull,'rb') as handle: handle.read(1)\n"
    "print(json.dumps({'events':seen,'fixture_result':result}))\n"
)


def observe_trusted_audit_events(python=sys.executable, enforce_as_sandbox=False):
    """Observe CPython audit event names in a child, never enforce security."""
    if enforce_as_sandbox:
        raise SecurityPolicyRejected("AUDIT_HOOK_IS_NOT_A_SANDBOX")
    if not isinstance(python, str) or not python or len(python) > 1024:
        raise SecurityPolicyRejected("PYTHON_INTERPRETER_INVALID")
    try:
        completed = subprocess.run([python, "-I", "-S", "-B", "-c", AUDIT_CHILD],
                                   capture_output=True, timeout=6, check=False)
        if completed.returncode != 0 or len(completed.stdout) > 4096:
            raise SecurityPolicyRejected("AUDIT_FIXTURE_PROCESS_FAILED")
        report = json.loads(completed.stdout)
        if (report.get("fixture_result") != 42 or not isinstance(report.get("events"), dict)
                or any(type(count) is not int or count < 1 or count > 1000
                       for count in report["events"].values())
                or not all(report["events"].get(name, 0) >= 1
                           for name in ("compile", "exec", "open"))):
            raise SecurityPolicyRejected("AUDIT_FIXTURE_EVENTS_MISSING")
    except SecurityPolicyRejected:
        raise
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise SecurityPolicyRejected("AUDIT_FIXTURE_PROCESS_FAILED") from None
    return {"status": "AUDIT_HOOK_OBSERVED_TRUSTED_FIXTURE_ONLY",
            "event_name_counts": report["events"], "hook_args_recorded": False,
            "security_boundary": False, "sandbox_claim": False,
            "unknown_project_source_executed": False,
            "independent_bypass_test_proven": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("audit", "scan"), default="audit")
    parser.add_argument("--root")
    args = parser.parse_args(argv)
    try:
        if args.mode == "audit":
            response = observe_trusted_audit_events()
        elif not args.root:
            raise SecurityPolicyRejected("ROOT_REQUIRED")
        else:
            response = scan_python_project(args.root)
    except SecurityPolicyRejected as error:
        print(json.dumps({"status": "NOT_VERIFIED", "reason": str(error),
                          "unknown_code_executed": False}, sort_keys=True))
        return 2
    print(json.dumps(response, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
