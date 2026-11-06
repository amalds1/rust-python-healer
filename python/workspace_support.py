"""F234/F249 offline agent snapshots and opt-in privacy-preserving bundles.

Read-only source snapshots use chmod + SHA256 revalidation, not OS sandboxing:
same-user agents can still change permissions. No user code is ever executed.
Support bundles accept only structured allowlisted observations; arbitrary
messages, paths, source, credentials and logs are never copied or uploaded.
"""

import hashlib
import importlib.util
from functools import lru_cache
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from types import MappingProxyType
import zipfile


MAX_SOURCE_FILE = 2_000_000
MAX_TOTAL_SOURCE = 8_000_000
MAX_AGENTS = 12
MAX_SOURCE_FILES = 64
MAX_EVENTS = 1000
MAX_BUNDLE_BYTES = 2_000_000
_AGENT = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,30}\Z", re.ASCII)
_SOURCE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,100}\Z", re.ASCII)
_CODE = re.compile(r"(?:F\d{3}|TEST_PASS|TEST_FAIL|WARN\d{3}|ERR\d{3})\Z", re.ASCII)
_PYVER = re.compile(r"3\.(?:9|1[0-5])\Z", re.ASCII)
_LEVEL = frozenset(("INFO", "WARN", "ERROR"))
_STAMP = (2020, 1, 1, 0, 0, 0)


class SnapshotError(Exception):
    pass


@lru_cache(maxsize=1)
def _windows_security():
    embedded = globals().get("_RPH_WINDOWS_SECURITY")
    if embedded is not None:
        return embedded
    spec = importlib.util.spec_from_file_location("rph_workspace_windows_security",
        Path(__file__).with_name("windows_descriptor_security_v029.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _plain_file_bytes(path, maximum):
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise SnapshotError("source_not_private_regular_file")
        if before.st_size > maximum:
            raise SnapshotError("source_limit_exceeded")
        if os.name == "nt":
            try:
                location = path.absolute()
                security = _windows_security()
                opened_root = security.Root(location.parent)
                try:
                    handle = security._open(opened_root.handles[0], location.name, False)
                    opened_root.handles.append(handle)
                    info = opened_root.blob._information(handle, False, maximum)
                    if info[0] != opened_root.identity[0]:
                        raise ValueError("cross_device_source_refused")
                    # This caller's contract permits 2 MB, while the generic
                    # project scanner's child() intentionally caps at 1 MB.
                    return opened_root.read(handle, maximum)
                finally:
                    opened_root.close()
            except (OSError, ValueError):
                raise SnapshotError("source_not_private_regular_file") from None
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                           | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise SnapshotError("source_changed_while_reading")
            content = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
        if (len(content) > maximum or (before.st_size, before.st_mtime_ns, before.st_ino)
                != (after.st_size, after.st_mtime_ns, after.st_ino)):
            raise SnapshotError("source_changed_while_reading")
        return content
    except SnapshotError:
        raise
    except (OSError, TypeError, ValueError):
        raise SnapshotError("source_unreadable") from None


def _real_directory(directory):
    try:
        info = Path(directory).lstat()
        if (not stat.S_ISDIR(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise SnapshotError("root_not_real_directory")
    except OSError:
        raise SnapshotError("root_not_real_directory") from None


class WorkspaceSession:
    """Immutable in-process digest baseline for independently copied sources."""

    def __init__(self, root, agent_names, sources):
        self.root = Path(root)
        self.agents = tuple(agent_names)
        self.baseline = MappingProxyType(dict(sources))

    def snapshot_path(self, agent, name):
        if agent not in self.agents or name not in self.baseline:
            raise SnapshotError("unknown_agent_or_source")
        return self.root / agent / "snapshot" / name

    def work_path(self, agent):
        if agent not in self.agents:
            raise SnapshotError("unknown_agent")
        return self.root / agent / "work"

    def verify(self):
        """Verify all copies, unexpected names, symlinks, hardlinks, permissions."""
        try:
            _real_directory(self.root)
            if {name for name in os.listdir(self.root)} != set(self.agents):
                raise SnapshotError("agent_workspace_inventory_changed")
            for agent in self.agents:
                agent_root = self.root / agent
                _real_directory(agent_root)
                if set(os.listdir(agent_root)) != {"snapshot", "work"}:
                    raise SnapshotError("agent_directory_inventory_changed")
                snapshot = agent_root / "snapshot"
                work = agent_root / "work"
                _real_directory(snapshot)
                _real_directory(work)
                if set(os.listdir(snapshot)) != set(self.baseline):
                    raise SnapshotError("snapshot_file_inventory_changed")
                for name, expected in self.baseline.items():
                    file = snapshot / name
                    if file.lstat().st_mode & 0o222:
                        raise SnapshotError("snapshot_not_readonly")
                    content = _plain_file_bytes(file, MAX_SOURCE_FILE)
                    if hashlib.sha256(content).hexdigest() != expected:
                        raise SnapshotError("snapshot_sha256_mismatch")
        except SnapshotError as error:
            return {"status": "INTEGRITY_FAILED", "reason": str(error),
                    "user_code_executed": False, "os_sandbox_enforced": False}
        except OSError:
            return {"status": "INTEGRITY_FAILED", "reason": "workspace_unreadable",
                    "user_code_executed": False, "os_sandbox_enforced": False}
        return {"status": "SNAPSHOTS_MATCH_BASELINE",
                "agents": len(self.agents), "source_files_per_agent": len(self.baseline),
                "user_code_executed": False, "os_sandbox_enforced": False,
                "immutability": "READ_ONLY_MODE_AND_SHA256_REVALIDATION_NOT_SANDBOX"}


def create_agent_workspaces(source_paths, agent_names, output_root):
    """Copy selected source bytes to separate agent trees. No code execution."""
    if (not isinstance(agent_names, (list, tuple)) or not 1 <= len(agent_names) <= MAX_AGENTS
            or any(not isinstance(name, str) or not _AGENT.fullmatch(name)
                   for name in agent_names) or len(set(agent_names)) != len(agent_names)):
        raise SnapshotError("invalid_agent_list")
    if (not isinstance(source_paths, (list, tuple))
            or not 1 <= len(source_paths) <= MAX_SOURCE_FILES):
        raise SnapshotError("invalid_source_list")
    _real_directory(output_root)
    files = {}
    total = 0
    for source_path in source_paths:
        file = Path(source_path)
        if not _SOURCE.fullmatch(file.name) or file.name in files:
            raise SnapshotError("invalid_or_duplicate_source_basename")
        content = _plain_file_bytes(file, MAX_SOURCE_FILE)
        total += len(content)
        if total > MAX_TOTAL_SOURCE:
            raise SnapshotError("aggregate_source_budget_exceeded")
        files[file.name] = content
    folder = Path(tempfile.mkdtemp(prefix="rph-agent-work-", dir=str(output_root)))
    digest = MappingProxyType({name: hashlib.sha256(value).hexdigest()
                               for name, value in files.items()})
    try:
        for agent in agent_names:
            agent_root = folder / agent
            agent_root.mkdir(mode=0o700)
            snapshots = agent_root / "snapshot"
            snapshots.mkdir(mode=0o700)
            (agent_root / "work").mkdir(mode=0o700)
            for name, content in files.items():
                target = snapshots / name
                with target.open("xb") as output:
                    output.write(content)
                target.chmod(0o400)
            snapshots.chmod(0o500)
    except OSError:
        # Leave a partial, clearly identifiable temp workspace for operator
        # cleanup; never recursively delete potentially concurrent agent work.
        raise SnapshotError("snapshot_creation_failed") from None
    return WorkspaceSession(folder, agent_names, digest)


def _filtered_events(events):
    if not isinstance(events, (list, tuple)) or len(events) > MAX_EVENTS:
        raise ValueError("invalid_event_list")
    clean = []
    discarded = 0
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("invalid_event")
        code = event.get("code")
        level = event.get("level")
        count = event.get("count", 1)
        version = event.get("python_version")
        if (not isinstance(code, str) or not _CODE.fullmatch(code)
                or level not in _LEVEL or type(count) is not int
                or not 0 <= count <= 1_000_000
                or (version is not None and (not isinstance(version, str)
                                             or not _PYVER.fullmatch(version)))):
            raise ValueError("unsafe_event_core_fields")
        allowed = {"code", "level", "count", "python_version"}
        discarded += len(event.keys() - allowed)
        payload = {"code": code, "level": level, "count": count}
        if version:
            payload["python_version"] = version
        clean.append(payload)
    return clean, discarded


def build_support_bundle(events, destination, opt_in=False):
    """Write deterministic *local-only* bundle iff user explicitly opts in."""
    baseline = {"telemetry_uploaded": False, "network_used": False,
                "source_content_included": False, "paths_included": False,
                "credentials_included": False}
    if opt_in is not True:
        return {**baseline, "status": "CONSENT_REQUIRED_NO_FILE_WRITTEN"}
    try:
        safe_events, dropped = _filtered_events(events)
        dest = Path(destination)
        if not _SOURCE.fullmatch(dest.name) or not dest.name.endswith(".zip"):
            raise ValueError("invalid_bundle_filename")
        _real_directory(dest.parent)
        document = json.dumps({"format": 1, "opt_in": True,
                               "events": safe_events, "redacted_fields": dropped,
                               "network_used": False, "telemetry_uploaded": False},
                              sort_keys=True, separators=(",", ":")).encode("utf-8")
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED,
                             allowZip64=False) as archive:
            for name, content in (
                    ("summary.json", document),
                    ("NOTICE.txt", b"Local opt-in diagnostic counts only; no upload or identity claims.\n")):
                info = zipfile.ZipInfo(name, _STAMP)
                info.compress_type = zipfile.ZIP_STORED
                archive.writestr(info, content)
        result = stream.getvalue()
        if len(result) > MAX_BUNDLE_BYTES:
            raise ValueError("bundle_size_limit")
        with dest.open("xb") as file:
            file.write(result)
    except (OSError, ValueError, SnapshotError, TypeError):
        return {**baseline, "status": "NOT_WRITTEN_INVALID_INPUT"}
    return {**baseline, "status": "OFFLINE_SUPPORT_BUNDLE_CREATED",
            "event_count": len(safe_events), "discarded_fields": dropped,
            "sha256": hashlib.sha256(result).hexdigest(), "bytes": len(result)}
