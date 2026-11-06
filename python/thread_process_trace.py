"""Trusted local thread/process trace probes and offline span correlation.

Only fixed local probe programs run.  No external service, network request,
queue, arbitrary script, or untrusted code is executed.  A traceparent-like
v00 format is validated, but no remote participant or span authenticity is
claimed.  Cross-service correlation accepts explicit local event records.
"""

import contextvars
import json
import os
import re
import secrets
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

TRACE = re.compile(r"00-([a-f0-9]{32})-([a-f0-9]{16})-([a-f0-9]{2})\Z")
HEX16 = re.compile(r"[a-f0-9]{16}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
MAX_EVENTS = 128
MAX_CHILD_SECONDS = 5
CURRENT_CONTEXT = contextvars.ContextVar("rust_python_healer_trusted_trace", default=None)

TRUSTED_CHILD_PROBE = '''import json, os, re, secrets, sys
raw = os.environ.get("RUST_HEALER_TRACEPARENT", "")
match = re.fullmatch(r"00-([a-f0-9]{32})-([a-f0-9]{16})-([a-f0-9]{2})", raw)
valid = bool(match and int(match.group(1), 16) and int(match.group(2), 16))
child_span = secrets.token_hex(8) if valid else None
result = {"context_received": valid,
          "trace_id": match.group(1) if valid else None,
          "parent_span_id": match.group(2) if valid else None,
          "child_span_id": child_span,
          "python_version": "%d.%d" % sys.version_info[:2],
          "source_executed": False}
print(json.dumps(result, sort_keys=True))
'''


def _with_native_windows_root(environment):
    """Keep the caller's fixed allowlist; obtain Windows startup root from OS."""
    if type(environment) is not dict or any(type(k) is not str or type(v) is not str for k,v in environment.items()):
        raise ValueError("invalid_fixed_child_environment")
    result=dict(environment)
    if os.name=="nt":
        import ctypes
        get_root=ctypes.WinDLL("kernel32",use_last_error=True).GetSystemWindowsDirectoryW
        get_root.argtypes=[ctypes.c_wchar_p,ctypes.c_uint]
        get_root.restype=ctypes.c_uint
        buffer=ctypes.create_unicode_buffer(32768)
        size=get_root(buffer,len(buffer))
        if not 0<size<len(buffer):
            raise OSError("native_system_windows_directory_unavailable")
        result={k:v for k,v in result.items() if k.casefold() not in ("systemroot","windir")}
        result["SystemRoot"]=buffer.value
    return result


def parse_traceparent(value):
    if not isinstance(value, str) or len(value) != 55:
        raise ValueError("invalid_traceparent_format")
    matched = TRACE.fullmatch(value)
    if not matched:
        raise ValueError("invalid_traceparent_format")
    trace_id, span_id, flags = matched.groups()
    if not int(trace_id, 16) or not int(span_id, 16):
        raise ValueError("zero_trace_or_span_id_forbidden")
    # We currently support sampled/no-sampled v00 flags, not other future bits.
    if flags not in ("00", "01"):
        raise ValueError("unsupported_trace_flags")
    return {"trace_id": trace_id, "span_id": span_id, "flags": flags}


def traceparent(trace_id, span_id, flags="01"):
    value = f"00-{trace_id}-{span_id}-{flags}"
    parse_traceparent(value)
    return value


def new_root():
    return traceparent(secrets.token_hex(16), secrets.token_hex(8))


def child_context(parent):
    origin = parse_traceparent(parent)
    while True:
        child_span = secrets.token_hex(8)
        if child_span != origin["span_id"]:
            return traceparent(origin["trace_id"], child_span, origin["flags"])


def probe_trusted_child(parent, python_executable=None):
    """Actual CPython subprocess receives only an explicit tracing env value."""
    parent_info = parse_traceparent(parent)
    executable = os.fspath(python_executable or sys.executable)
    try:
        completed = subprocess.run(
            [executable, "-I", "-S", "-c", TRUSTED_CHILD_PROBE],
            capture_output=True, check=False, timeout=MAX_CHILD_SECONDS,
            env=_with_native_windows_root({"PATH": os.defpath, "PYTHONIOENCODING": "utf-8",
                 "RUST_HEALER_TRACEPARENT": parent}))
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("trusted_child_unavailable_or_timed_out") from None
    if completed.returncode or len(completed.stdout) > 2048 or len(completed.stderr) > 2048:
        raise ValueError("trusted_child_probe_failed")
    try:
        evidence = json.loads(completed.stdout)
    except (ValueError, UnicodeError):
        raise ValueError("trusted_child_invalid_response") from None
    if (not isinstance(evidence, dict) or evidence.get("context_received") is not True or
            evidence.get("trace_id") != parent_info["trace_id"] or
            evidence.get("parent_span_id") != parent_info["span_id"] or
            not isinstance(evidence.get("child_span_id"), str) or
            not HEX16.fullmatch(evidence["child_span_id"]) or
            evidence["child_span_id"] == parent_info["span_id"] or
            evidence.get("source_executed") is not False):
        raise ValueError("trusted_child_trace_mismatch")
    version = evidence.get("python_version")
    if (not isinstance(version, str) or
            not re.fullmatch(r"3\.(?:9|1[0-9]|[2-9][0-9])", version)):
        raise ValueError("trusted_child_version_invalid")
    return {"status": "TRUSTED_CHILD_CONTEXT_PROPAGATED",
            "trace_id": parent_info["trace_id"],
            "parent_span_id": parent_info["span_id"],
            "child_span_id": evidence["child_span_id"],
            "child_python_version": version,
            "source_executed": False,
            "trusted_probe_executed": True,
            "external_services_contacted": False,
            "environment_secrets_forwarded": False,
            "remote_span_authenticated": False}


def probe_trusted_thread(parent):
    """Actually copy ContextVar into a thread running only this fixed probe."""
    parse_traceparent(parent)
    token = CURRENT_CONTEXT.set(parent)
    try:
        copied = contextvars.copy_context()
        with ThreadPoolExecutor(max_workers=1) as workers:
            received = workers.submit(copied.run, CURRENT_CONTEXT.get).result(timeout=5)
    finally:
        CURRENT_CONTEXT.reset(token)
    if received != parent:
        raise ValueError("trusted_thread_context_not_propagated")
    return {"status": "TRUSTED_THREAD_CONTEXT_PROPAGATED",
            "trace_id": parse_traceparent(received)["trace_id"],
            "context_propagated": True,
            "untrusted_callback_executed": False}


class OfflineCorrelationLedger:
    """Correlate signed-format, NOT cryptographically authenticated, spans."""

    def __init__(self):
        self.events = []
        self.identifiers = set()
        self.spans = set()

    def add(self, record):
        fields = {"event_id", "stage", "service", "traceparent", "parent_span_id"}
        if not isinstance(record, dict) or set(record) != fields:
            raise ValueError("invalid_trace_event_schema")
        for key in ("event_id", "service"):
            if not isinstance(record[key], str) or not IDENTIFIER.fullmatch(record[key]):
                raise ValueError("invalid_trace_event_identity")
        if record["stage"] not in ("service", "queue", "job"):
            raise ValueError("invalid_trace_event_stage")
        parsed = parse_traceparent(record["traceparent"])
        parent = record["parent_span_id"]
        if parent is not None and (
                not isinstance(parent, str) or not HEX16.fullmatch(parent) or
                not int(parent, 16) or parent == parsed["span_id"]):
            raise ValueError("invalid_parent_span")
        if len(self.events) >= MAX_EVENTS:
            raise ValueError("trace_event_limit")
        if (record["event_id"] in self.identifiers or
                (parsed["trace_id"], parsed["span_id"]) in self.spans):
            raise ValueError("duplicate_trace_event_or_span")
        self.identifiers.add(record["event_id"])
        self.spans.add((parsed["trace_id"], parsed["span_id"]))
        self.events.append({"event_id": record["event_id"],
                            "stage": record["stage"],
                            "service": record["service"],
                            "trace_id": parsed["trace_id"],
                            "span_id": parsed["span_id"],
                            "parent_span_id": parent})

    def correlate(self):
        """Evaluate complete offline edges and cycles; never imply live network."""
        by_span = {(row["trace_id"], row["span_id"]): row for row in self.events}
        edges, orphans, cycles = [], [], []
        for row in self.events:
            parent_id = row["parent_span_id"]
            if parent_id is None:
                continue
            parent = by_span.get((row["trace_id"], parent_id))
            if parent is None:
                orphans.append(row["event_id"])
            else:
                edges.append({"parent_event": parent["event_id"],
                              "child_event": row["event_id"]})
        for row in self.events:
            visited = set()
            step = row
            while step is not None:
                marker = (step["trace_id"], step["span_id"])
                if marker in visited:
                    cycles.append(row["event_id"])
                    break
                visited.add(marker)
                step = by_span.get((step["trace_id"], step["parent_span_id"]))
        status = ("NO_TRACE_EVENTS" if not self.events else
                  "PARTIAL_OFFLINE_CORRELATION" if not orphans and not cycles else
                  "INCOMPLETE_OR_INVALID_OFFLINE_CORRELATION")
        return {"status": status,
                "events": len(self.events),
                "trace_ids": len({row["trace_id"] for row in self.events}),
                "stage_counts": {stage: sum(row["stage"] == stage for row in self.events)
                                 for stage in ("service", "queue", "job")},
                "linked_parent_child_events": sorted(edges,
                                                      key=lambda edge: edge["child_event"]),
                "orphan_events": sorted(orphans),
                "cycle_events": sorted(set(cycles)),
                "network_used": False,
                "cross_service_runtime_verified": False,
                "queue_delivery_verified": False,
                "job_execution_verified": False,
                "remote_span_authenticated": False,
                "user_source_executed": False}

