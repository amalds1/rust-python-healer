"""Privacy-preserving offline ExceptionGroup/TaskGroup traceback observations.

This is bounded forensic text inspection, not a debugger backend, an asyncio
task enumerator, a sandbox, or proof of the actual exception hierarchy.  The
parser never imports or executes a module named in the supplied traceback.
"""

import argparse
import ast
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

MAX_LOG_BYTES = 131_072
MAX_LINES = 2400
MAX_LINE_CHARS = 4096
MAX_GROUPS = 128
MAX_LEAVES = 512
MAX_DECLARED_CHILDREN = 10_000
SAFE_EXCEPTION_NAMES = frozenset((
    "ArithmeticError", "AssertionError", "AttributeError", "BlockingIOError",
    "BrokenPipeError", "BufferError", "ChildProcessError", "ConnectionAbortedError",
    "ConnectionError", "ConnectionRefusedError", "ConnectionResetError",
    "EOFError", "Exception", "FileExistsError", "FileNotFoundError",
    "FloatingPointError", "ImportError", "IndentationError", "IndexError",
    "InterruptedError", "IsADirectoryError", "KeyError", "KeyboardInterrupt",
    "LookupError", "MemoryError", "ModuleNotFoundError", "NameError",
    "NotADirectoryError", "NotImplementedError", "OSError", "OverflowError",
    "PermissionError", "ProcessLookupError", "RecursionError", "ReferenceError",
    "RuntimeError", "StopAsyncIteration", "StopIteration", "SyntaxError",
    "SystemError", "SystemExit", "TabError", "TimeoutError", "TypeError",
    "UnboundLocalError", "UnicodeError", "UnicodeDecodeError",
    "UnicodeEncodeError", "UnicodeTranslateError", "ValueError", "Warning",
    "ZeroDivisionError", "ExceptionGroup", "BaseExceptionGroup",
))

GROUP_LINE = re.compile(
    r"^(?P<margin>[ +|\-]*)"
    r"(?P<kind>(?:[A-Za-z_][A-Za-z_0-9.]*\.)?"
    r"(?:BaseExceptionGroup|ExceptionGroup)):\s*"
    r"(?P<message>.*?)\s*\((?P<count>\d{1,5}) sub-exceptions?\)\s*$"
)
LEAF_LINE = re.compile(
    r"^[ +|\-]*"
    r"(?P<name>[A-Za-z_][A-Za-z_0-9.]*)\s*:\s*.*$"
)
TRUNCATED_LINE = re.compile(r"(?:and \d+ more exceptions|max_group_(?:depth|width))")


def parser_capabilities():
    """Versioned, compile-only syntax capability checks on a fixed snippet."""
    source = "try:\n    pass\nexcept* ValueError:\n    pass\n"
    try:
        ast.parse(source, filename="<trusted-except-star-capability>")
    except SyntaxError:
        supports_except_star = False
    else:
        supports_except_star = True
    return {
        "python_minor": f"{sys.version_info.major}.{sys.version_info.minor}",
        "implementation": sys.implementation.name,
        "except_star_syntax": supports_except_star,
        "task_group_runtime_available": (
            sys.implementation.name == "cpython" and
            sys.version_info >= (3, 11)
        ),
        "source_executed": False,
    }


def bounded_trace(path):
    """Read a regular unique file via no-follow FD, never reveal its path."""
    target = Path(path)
    if target.is_symlink():
        raise ValueError("trace_symlink_refused")
    try:
        descriptor = os.open(str(target), os.O_RDONLY |
                             getattr(os, "O_NOFOLLOW", 0) |
                             getattr(os, "O_NONBLOCK", 0))
    except OSError:
        raise ValueError("trace_unreadable") from None
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("trace_not_unique_regular_file")
        if before.st_size > MAX_LOG_BYTES:
            raise ValueError("trace_size_limit")
        raw = stream.read(MAX_LOG_BYTES + 1)
        after = os.fstat(stream.fileno())
        if (len(raw) > MAX_LOG_BYTES or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise ValueError("trace_changed_or_oversized")
    if b"\x00" in raw:
        raise ValueError("trace_contains_nul")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise ValueError("trace_invalid_utf8") from None
    return text, hashlib.sha256(raw).hexdigest()


def analyze_text(text):
    """Extract sanitized group counts and leaf names; do not trust hierarchy."""
    envelope = {
        "schema_version": 1,
        "source_executed": False,
        "project_modules_imported": False,
        "private_exception_messages_exposed": False,
        "source_paths_exposed": False,
        "exception_hierarchy_verified": False,
        "task_execution_verified": False,
        "trace_data_trust": "UNTRUSTED_OFFLINE_TEXT",
        "capabilities": parser_capabilities(),
    }
    if not isinstance(text, str):
        return dict(envelope, status="NOT_RUN", reason="trace_invalid_type")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError:
        return dict(envelope, status="NOT_RUN", reason="trace_invalid_unicode")
    if size > MAX_LOG_BYTES:
        return dict(envelope, status="NOT_RUN", reason="trace_size_limit")
    lines = text.splitlines()
    if len(lines) > MAX_LINES or "\0" in text:
        return dict(envelope, status="NOT_RUN", reason="trace_structure_limit")
    if any(len(line) > MAX_LINE_CHARS for line in lines):
        return dict(envelope, status="NOT_RUN", reason="trace_line_limit")
    if not envelope["capabilities"]["task_group_runtime_available"]:
        return dict(envelope, status="NOT_SUPPORTED",
                    reason="exception_group_requires_cpython_3_11")

    header = any("Exception Group Traceback (most recent call last):" in line
                 for line in lines)
    groups, leaves, stack = [], [], []
    truncated = False
    for lineno, line in enumerate(lines, start=1):
        if TRUNCATED_LINE.search(line):
            truncated = True
        group = GROUP_LINE.fullmatch(line)
        if group:
            if len(groups) >= MAX_GROUPS:
                return dict(envelope, status="NOT_RUN", reason="trace_group_limit")
            declared = int(group.group("count"))
            if declared > MAX_DECLARED_CHILDREN:
                return dict(envelope, status="NOT_RUN", reason="declared_group_size_limit")
            margin = group.group("margin")
            indent = len(margin) - len(margin.lstrip(" "))
            while stack and stack[-1][0] >= indent:
                stack.pop()
            parent = stack[-1][1] if stack else None
            index = len(groups)
            record = {
                "index": index,
                "parent_group_index_hint": parent,
                "type": group.group("kind").rsplit(".", 1)[-1],
                "declared_subexceptions": declared,
                "line": lineno,
                "taskgroup_message_hint": "TaskGroup" in group.group("message"),
                "parentage_verified": False,
            }
            groups.append(record)
            stack.append((indent, index))
            continue
        leaf = LEAF_LINE.fullmatch(line)
        if not leaf:
            continue
        raw_name = leaf.group("name").rsplit(".", 1)[-1]
        if (raw_name not in ("KeyboardInterrupt", "SystemExit") and
                not raw_name.endswith(("Error", "Exception", "Warning"))):
            continue
        if raw_name in ("ExceptionGroup", "BaseExceptionGroup"):
            continue
        name = raw_name if raw_name in SAFE_EXCEPTION_NAMES else "[CUSTOM_EXCEPTION_REDACTED]"
        if len(leaves) >= MAX_LEAVES:
            return dict(envelope, status="NOT_RUN", reason="trace_leaf_limit")
        indent = len(line) - len(line.lstrip(" "))
        parent = next((index for margin, index in reversed(stack) if margin < indent), None)
        leaves.append({"type": name, "line": lineno,
                       "parent_group_index_hint": parent, "parentage_verified": False})

    if not groups:
        return dict(envelope, status="NOT_RECOGNIZED",
                    reason="no_exception_group_headers")
    hint = "POSSIBLE_TRACE_TEXT_NOT_VERIFIED" if any(
        group["taskgroup_message_hint"] for group in groups) else "NOT_DETECTED"
    return dict(envelope,
                status="INSPECTED_PARTIAL" if header and not truncated else
                       "INCOMPLETE_TRACE_TEXT",
                exception_group_headers=groups,
                exception_groups_seen=len(groups),
                leaf_exception_classes=sorted({item["type"] for item in leaves}),
                leaf_exceptions_seen=len(leaves),
                leaf_observations=leaves,
                declared_subexception_total=sum(item["declared_subexceptions"]
                                                for item in groups),
                header_present=header,
                truncated_group_output=truncated,
                taskgroup_hint=hint,
                except_star_syntax_supported=True,
                diagnostic_scope="TRACED_EXCEPTIONGROUP_TEXT_ONLY_NOT_RUNTIME_VERIFIED")


def inspect_file(path):
    """Never execute or import the sources mentioned in a saved traceback."""
    if not parser_capabilities()["task_group_runtime_available"]:
        return analyze_text("")
    try:
        text, fingerprint = bounded_trace(path)
    except ValueError as failure:
        report = analyze_text("")
        report["status"] = "NOT_RUN"
        report["reason"] = str(failure)
        return report
    report = analyze_text(text)
    report["trace_sha256"] = fingerprint
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace_file", type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect_file(args.trace_file), ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
