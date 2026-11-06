"""F098/F202: bounded, no-execution static diagnostics and ZIP policy inspection.

This is never a malware verdict and cannot prove arbitrary Python deadness.
All identifiers/reasons are fixed; file names, source and metadata are omitted.
"""

import ast
import io
import os
from pathlib import Path
import re
import stat
import tokenize
import zipfile


MAX_SOURCE = 1_000_000
MAX_ARCHIVE = 8_000_000
MAX_INFLATED = 12_000_000
MAX_ENTRY = 4_000_000
MAX_NESTED = 2
MAX_ENTRIES = 400
MAX_FINDINGS = 512
MAX_RATIO = 100
MAX_METADATA = 64_000
_SAFE_ENTRY = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/+-]*\Z", re.ASCII)
_META_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z", re.ASCII)
_META_VERSION = re.compile(r"[0-9][A-Za-z0-9.!+_]*\Z", re.ASCII)


class InspectionRejected(Exception):
    pass


def read_plain(path, limit):
    """Reject symlink/hardlink and read only one bounded regular file."""
    try:
        before = Path(path).lstat()
        if not stat.S_ISREG(before.st_mode):
            raise InspectionRejected("input_not_regular")
        if before.st_nlink != 1:
            raise InspectionRejected("input_hardlink_refused")
        if before.st_size > limit:
            raise InspectionRejected("input_size_limit")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(str(path), flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise InspectionRejected("input_changed")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        if len(data) > limit or (before.st_size, before.st_mtime_ns, before.st_ino) != (
                after.st_size, after.st_mtime_ns, after.st_ino):
            raise InspectionRejected("input_changed")
        return data
    except InspectionRejected:
        raise
    except (OSError, ValueError, TypeError):
        raise InspectionRejected("input_unreadable") from None


def _finding(rule, node, confidence):
    return {"rule": rule, "line": getattr(node, "lineno", 0),
            "confidence": confidence}


def _static_findings(tree):
    found = []

    def mark(rule, node, confidence):
        if len(found) < MAX_FINDINGS:
            found.append(_finding(rule, node, confidence))
        else:
            raise InspectionRejected("static_finding_budget_exceeded")

    for node in ast.walk(tree):
        if isinstance(node, ast.If) and isinstance(node.test, ast.Constant) and type(node.test.value) is bool:
            unreachable = node.orelse if node.test.value else node.body
            for stmt in unreachable:
                mark("F098_LITERAL_UNREACHABLE_BRANCH", stmt,
                     "PROVEN_LITERAL_BOOL_BRANCH_ONLY")
        # Only same-block unconditional exits are statically certain.
        for attr in ("body", "orelse", "finalbody"):
            statements = getattr(node, attr, None)
            if not isinstance(statements, list) or not statements:
                continue
            terminated = False
            for stmt in statements:
                if not isinstance(stmt, ast.stmt):
                    continue
                if terminated:
                    mark("F098_UNREACHABLE_AFTER_EXIT", stmt,
                         "PROVEN_UNCONDITIONAL_SAME_BLOCK_EXIT")
                if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                    terminated = True
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Local dynamic introspection makes unused-variable guesses unsound.
        body = ast.Module(body=node.body, type_ignores=[])
        children = list(ast.walk(body))
        if any(isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
               and child.func.id in ("locals", "globals", "vars", "eval", "exec")
               for child in children):
            continue
        reads = {child.id for child in children if isinstance(child, ast.Name)
                 and isinstance(child.ctx, (ast.Load, ast.Del))}
        for child in children:
            if isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                for target in targets:
                    if isinstance(target, ast.Name) and not target.id.startswith("_") \
                            and target.id not in reads:
                        mark("F098_UNUSED_LOCAL_CANDIDATE", target,
                             "STATIC_CANDIDATE_NOT_SEMANTIC_PROOF")
    return found


def analyze_dead_code(path):
    baseline = {"status": "NOT_RUN", "source_executed": False,
                "unused_semantics_proven": False, "interpreter_runtime_proven": False}
    try:
        data = read_plain(path, MAX_SOURCE)
        reader = io.BytesIO(data).readline
        encoding, _ = tokenize.detect_encoding(reader)
        source = data.decode(encoding)
        tree = ast.parse(source)
        findings = _static_findings(tree)
    except InspectionRejected as error:
        return {**baseline, "reason": str(error)}
    except (SyntaxError, UnicodeError, LookupError, ValueError):
        return {**baseline, "reason": "invalid_source_or_syntax"}
    return {**baseline, "status": "STATIC_PARTIAL_NOT_EXECUTED",
            "findings": findings, "findings_count": len(findings)}


def _archive_member_name(name):
    if (not 1 <= len(name) <= 240 or not name.isascii() or "\\" in name
            or ":" in name or "\x00" in name or name.startswith("/")):
        raise InspectionRejected("archive_unsafe_entry_name")
    cleaned = name[:-1] if name.endswith("/") else name
    parts = cleaned.split("/")
    if (not cleaned or any(part in ("", ".", "..") for part in parts)
            or not _SAFE_ENTRY.fullmatch(cleaned)):
        raise InspectionRejected("archive_unsafe_entry_name")


def _inspect_metadata(data):
    if len(data) > MAX_METADATA:
        raise InspectionRejected("metadata_size_limit")
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        raise InspectionRejected("metadata_invalid_utf8") from None
    if ("\r" in text or any(0x7F <= ord(char) <= 0x9F
                            or 0x202A <= ord(char) <= 0x202E
                            or 0x2066 <= ord(char) <= 0x2069 for char in text)):
        raise InspectionRejected("metadata_control_or_line_limit")
    lines = text.splitlines()
    if any(len(line) > 4096 or "\x00" in line or "\r" in line
           or any(ord(char) < 32 and char != "\t" for char in line) for line in lines):
        raise InspectionRejected("metadata_control_or_line_limit")
    for field, pattern in (("Name", _META_NAME), ("Version", _META_VERSION)):
        found = [line.split(":", 1)[1].strip() for line in lines if line.startswith(field + ":")]
        if len(found) > 1 or (found and not pattern.fullmatch(found[0])):
            raise InspectionRejected("metadata_invalid_identity_field")


def _scan_zip(content, depth, budget):
    if depth > MAX_NESTED:
        raise InspectionRejected("archive_nesting_limit")
    try:
        archive = zipfile.ZipFile(io.BytesIO(content), "r")
        with archive:
            entries = archive.infolist()
            budget["entries"] += len(entries)
            if budget["entries"] > MAX_ENTRIES:
                raise InspectionRejected("archive_entry_budget_exceeded")
            seen = set()
            for entry in entries:
                _archive_member_name(entry.filename)
                folded = entry.filename.casefold()
                if folded in seen:
                    raise InspectionRejected("archive_duplicate_entry")
                seen.add(folded)
                mode = (entry.external_attr >> 16) & 0o170000
                if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise InspectionRejected("archive_special_entry_refused")
                if entry.flag_bits & 1:
                    raise InspectionRejected("archive_encrypted_entry")
                if entry.file_size > MAX_ENTRY or entry.file_size > MAX_INFLATED - budget["bytes"]:
                    raise InspectionRejected("archive_inflated_budget_exceeded")
                if entry.file_size and (entry.compress_size == 0
                                        or entry.file_size > entry.compress_size * MAX_RATIO):
                    raise InspectionRejected("archive_compression_ratio_limit")
                if entry.is_dir():
                    continue
                with archive.open(entry, "r") as member:
                    data = member.read(entry.file_size + 1)
                    if len(data) != entry.file_size:
                        raise InspectionRejected("archive_entry_size_mismatch")
                    # Ensure CRC was validated by exhausting member input.
                    if member.read(1):
                        raise InspectionRejected("archive_entry_size_mismatch")
                budget["bytes"] += len(data)
                if entry.filename.endswith(("/METADATA", "/PKG-INFO", "/WHEEL")):
                    _inspect_metadata(data)
                if (entry.filename.lower().endswith((".zip", ".whl", ".egg", ".pyz", ".jar"))
                        or data.startswith(b"PK\x03\x04")):
                    if depth >= MAX_NESTED:
                        raise InspectionRejected("archive_nesting_limit")
                    _scan_zip(data, depth + 1, budget)
    except InspectionRejected:
        raise
    except (OSError, EOFError, RuntimeError, ValueError, zipfile.BadZipFile, zipfile.LargeZipFile):
        raise InspectionRejected("archive_unreadable_or_invalid") from None


def inspect_zip(path):
    baseline = {"status": "NOT_RUN", "user_code_executed": False,
                "archive_extracted": False, "network_used": False,
                "malware_absence_proven": False}
    try:
        content = read_plain(path, MAX_ARCHIVE)
        budget = {"entries": 0, "bytes": 0}
        _scan_zip(content, 0, budget)
    except InspectionRejected as error:
        return {**baseline, "status": "REJECTED_BY_STATIC_POLICY", "reason": str(error)}
    return {**baseline, "status": "STATIC_ZIP_STRUCTURE_ACCEPTED_NOT_TRUSTED",
            "entry_count": budget["entries"], "inflated_bytes": budget["bytes"]}
