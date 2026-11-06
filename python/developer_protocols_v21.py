"""Offline, bounded MCP/LSP/TUI diagnostics on trusted protocol messages.

No source code is executed, no files are edited, no network sockets opened.
The LSP code-action producer requires a separately signed approval and returns
an edit proposal only; it does not apply any user code or certify IDE clients.
"""

import argparse
import ast
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys


MAX_MESSAGE = 100_000
MAX_REQUESTS = 128
MAX_SOURCE = 32_000
MAX_DOCS = 12
HEX = re.compile(r"[a-f0-9]{64}\Z")


def safe_json(raw):
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not isinstance(raw, bytes) or len(raw) > MAX_MESSAGE:
        raise ValueError("protocol_message_quota")

    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    return json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)


def bounded_source(value):
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_SOURCE:
        raise ValueError("unbounded_or_missing_source")
    return value


def inspect_source(source):
    """Produce a read-only, version-grounded AST summary, never eval/exec."""
    source = bounded_source(source)
    try:
        parsed = ast.parse(source, mode="exec")
    except (SyntaxError, ValueError, UnicodeError) as exc:
        return {"status": "SYNTAX_ERROR", "error_type": type(exc).__name__,
                "source_executed": False, "python_minor": "{}.{}".format(*sys.version_info[:2])}
    if sum(1 for _ in ast.walk(parsed)) > 4000:
        raise ValueError("ast_nodes_quota")
    funcs = sorted(node.name for node in ast.walk(parsed)
                   if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))[:200]
    imports = sorted({alias.name.split(".")[0] for node in ast.walk(parsed)
                      if isinstance(node, ast.Import) for alias in node.names} |
                     {node.module.split(".")[0] for node in ast.walk(parsed)
                      if isinstance(node, ast.ImportFrom) and node.module})[:200]
    return {"status": "AST_INSPECTED_NEVER_EXECUTED",
            "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "python_minor": "{}.{}".format(*sys.version_info[:2]),
            "functions": funcs, "imports": imports, "source_executed": False,
            "dynamic_call_targets_verified": False}


def _request_id(message):
    identity = message.get("id")
    if identity is not None and (type(identity) not in (str, int) or
                                 isinstance(identity, str) and len(identity) > 120):
        raise ValueError("invalid_request_identifier")
    return identity


def _response(identity, result=None, error=None):
    if error is not None:
        return {"jsonrpc": "2.0", "id": identity,
                "error": {"code": -32602, "message": str(error)[:150]}}
    return {"jsonrpc": "2.0", "id": identity, "result": result}


class McpSession:
    """Small real JSON-RPC MCP stdio surface, without remote tool mutation."""

    def __init__(self):
        self.initialized = False
        self.completed = False
        self.requests = 0

    def handle(self, message):
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _response(None, error="invalid_jsonrpc_envelope")
        try:
            identity = _request_id(message)
            method = message.get("method")
            if not isinstance(method, str) or len(method) > 100:
                raise ValueError("invalid_method")
            self.requests += 1
            if self.requests > MAX_REQUESTS:
                raise ValueError("requests_quota")
            if method == "initialize":
                params = message.get("params", {})
                if not isinstance(params, dict):
                    raise ValueError("invalid_initialize")
                self.initialized = True
                return _response(identity, {"protocolVersion": "2025-06-18",
                           "capabilities": {"tools": {"listChanged": False}},
                           "serverInfo": {"name": "rust-python-healer-offline", "version": "0.21"}})
            if method == "notifications/initialized":
                return None
            if not self.initialized:
                raise ValueError("initialize_required")
            if method == "ping":
                return _response(identity, {})
            if method == "tools/list":
                return _response(identity, {"tools": [{"name": "rph.inspect_python",
                    "description": "Parse supplied Python text without running it",
                    "inputSchema": {"type": "object", "properties": {
                        "code": {"type": "string"}}, "required": ["code"],
                        "additionalProperties": False}}]})
            if method == "tools/call":
                params = message.get("params")
                if not isinstance(params, dict) or params.get("name") != "rph.inspect_python":
                    raise ValueError("unknown_or_untrusted_tool")
                arguments = params.get("arguments", {})
                if not isinstance(arguments, dict) or set(arguments) != {"code"}:
                    raise ValueError("invalid_tool_arguments")
                result = inspect_source(arguments["code"])
                return _response(identity, {"content": [{"type": "text",
                    "text": json.dumps(result, sort_keys=True)}],
                    "isError": result["status"] != "AST_INSPECTED_NEVER_EXECUTED"})
            raise ValueError("unsupported_method")
        except (ValueError, TypeError) as exc:
            return _response(message.get("id"), error=exc)


def read_private_key(path):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size not in range(16, 129):
        raise ValueError("invalid_private_review_key")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("review_key_must_be_private")
    if os.name == "nt":
        privacy = _windows_key_privacy()
        try:
            fd = privacy.open_private_readonly(path)
        except (OSError, ValueError) as problem:
            raise ValueError("review_key_must_be_private") from problem
    else:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (info.st_dev, info.st_ino, info.st_size) != (opened.st_dev, opened.st_ino, opened.st_size):
                raise ValueError("private_review_key_changed_before_read")
            key = stream.read(129)
            after = os.fstat(stream.fileno())
            if os.name == "nt":
                privacy.assert_private_file_descriptor(stream.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise ValueError("private_review_key_changed_during_read")
    except Exception:
        raise
    if len(key) < 16 or len(key) > 128:
        raise ValueError("review_key_size_changed")
    return key


def _windows_key_privacy():
    embedded = globals().get("_RPH_WINDOWS_PRIVACY")
    if embedded is not None:
        return embedded
    import importlib.util
    module_path = Path(__file__).resolve().with_name("windows_private_paths.py")
    spec = importlib.util.spec_from_file_location("rph_protocol_windows_privacy", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    globals()["_RPH_WINDOWS_PRIVACY"] = module
    return module


def sign_approval(payload, key):
    if not isinstance(payload, dict):
        raise ValueError("approval_object_required")
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def approved_edit(document, approval, key):
    if not isinstance(document, dict) or not isinstance(approval, dict):
        raise ValueError("invalid_approval_schema")
    signed = approval.get("signed")
    signature = approval.get("signature")
    required = {"uri", "version", "sha256", "line", "start", "end",
                "old", "replacement", "reviewer"}
    if not isinstance(signed, dict) or set(signed) != required or not isinstance(signature, str):
        raise ValueError("invalid_signed_edit")
    if not HEX.fullmatch(signature) or not hmac.compare_digest(
            sign_approval(signed, key), signature):
        raise ValueError("untrusted_edit_signature")
    if (signed["uri"] != document["uri"] or signed["version"] != document["version"] or
            signed["sha256"] != hashlib.sha256(document["text"].encode("utf-8")).hexdigest()):
        raise ValueError("stale_document_or_version")
    if not isinstance(signed["reviewer"], str) or not 1 <= len(signed["reviewer"]) <= 60:
        raise ValueError("missing_review_identity")
    lines = document["text"].splitlines(keepends=True)
    line, start, end = signed["line"], signed["start"], signed["end"]
    if any(type(v) is not int for v in (line, start, end)) or not 0 <= line < len(lines):
        raise ValueError("invalid_edit_position")
    if not 0 <= start <= end <= len(lines[line].rstrip("\r\n")):
        raise ValueError("invalid_edit_range")
    if signed["old"] != lines[line][start:end]:
        raise ValueError("original_span_not_equal")
    replacement = signed["replacement"]
    if (not isinstance(replacement, str) or len(replacement) > 2000 or
            any(token in replacement for token in ("\n", "\r", "\x00"))):
        raise ValueError("unsafe_edit_replacement")
    return {"title": "Reviewed offline safe quickfix", "kind": "quickfix",
            "edit": {"documentChanges": [{"textDocument": {
                "uri": document["uri"], "version": document["version"]},
                "edits": [{"range": {"start": {"line": line, "character": start},
                                      "end": {"line": line, "character": end}},
                           "newText": replacement}]}]},
            "data": {"reviewer_sha256": hashlib.sha256(
                signed["reviewer"].encode()).hexdigest(),
                "source_sha256": signed["sha256"], "applied": False}}


class LspSession:
    def __init__(self, key):
        self.key = key
        self.initialized = False
        self.shutdown = False
        self.documents = {}
        self.audit = []
        self.requests = 0

    def handle(self, message):
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _response(None, error="invalid_jsonrpc_envelope")
        try:
            identity = _request_id(message)
            self.requests += 1
            if self.requests > MAX_REQUESTS:
                raise ValueError("requests_quota")
            method = message.get("method")
            params = message.get("params", {})
            if not isinstance(params, dict):
                raise ValueError("invalid_params")
            if method == "initialize":
                if self.initialized:
                    raise ValueError("duplicate_initialize")
                self.initialized = True
                return _response(identity, {"capabilities": {
                    "textDocumentSync": 1, "codeActionProvider": True},
                    "serverInfo": {"name": "rust-python-healer-offline", "version": "0.21"}})
            if not self.initialized:
                raise ValueError("initialize_required")
            if method == "initialized":
                return None
            if method == "exit":
                return None
            if self.shutdown:
                raise ValueError("server_shutdown")
            if method == "textDocument/didOpen":
                item = params.get("textDocument")
                if not isinstance(item, dict) or not isinstance(item.get("uri"), str) or \
                        not 1 <= len(item["uri"]) <= 4096 or "\x00" in item["uri"] or \
                        type(item.get("version")) is not int:
                    raise ValueError("invalid_open_document")
                bounded_source(item.get("text"))
                if len(self.documents) >= MAX_DOCS and item["uri"] not in self.documents:
                    raise ValueError("open_document_quota")
                self.documents[item["uri"]] = {"uri": item["uri"], "version": item["version"],
                                               "text": item["text"]}
                return None
            if method == "textDocument/didChange":
                item = params.get("textDocument")
                changes = params.get("contentChanges")
                if (not isinstance(item, dict) or not isinstance(item.get("uri"), str) or
                        item["uri"] not in self.documents or
                        type(item.get("version")) is not int or
                        not isinstance(changes, list) or len(changes) != 1 or
                        not isinstance(changes[0], dict) or set(changes[0]) != {"text"}):
                    raise ValueError("invalid_full_document_change")
                current = self.documents[item["uri"]]
                if item["version"] <= current["version"]:
                    raise ValueError("stale_document_change")
                new_text = bounded_source(changes[0]["text"])
                self.documents[item["uri"]] = {"uri": item["uri"],
                                               "version": item["version"], "text": new_text}
                return None
            if method == "textDocument/didClose":
                item = params.get("textDocument", {})
                if isinstance(item, dict):
                    self.documents.pop(item.get("uri"), None)
                return None
            if method == "textDocument/codeAction":
                item = params.get("textDocument", {})
                uri = item.get("uri") if isinstance(item, dict) else None
                if uri not in self.documents:
                    raise ValueError("unopened_document")
                proposal = approved_edit(self.documents[uri], params.get("reviewedApproval"),
                                         self.key)
                self.audit.append({"uri_sha256": hashlib.sha256(uri.encode()).hexdigest(),
                                   "signed_reviewed": True, "code_executed": False})
                return _response(identity, [proposal])
            if method == "shutdown":
                self.shutdown = True
                return _response(identity, None)
            raise ValueError("unsupported_method")
        except (ValueError, TypeError, KeyError) as exc:
            return _response(message.get("id"), error=exc)


def run_mcp(input_stream, output_stream):
    session = McpSession()
    for _ in range(MAX_REQUESTS):
        line = input_stream.readline(MAX_MESSAGE + 2)
        if not line:
            return session.requests
        oversized = len(line) > MAX_MESSAGE
        try:
            answer = session.handle(safe_json(line.strip()))
        except (ValueError, UnicodeError, json.JSONDecodeError):
            answer = _response(None, error="invalid_or_oversized_protocol_message")
        if answer is not None:
            output_stream.write(json.dumps(answer, sort_keys=True).encode() + b"\n")
            output_stream.flush()
        if oversized:
            # The remainder of this malformed frame is not a new request.
            return session.requests
    return session.requests


def read_lsp_frame(input_stream):
    """Parse real editor stdio framing, including optional Content-Type.

    Every byte is quota-bounded. Duplicate/conflicting lengths and non-UTF-8
    declared payloads are rejected instead of permitting parser desync.
    """
    headers = {}
    for _ in range(8):
        line = input_stream.readline(257)
        if not line:
            if headers:
                raise ValueError("truncated_lsp_header")
            return None
        if len(line) > 256 or not line.endswith(b"\r\n"):
            raise ValueError("invalid_lsp_frame_header")
        if line == b"\r\n":
            break
        try:
            name, value = line[:-2].split(b":", 1)
            if not name or not value or any(c not in b"abcdefghijklmnopqrstuvwxyz-"
                                            for c in name.lower()):
                raise ValueError("invalid_lsp_frame_header")
            name = name.lower()
            value = value.strip()
        except ValueError as exc:
            raise ValueError("invalid_lsp_frame_header") from exc
        if name not in (b"content-length", b"content-type") or name in headers:
            raise ValueError("unsupported_or_duplicate_lsp_header")
        headers[name] = value
    else:
        raise ValueError("too_many_lsp_headers")
    size = headers.get(b"content-length")
    if size is None or not 1 <= len(size) <= 7 or any(c not in b"0123456789" for c in size):
        raise ValueError("invalid_lsp_frame_size")
    length = int(size)
    if length > MAX_MESSAGE:
        raise ValueError("invalid_lsp_frame_limit")
    content_type = headers.get(b"content-type")
    if content_type is not None:
        normalized = content_type.lower().replace(b" ", b"")
        if normalized not in (b"application/vscode-jsonrpc",
                              b"application/vscode-jsonrpc;charset=utf-8"):
            raise ValueError("unsupported_lsp_content_type")
    raw = input_stream.read(length)
    if len(raw) != length:
        raise ValueError("truncated_lsp_frame")
    return raw


def run_lsp(input_stream, output_stream, key):
    session = LspSession(key)
    for _ in range(MAX_REQUESTS):
        raw = read_lsp_frame(input_stream)
        if raw is None:
            return session.requests
        try:
            answer = session.handle(safe_json(raw))
        except (ValueError, UnicodeError, json.JSONDecodeError):
            answer = _response(None, error="invalid_lsp_json")
        if answer is not None:
            payload = json.dumps(answer, sort_keys=True).encode()
            output_stream.write(b"Content-Length: " + str(len(payload)).encode() +
                                b"\r\n\r\n" + payload)
            output_stream.flush()
    return session.requests


class TerminalMenu:
    """Deterministic keyboard-driven view usable in plain screen-reader mode."""

    def __init__(self, records):
        if not isinstance(records, list) or not 1 <= len(records) <= 40 or any(
                not isinstance(item, dict) or set(item) != {"id", "status"} or
                not isinstance(item["id"], str) or len(item["id"]) > 64 or
                not isinstance(item["status"], str) or len(item["status"]) > 40
                for item in records):
            raise ValueError("invalid_terminal_records")
        self.records = records
        self.selected = 0
        self.closed = False

    def render(self, screen_reader=False):
        lines = ["Rust Python Healer — keyboard: j/down k/up enter/select q/quit"]
        for index, item in enumerate(self.records):
            prefix = "SELECTED" if index == self.selected else " "
            lines.append("{} {} — {}".format(prefix, item["id"], item["status"]))
        result = "\n".join(lines) + "\n"
        return result if screen_reader else "\x1b[2J\x1b[H" + result

    def key(self, event):
        if event in ("j", "\x1b[B", "down"):
            self.selected = min(len(self.records) - 1, self.selected + 1)
        elif event in ("k", "\x1b[A", "up"):
            self.selected = max(0, self.selected - 1)
        elif event in ("", "enter", "\r", "\n"):
            self.closed = True
            return {"status": "SELECTED", "record": self.records[self.selected],
                    "index": self.selected}
        elif event in ("q", "quit", "\x1b"):
            self.closed = True
            return {"status": "CANCELLED", "record": None}
        else:
            return {"status": "UNKNOWN_KEY", "index": self.selected}
        return {"status": "NAVIGATING", "index": self.selected}


def run_terminal(records, input_stream, output_stream, screen_reader=False):
    menu = TerminalMenu(records)
    output_stream.write(menu.render(screen_reader))
    output_stream.flush()
    for _ in range(200):
        action = input_stream.readline(80)
        if not action:
            return {"status": "INPUT_ENDED_NO_SELECTION"}
        result = menu.key(action.rstrip("\n\r"))
        if menu.closed:
            return result
        output_stream.write(menu.render(screen_reader))
        output_stream.flush()
    return {"status": "KEY_QUOTA_EXHAUSTED"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("mcp", "lsp", "tui"), required=True)
    parser.add_argument("--key-file")
    parser.add_argument("--records-json")
    parser.add_argument("--screen-reader", action="store_true")
    args = parser.parse_args()
    if args.mode == "mcp":
        if args.key_file or args.records_json or args.screen_reader:
            parser.error("mcp_rejects_unneeded_arguments")
        run_mcp(sys.stdin.buffer, sys.stdout.buffer)
    elif args.mode == "lsp":
        if not args.key_file or args.records_json or args.screen_reader:
            parser.error("lsp_requires_review_key_only")
        run_lsp(sys.stdin.buffer, sys.stdout.buffer, read_private_key(args.key_file))
    else:
        if args.key_file or not args.records_json:
            parser.error("tui_requires_records")
        records = safe_json(args.records_json)
        report = run_terminal(records, sys.stdin, sys.stdout, args.screen_reader)
        print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
