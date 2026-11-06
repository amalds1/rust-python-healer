"""Real MCP/LSP stdio and keyboard UX tests; no untrusted program execution."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "developer_protocols_v21.py"
spec = importlib.util.spec_from_file_location("developer_protocols_v21", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def request(method, identity=1, params=None):
    result = {"jsonrpc": "2.0", "id": identity, "method": method}
    if params is not None:
        result["params"] = params
    return result


def key_and_approval(text="answer = None\n", replacement="42"):
    key = b"this-is-a-private-fixed-test-review-key"
    payload = {"uri": "file:///synthetic-safe.py", "version": 7,
               "sha256": hashlib.sha256(text.encode()).hexdigest(),
               "line": 0, "start": 9, "end": 13, "old": "None",
               "replacement": replacement, "reviewer": "trusted-test-reviewer"}
    approval = {"signed": payload, "signature": mod.sign_approval(payload, key)}
    return key, approval


class ProtocolTests(unittest.TestCase):
    def test_mcp_initialize_lists_tools_and_inspects_actual_parser(self):
        session = mod.McpSession()
        self.assertEqual(session.handle(request("initialize"))["result"]["protocolVersion"],
                         "2025-06-18")
        self.assertEqual(session.handle(request("tools/list"))["result"]["tools"][0]["name"],
                         "rph.inspect_python")
        report = session.handle(request("tools/call", params={"name": "rph.inspect_python",
                       "arguments": {"code": "import ast\ndef f():\n    return 1\n"}}))
        self.assertFalse(report["result"]["isError"])
        data = json.loads(report["result"]["content"][0]["text"])
        self.assertEqual(data["functions"], ["f"])
        self.assertEqual(data["imports"], ["ast"])
        self.assertFalse(data["source_executed"])

    def test_unknown_tool_and_uninitialized_access_fail_closed(self):
        session = mod.McpSession()
        self.assertIn("error", session.handle(request("tools/list")))
        session.handle(request("initialize"))
        self.assertIn("error", session.handle(request("tools/call", params={
            "name": "rph.shell", "arguments": {"cmd": "echo unsafe"}})))
        self.assertIn("error", session.handle(request("methods/execute")))

    def test_syntax_failure_is_tool_error_without_execution(self):
        session = mod.McpSession()
        session.handle(request("initialize"))
        result = session.handle(request("tools/call", params={
            "name": "rph.inspect_python", "arguments": {"code": "def broken(:\n"}}))
        self.assertTrue(result["result"]["isError"])
        self.assertEqual(json.loads(result["result"]["content"][0]["text"])["status"],
                         "SYNTAX_ERROR")

    def test_duplicate_json_and_oversized_source_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            mod.safe_json(b'{"jsonrpc":"2.0","id":1,"id":2}')
        with self.assertRaisesRegex(ValueError, "unbounded"):
            mod.inspect_source("#" * (mod.MAX_SOURCE + 1))

    def test_mcp_real_stdio_multiple_requests_and_notification(self):
        content = b"\n".join(json.dumps(row).encode() for row in (
            request("initialize"), {"jsonrpc": "2.0", "method": "notifications/initialized"},
            request("tools/list", 2), request("ping", 3))) + b"\n"
        completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                                    "--mode", "mcp"], input=content,
                                   capture_output=True, timeout=8, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual([row["id"] for row in responses], [1, 2, 3])
        self.assertFalse(completed.stderr)

    def test_mcp_rejects_large_input_without_panic_or_source_execution(self):
        incoming = b"x" * (mod.MAX_MESSAGE + 9) + b"\n"
        output = io.BytesIO()
        mod.run_mcp(io.BytesIO(incoming), output)
        self.assertEqual(json.loads(output.getvalue())["error"]["code"], -32602)

    def test_signed_lsp_codeaction_returns_versioned_edit_only(self):
        key, signed = key_and_approval()
        session = mod.LspSession(key)
        self.assertTrue(session.handle(request("initialize"))["result"]["capabilities"][
            "codeActionProvider"])
        self.assertIsNone(session.handle(request("textDocument/didOpen", params={
            "textDocument": {"uri": "file:///synthetic-safe.py", "version": 7,
                             "text": "answer = None\n"}})))
        result = session.handle(request("textDocument/codeAction", 2, params={
            "textDocument": {"uri": "file:///synthetic-safe.py"},
            "reviewedApproval": signed}))
        fix = result["result"][0]
        self.assertEqual(fix["edit"]["documentChanges"][0]["edits"][0]["newText"], "42")
        self.assertFalse(fix["data"]["applied"])
        self.assertEqual(len(session.audit), 1)

    def test_tampered_signature_cannot_propose_lsp_edit(self):
        key, signed = key_and_approval()
        session = mod.LspSession(key)
        session.handle(request("initialize"))
        session.handle(request("textDocument/didOpen", params={"textDocument": {
            "uri": "file:///synthetic-safe.py", "version": 7, "text": "answer = None\n"}}))
        signed["signed"]["replacement"] = "exec('bad')"
        result = session.handle(request("textDocument/codeAction", params={
            "textDocument": {"uri": "file:///synthetic-safe.py"},
            "reviewedApproval": signed}))
        self.assertIn("error", result)
        self.assertEqual(session.audit, [])

    def test_stale_text_and_version_fail_closed(self):
        key, signed = key_and_approval()
        with self.assertRaisesRegex(ValueError, "stale"):
            mod.approved_edit({"uri": "file:///synthetic-safe.py", "version": 8,
                               "text": "answer = None\n"}, signed, key)
        with self.assertRaisesRegex(ValueError, "stale"):
            mod.approved_edit({"uri": "file:///synthetic-safe.py", "version": 7,
                               "text": "answer = 2\n"}, signed, key)

    def test_approval_rejects_invalid_original_span_and_newline(self):
        key, signed = key_and_approval()
        original = {"uri": "file:///synthetic-safe.py", "version": 7,
                    "text": "answer = None\n"}
        signed["signed"]["old"] = "Else"
        signed["signature"] = mod.sign_approval(signed["signed"], key)
        with self.assertRaisesRegex(ValueError, "original_span"):
            mod.approved_edit(original, signed, key)
        signed["signed"]["old"] = "None"
        signed["signed"]["replacement"] = "42\nexec('bad')"
        signed["signature"] = mod.sign_approval(signed["signed"], key)
        with self.assertRaisesRegex(ValueError, "unsafe_edit_replacement"):
            mod.approved_edit(original, signed, key)

    def test_lsp_real_content_length_binary_protocol(self):
        key, signed = key_and_approval()
        with tempfile.TemporaryDirectory() as tmp:
            keyfile = Path(tmp) / "key"
            keyfile.write_bytes(key)
            keyfile.chmod(0o600)
            events = [request("initialize"), request("textDocument/didOpen", params={
                "textDocument": {"uri": "file:///synthetic-safe.py", "version": 7,
                                 "text": "answer = None\n"}}),
                request("textDocument/codeAction", 5, params={
                    "textDocument": {"uri": "file:///synthetic-safe.py"},
                    "reviewedApproval": signed})]
            frames = b"".join(b"Content-Length: " + str(len(body)).encode() +
                              b"\r\n\r\n" + body
                              for body in (json.dumps(x).encode() for x in events))
            completed = subprocess.run([sys.executable, "-I", "-S", "-B",
                        str(SCRIPT), "--mode", "lsp", "--key-file", str(keyfile)],
                        input=frames, capture_output=True, timeout=8, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn(b'"codeActionProvider": true', completed.stdout)
            self.assertIn(b'"newText": "42"', completed.stdout)
            self.assertNotIn(key, completed.stdout)

    def test_lsp_refuses_unprivileged_review_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "key"
            path.write_bytes(b"0123456789abcdef0123456789abcdef")
            path.chmod(0o644)
            if os.name == "nt":
                sys.path.insert(0, str(ROOT / "tests"))
                import windows_privacy_fixtures
                windows_privacy_fixtures.set_public_read_acl(path)
            with self.assertRaisesRegex(ValueError, "private"):
                mod.read_private_key(path)
            link = Path(tmp) / "symlink"
            link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, "key"):
                mod.read_private_key(link)

    def test_tui_keys_arrows_and_boundaries(self):
        menu = mod.TerminalMenu([{"id": "one", "status": "PASS"},
                                 {"id": "two", "status": "BLOCKED"}])
        self.assertEqual(menu.key("k")["index"], 0)
        self.assertEqual(menu.key("\x1b[B")["index"], 1)
        self.assertEqual(menu.key("j")["index"], 1)
        self.assertEqual(menu.key("\x1b[A")["index"], 0)
        self.assertEqual(menu.key("enter")["record"]["id"], "one")

    def test_tui_screen_reader_includes_text_not_terminal_controls(self):
        menu = mod.TerminalMenu([{"id": "F001", "status": "PASS"}])
        self.assertIn("SELECTED F001", menu.render(screen_reader=True))
        self.assertNotIn("\x1b", menu.render(screen_reader=True))
        self.assertIn("\x1b", menu.render(screen_reader=False))

    def test_tui_real_keyboard_subprocess_selects_second_item(self):
        records = json.dumps([{"id": "first", "status": "PASS"},
                              {"id": "second", "status": "PARTIAL"}])
        completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                                    "--mode", "tui", "--records-json", records,
                                    "--screen-reader"], input=b"j\n\n",
                                   capture_output=True, timeout=8, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout.splitlines()[-1])["record"]["id"],
                         "second")

    def test_tui_rejects_excessive_records(self):
        with self.assertRaisesRegex(ValueError, "terminal_records"):
            mod.TerminalMenu([{"id": str(n), "status": "PASS"} for n in range(41)])


if __name__ == "__main__":
    unittest.main()
