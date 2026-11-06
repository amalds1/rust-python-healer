"""Bounded LSP editor-frame interoperability; no editor or project code runs."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "python" / "developer_protocols_v21.py"
SPEC = importlib.util.spec_from_file_location("developer_protocols_v21", SOURCE)
LSP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LSP)
KEY = b"test-only-private-editor-approval-secret"
URI = "file:///trusted-editor-buffer.py"


def message(method, identity=None, params=None):
    result = {"jsonrpc": "2.0", "method": method}
    if identity is not None:
        result["id"] = identity
    if params is not None:
        result["params"] = params
    return result


def frame(data, content_type=False):
    payload = json.dumps(data, sort_keys=True).encode("utf-8")
    header = b"Content-Length: " + str(len(payload)).encode("ascii") + b"\r\n"
    if content_type:
        header += b"Content-Type: application/vscode-jsonrpc; charset=utf-8\r\n"
    return header + b"\r\n" + payload


def reviewed_fix(text, version, replacement="42"):
    signed = {"uri": URI, "version": version,
              "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
              "line": 0, "start": 9, "end": 13, "old": "None",
              "replacement": replacement, "reviewer": "test-local-reviewer"}
    return {"signed": signed, "signature": LSP.sign_approval(signed, KEY)}


def opened(version=1, text="answer = None\n"):
    return message("textDocument/didOpen", params={"textDocument": {
        "uri": URI, "version": version, "text": text}})


def changed(version=2, text="answer = None\n"):
    return message("textDocument/didChange", params={
        "textDocument": {"uri": URI, "version": version},
        "contentChanges": [{"text": text}]})


class LspInteropTests(unittest.TestCase):
    def session(self):
        session = LSP.LspSession(KEY)
        initialized = session.handle(message("initialize", 1))
        self.assertEqual(initialized["result"]["capabilities"]["textDocumentSync"], 1)
        return session

    def test_actual_editor_content_type_round_trip(self):
        content = b"".join(frame(value, True) for value in (
            message("initialize", 1), opened(),
            changed(2), message("textDocument/codeAction", 8, {
                "textDocument": {"uri": URI},
                "reviewedApproval": reviewed_fix("answer = None\n", 2)}),
            message("shutdown", 10), message("exit")))
        with tempfile.TemporaryDirectory() as dirname:
            path = Path(dirname) / "key"
            path.write_bytes(KEY)
            path.chmod(0o600)
            done = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE),
                                   "--mode", "lsp", "--key-file", str(path)],
                                  input=content, capture_output=True, timeout=10,
                                  check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stderr, b"")
        self.assertIn(b'"newText": "42"', done.stdout)
        self.assertIn(b'"id": 8', done.stdout)
        self.assertNotIn(KEY, done.stdout)
        self.assertEqual(done.stdout.count(b"Content-Length:"), 3)

    def test_full_sync_replaces_text_and_bumps_version(self):
        session = self.session()
        self.assertIsNone(session.handle(opened()))
        self.assertIsNone(session.handle(changed(2, "answer = 999\n")))
        self.assertEqual(session.documents[URI]["text"], "answer = 999\n")
        self.assertEqual(session.documents[URI]["version"], 2)

    def test_stale_signed_fix_after_didchange_fails_closed(self):
        session = self.session()
        session.handle(opened())
        approval = reviewed_fix("answer = None\n", 1)
        session.handle(changed(2))
        answer = session.handle(message("textDocument/codeAction", 8, {
            "textDocument": {"uri": URI}, "reviewedApproval": approval}))
        self.assertIn("error", answer)
        self.assertEqual(session.audit, [])

    def test_correctly_resigned_fix_after_change_succeeds_without_apply(self):
        session = self.session()
        session.handle(opened())
        session.handle(changed(2))
        answer = session.handle(message("textDocument/codeAction", 8, {
            "textDocument": {"uri": URI},
            "reviewedApproval": reviewed_fix("answer = None\n", 2)}))
        self.assertEqual(answer["result"][0]["edit"]["documentChanges"][0][
            "textDocument"]["version"], 2)
        self.assertFalse(answer["result"][0]["data"]["applied"])

    def test_replayed_or_decreasing_versions_are_rejected(self):
        session = self.session()
        session.handle(opened())
        session.handle(changed(2))
        self.assertIn("error", session.handle(changed(2)))
        self.assertIn("error", session.handle(changed(1)))
        self.assertEqual(session.documents[URI]["version"], 2)

    def test_incremental_change_is_not_misread_as_full_text(self):
        session = self.session()
        session.handle(opened())
        event = changed()
        event["params"]["contentChanges"][0]["range"] = {
            "start": {"line": 0, "character": 0},
            "end": {"line": 0, "character": 1}}
        self.assertIn("error", session.handle(event))
        self.assertEqual(session.documents[URI]["version"], 1)

    def test_change_rejects_multiple_snapshots(self):
        session = self.session()
        session.handle(opened())
        event = changed()
        event["params"]["contentChanges"].append({"text": "other"})
        self.assertIn("error", session.handle(event))

    def test_oversized_changed_buffer_rejected_without_mutation(self):
        session = self.session()
        session.handle(opened())
        self.assertIn("error", session.handle(changed(2, "X" * (LSP.MAX_SOURCE + 1))))
        self.assertEqual(session.documents[URI]["version"], 1)

    def test_unopened_change_rejected_without_document_creation(self):
        session = self.session()
        self.assertIn("error", session.handle(changed()))
        self.assertEqual(session.documents, {})

    def test_duplicate_initialize_and_shutdown_gate(self):
        session = self.session()
        self.assertIn("error", session.handle(message("initialize", 99)))
        self.assertIsNone(session.handle(opened()))
        self.assertIsNone(session.handle(message("shutdown", 2))["result"])
        self.assertIn("error", session.handle(changed()))
        self.assertIsNone(session.handle(message("exit")))

    def test_optional_case_insensitive_headers(self):
        body = json.dumps(message("initialize", 1)).encode()
        data = (b"content-type: APPLICATION/VSCODE-JSONRPC;CHARSET=UTF-8\r\n"
                + b"content-length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        self.assertEqual(LSP.read_lsp_frame(io.BytesIO(data)), body)

    def test_duplicate_content_length_fails_closed(self):
        data = b"Content-Length: 2\r\nContent-Length: 3\r\n\r\n{}"
        with self.assertRaisesRegex(ValueError, "duplicate"):
            LSP.read_lsp_frame(io.BytesIO(data))

    def test_malformed_size_and_truncated_frame_fail_closed(self):
        for raw in (b"Content-Length: -1\r\n\r\n",
                    b"Content-Length: 1000000\r\n\r\n{}",
                    b"Content-Length: 5\r\n\r\n{}",
                    b"Content-Length: 1\n\n{}"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    LSP.read_lsp_frame(io.BytesIO(raw))

    def test_non_utf8_declared_content_type_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "content_type"):
            LSP.read_lsp_frame(io.BytesIO(
                b"Content-Length: 2\r\nContent-Type: application/vscode-jsonrpc; "
                b"charset=latin1\r\n\r\n{}"))

    def test_unknown_header_rejected(self):
        with self.assertRaisesRegex(ValueError, "header"):
            LSP.read_lsp_frame(io.BytesIO(
                b"Content-Length: 2\r\nX-Side-Channel: token\r\n\r\n{}"))

    def test_duplicate_json_key_not_accepted(self):
        body = b'{"jsonrpc":"2.0","id":1,"id":2}'
        content = b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        outputs = io.BytesIO()
        count = LSP.run_lsp(io.BytesIO(content), outputs, KEY)
        self.assertEqual(count, 0)
        self.assertIn(b"invalid_lsp_json", outputs.getvalue())

    def test_no_binary_content_returns_no_fabricated_response(self):
        outputs = io.BytesIO()
        self.assertEqual(LSP.run_lsp(io.BytesIO(b""), outputs, KEY), 0)
        self.assertEqual(outputs.getvalue(), b"")


if __name__ == "__main__":
    unittest.main()
