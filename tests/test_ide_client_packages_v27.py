"""Offline IDE client packages and real CPython LSP conformance (v0.27).

Node tests launch the real Python backend once for each interpreter under test.
This does not claim a genuine VS Code or JetBrains IDE runtime was started.
"""

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VSCODE = ROOT / "integrations" / "vscode-v27"
PYCHARM = ROOT / "integrations" / "pycharm-v27"
BACKEND = ROOT / "python" / "developer_protocols_v21.py"


def load_launcher():
    spec = importlib.util.spec_from_file_location("v27_ide_launcher", PYCHARM / "start_lsp.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def frames(data):
    result = []
    while data:
        header, marker, remainder = data.partition(b"\r\n\r\n")
        if not marker or not header.startswith(b"Content-Length: "):
            raise AssertionError("invalid LSP response framing")
        count = int(header.split(b": ", 1)[1]); message = remainder[:count]
        if len(message) != count:
            raise AssertionError("truncated LSP response")
        result.append(json.loads(message))
        data = remainder[count:]
    return result


def request(value):
    data = json.dumps(value, separators=(",", ":")).encode("utf8")
    return b"Content-Length: " + str(len(data)).encode("ascii") + b"\r\n\r\n" + data


class IdeClientPackagesV27(unittest.TestCase):
    def test_vscode_manifest_is_local_no_runtime_network_dependencies(self):
        manifest = json.loads((VSCODE / "package.json").read_text(encoding="utf8"))
        self.assertEqual(manifest["main"], "./extension.js")
        self.assertEqual(manifest["extensionKind"], ["workspace"])
        self.assertNotIn("dependencies", manifest)
        self.assertNotIn("devDependencies", manifest)
        self.assertIn("rphReviewed.loadApproval", [c["command"] for c in manifest["contributes"]["commands"]])
        self.assertIn("rphReviewed.restartServer", [c["command"] for c in manifest["contributes"]["commands"]])
        self.assertIn("onLanguage:python", manifest["activationEvents"])
        for name in ("pythonExecutable", "serverScript", "reviewKeyFile"):
            self.assertEqual(manifest["contributes"]["configuration"]["properties"]["rphReviewed." + name]["scope"], "machine")

    def test_vscode_js_syntax_checks(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node executable unavailable: VS Code client runtime NOT_RUN")
        for file in (VSCODE / "extension.js", VSCODE / "lsp_client.js", VSCODE / "tests" / "lsp_client.test.js", VSCODE / "tests" / "extension.test.js"):
            completed = subprocess.run([node, "--check", str(file)], check=False,
                                       capture_output=True, timeout=15)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))

    def test_real_node_lsp_suite_for_this_python_minor(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node executable unavailable: live VS Code client transport NOT_RUN")
        env = os.environ.copy()
        env["RPH_PYTHON"] = sys.executable
        completed = subprocess.run([node, "--test", str(VSCODE / "tests" / "lsp_client.test.js"),
                                    str(VSCODE / "tests" / "extension.test.js")],
                                   cwd=str(ROOT), capture_output=True, check=False,
                                   env=env, timeout=45)
        output = completed.stdout.decode(errors="replace") + completed.stderr.decode(errors="replace")
        self.assertEqual(completed.returncode, 0, output[-6000:])
        self.assertIn("pass 24", output)
        self.assertIn("fail 0", output)

    def test_pycharm_lsp4ij_importable_template_schema(self):
        template = json.loads((PYCHARM / "template.json").read_text(encoding="utf8"))
        self.assertEqual(template["id"], "rust-python-healer-reviewed-offline-v27")
        self.assertIn("$PROJECT_DIR$/integrations/pycharm-v27/start_lsp.py", template["programArgs"]["default"])
        self.assertEqual(template["fileTypeMappings"][0]["languageId"], "python")
        self.assertIn("*.py", template["fileTypeMappings"][0]["fileType"]["patterns"])

    def test_pycharm_launcher_uses_exact_local_backend(self):
        launcher = load_launcher()
        with tempfile.TemporaryDirectory(dir=str(ROOT)) as workspace:
            key = Path(workspace) / "private.key"
            key.write_bytes(b"unit-test-private-review-key-v27")
            key.chmod(0o600)
            if os.name == "nt":
                import windows_privacy_fixtures
                windows_privacy_fixtures.set_private_acl(key)
            old = os.environ.get("RPH_LSP_KEY_FILE")
            try:
                os.environ["RPH_LSP_KEY_FILE"] = str(key)
                command = launcher.checked_launch()
                self.assertEqual(command[0], sys.executable)
                self.assertEqual(Path(command[1]), BACKEND.resolve())
                self.assertEqual(command[2:4], ["--mode", "lsp"])
                self.assertEqual(command[4:6], ["--key-file", str(key)])
            finally:
                if old is None:
                    os.environ.pop("RPH_LSP_KEY_FILE", None)
                else:
                    os.environ["RPH_LSP_KEY_FILE"] = old

    def test_pycharm_launcher_rejects_missing_and_relative_key(self):
        launcher = load_launcher()
        old = os.environ.get("RPH_LSP_KEY_FILE")
        try:
            for value in ("", "relative.key"):
                os.environ["RPH_LSP_KEY_FILE"] = value
                with self.assertRaisesRegex(ValueError, "absolute_private_key_path_required"):
                    launcher.checked_launch()
        finally:
            if old is None:
                os.environ.pop("RPH_LSP_KEY_FILE", None)
            else:
                os.environ["RPH_LSP_KEY_FILE"] = old

    def test_pycharm_launcher_rejects_symbolic_key_and_world_readable_key(self):
        launcher = load_launcher()
        old = os.environ.get("RPH_LSP_KEY_FILE")
        with tempfile.TemporaryDirectory(dir=str(ROOT)) as workspace:
            key = Path(workspace) / "private.key"
            key.write_bytes(b"unit-test-private-review-key-v27")
            key.chmod(0o600)
            if os.name == "nt":
                import windows_privacy_fixtures
                windows_privacy_fixtures.set_private_acl(key)
            link = Path(workspace) / "link.key"
            link.symlink_to(key)
            try:
                os.environ["RPH_LSP_KEY_FILE"] = str(link)
                with self.assertRaisesRegex(ValueError, "invalid_private_key"):
                    launcher.checked_launch()
                key.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
                if os.name == "nt":
                    windows_privacy_fixtures.set_public_read_acl(key)
                os.environ["RPH_LSP_KEY_FILE"] = str(key)
                with self.assertRaisesRegex(ValueError, "review_key_must_be_private"):
                    launcher.checked_launch()
            finally:
                if old is None:
                    os.environ.pop("RPH_LSP_KEY_FILE", None)
                else:
                    os.environ["RPH_LSP_KEY_FILE"] = old

    def test_pycharm_launcher_rejects_short_key(self):
        launcher = load_launcher()
        old = os.environ.get("RPH_LSP_KEY_FILE")
        with tempfile.TemporaryDirectory(dir=str(ROOT)) as workspace:
            key = Path(workspace) / "short.key"
            key.write_bytes(b"too-short")
            key.chmod(0o600)
            if os.name == "nt":
                import windows_privacy_fixtures
                windows_privacy_fixtures.set_private_acl(key)
            try:
                os.environ["RPH_LSP_KEY_FILE"] = str(key)
                with self.assertRaisesRegex(ValueError, "invalid_private_key"):
                    launcher.checked_launch()
            finally:
                if old is None:
                    os.environ.pop("RPH_LSP_KEY_FILE", None)
                else:
                    os.environ["RPH_LSP_KEY_FILE"] = old

    def test_pycharm_launcher_real_stdio_initialize_shutdown(self):
        with tempfile.TemporaryDirectory(dir=str(ROOT)) as workspace:
            key = Path(workspace) / "private.key"
            key.write_bytes(b"unit-test-private-review-key-v27")
            key.chmod(0o600)
            if os.name == "nt":
                import windows_privacy_fixtures
                windows_privacy_fixtures.set_private_acl(key)
            env = os.environ.copy()
            env["RPH_LSP_KEY_FILE"] = str(key)
            requests = b"".join((
                request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                request({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
                request({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {
                    "textDocument": {"uri": "file:///jetbrains.py", "version": 1, "text": "x = 1\n"}}}),
                request({"jsonrpc": "2.0", "id": 2, "method": "textDocument/codeAction", "params": {
                    "textDocument": {"uri": "file:///jetbrains.py"}}}),
                request({"jsonrpc": "2.0", "id": 3, "method": "shutdown", "params": {}}),
                request({"jsonrpc": "2.0", "method": "exit", "params": {}}),
            ))
            process = subprocess.run([sys.executable, str(PYCHARM / "start_lsp.py")], input=requests,
                                     capture_output=True, check=False, env=env,
                                     cwd=str(ROOT), timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace"))
            responses = frames(process.stdout)
            self.assertEqual([x["id"] for x in responses], [1, 2, 3])
            self.assertEqual(responses[0]["result"]["capabilities"]["textDocumentSync"], 1)
            self.assertEqual(responses[1]["error"]["message"], "invalid_approval_schema")
            self.assertIsNone(responses[2]["result"])

    def test_pycharm_launcher_fails_closed_without_key(self):
        env = os.environ.copy()
        env.pop("RPH_LSP_KEY_FILE", None)
        completed = subprocess.run([sys.executable, str(PYCHARM / "start_lsp.py")],
                                   capture_output=True, check=False, env=env, timeout=10)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, b"")
        self.assertIn(b"rejected", completed.stderr)


if __name__ == "__main__":
    unittest.main()
