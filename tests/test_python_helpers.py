"""Hermetic tests for Rust's embedded Python helper scripts.

These tests NEVER execute the source being diagnosed.
"""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
VALIDATOR = (PROJECT / "python" / "verify.py").read_text(encoding="utf-8")
INVENTORY = (PROJECT / "python" / "package_inventory.py").read_text(encoding="utf-8")


class VerifyTests(unittest.TestCase):
    def check(self, code):
        with tempfile.TemporaryDirectory() as folder:
            script = Path(folder) / "sample.py"
            script.write_bytes(code)
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-c", VALIDATOR, str(script)],
                capture_output=True, text=True, check=True, timeout=5,
            )
            return json.loads(result.stdout)

    def test_valid_source(self):
        self.assertEqual(self.check(b"answer = 42\n")["compile"], "PASS")

    def test_syntax_error_with_line(self):
        result = self.check(b"if True\n    pass\n")
        self.assertEqual(result["compile"], "FAIL")
        self.assertEqual(result["error_type"], "SyntaxError")
        self.assertEqual(result["line"], 1)

    def test_never_executes_source(self):
        # A valid program that would fail if actually executed.
        result = self.check(b"raise RuntimeError('must not execute')\n")
        self.assertEqual(result["compile"], "PASS")

    def test_invalid_utf8(self):
        result = self.check(b"value = '\xff'\n")
        self.assertEqual(result["compile"], "FAIL")

    def test_declared_encoding(self):
        result = self.check(b"# coding: latin-1\nvalue = '\xe9'\n")
        self.assertEqual(result["compile"], "PASS")

    def test_compiler_rejects_return_outside_function(self):
        result = self.check(b"return 42\n")
        self.assertEqual(result["compile"], "FAIL")

    def test_audit_hook_counts_compilation_without_running_project_code(self):
        result = self.check(b"raise RuntimeError('do-not-execute')\n")
        self.assertEqual(result["compile"], "PASS")
        observed = result["audit_observation"]
        self.assertGreaterEqual(observed["events"]["compile"], 1)
        self.assertEqual(observed["events"]["exec"], 0)
        self.assertFalse(observed["security_boundary"])
        self.assertFalse(observed["arguments_collected"])

    def test_privacy_removes_untrusted_compiler_exception_details(self):
        result = self.check(b"secret = 'VERY_PRIVATE_TOKEN_42'\nif True\n pass\n")
        self.assertEqual(result["compile"], "FAIL")
        self.assertEqual(result["message"], "Diagnostic details withheld for privacy")
        self.assertNotIn("VERY_PRIVATE_TOKEN_42", json.dumps(result))
        self.assertNotIn("arguments", result["audit_observation"])


class MetadataTests(unittest.TestCase):
    def test_inventory_produces_versioned_json_lines(self):
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", INVENTORY],
            capture_output=True, text=True, check=True, timeout=10,
        )
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertTrue(all("name" in row and "version" in row for row in rows))
        self.assertTrue(all(isinstance(row["requires_dist"], list) for row in rows))


if __name__ == "__main__":
    unittest.main()
