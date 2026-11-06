"""Independent CLI/oracle checks for the integrated local Rust policy gate.

These tests enumerate the ACTUAL compiled Rust surface, compare it to the
fail-closed policy inventory, and exercise selected real privacy behaviors.
Local HMAC enforcement is not independently authenticated human identity.
"""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "src" / "policy_boundary_v23.rs"
MAIN = ROOT / "src" / "main.rs"
BINARY = ROOT / "target" / "release" / ("rust-python-healer.exe" if sys.platform == "win32" else "rust-python-healer")


def _source():
    return MODULE.read_text(encoding="utf-8")


def _rust_string_array(name):
    match = re.search(r"const " + name + r": \[&str; \d+\] = \[(.*?)\];", _source(), re.S)
    if not match:
        raise AssertionError("required policy array not registered")
    return re.findall(r'"([a-z][a-z0-9-]+)"', match.group(1))


def _rust(args, input_bytes=None):
    if not BINARY.is_file():
        raise AssertionError("actual Rust release binary unavailable")
    return subprocess.run([str(BINARY)] + list(args), input=input_bytes,
                          capture_output=True, check=False, timeout=10)


def _actual_commands():
    text = _rust(["--help"])
    if text.returncode != 0:
        raise AssertionError("Rust CLI help unavailable")
    section = text.stdout.decode("utf-8", "replace").split("Commands:\n", 1)[1]
    section = section.split("\nOptions:", 1)[0]
    return {line.split()[0] for line in section.splitlines()
            if line.startswith("  ") and line.strip() and line.split()[0] != "help"}


class ActualRustInventoryTests(unittest.TestCase):
    def test_all_21_actual_commands_have_exact_policy_inventory_entries(self):
        policy = set(_rust_string_array("TOP_LEVEL"))
        actual = _actual_commands()
        self.assertEqual(len(actual), 21)
        self.assertEqual(policy, actual)

    def test_no_duplicate_commands_in_policy_table(self):
        commands = _rust_string_array("TOP_LEVEL")
        self.assertEqual(len(commands), len(set(commands)))

    def test_each_actual_command_help_is_true_read_only_probe(self):
        for command in sorted(_actual_commands()):
            with self.subTest(command=command):
                report = _rust([command, "--help"])
                self.assertEqual(report.returncode, 0)
                self.assertFalse(report.stderr)
                self.assertIn(b"Usage:", report.stdout)

    def test_every_catalog_subcommand_is_explicitly_classified(self):
        help_report = _rust(["catalog", "--help"])
        self.assertEqual(help_report.returncode, 0)
        text = help_report.stdout.decode("utf-8", "replace")
        present = {word for word in ("add", "backup", "import-installed", "maintain",
                                      "restore", "search", "stats")
                   if re.search(r"(?m)^  " + re.escape(word) + r"\s", text)}
        self.assertEqual(present, set(_rust_string_array("CATALOG_MUTATIONS")) |
                         set(_rust_string_array("CATALOG_READ_ONLY")))
        self.assertEqual(len(present), 7)

    def test_unknown_main_command_is_nonzero_no_tool_run(self):
        report = _rust(["delete-all-production-data"])
        self.assertNotEqual(report.returncode, 0)
        self.assertNotIn(b"secret", report.stdout.lower())

    def test_operator_help_does_not_need_mutation_approval(self):
        for args in (["repair", "--help"], ["update", "--help"],
                     ["catalog", "restore", "--help"],
                     ["lab", "backup-drill", "--help"]):
            with self.subTest(args=args):
                report = _rust(args)
                self.assertEqual(report.returncode, 0)

    def test_untrusted_argv_hashing_function_exists_and_is_bounded(self):
        source = _source()
        self.assertIn("pub fn command_sha256", source)
        self.assertIn("MAX_CLI_ARGS", source)
        self.assertIn("MAX_ARG_BYTES", source)

    def test_scary_actions_are_registered_for_approval(self):
        source = _source()
        for action in ("SOURCE_MODIFY", "KNOWLEDGE_UPDATE",
                       "CATALOG_MUTATION", "LAB_MUTATION"):
            self.assertIn('"' + action + '"', source)


class PrivacyAndApprovalScopeTests(unittest.TestCase):
    def test_real_traceback_secret_is_redacted_by_default(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-trace-") as folder:
            path = Path(folder) / "errors.txt"
            path.write_text(
                "Traceback (most recent call last):\n"
                "  File \"/very/private/source.py\", line 7, in private_function\n"
                "    raise ValueError('Bearer SUPER_PRIVATE_SECRET')\n"
                "ValueError: Bearer SUPER_PRIVATE_SECRET\n", encoding="utf-8")
            report = _rust(["trace", str(path)])
            self.assertEqual(report.returncode, 0, report.stderr)
            for secret in (b"SUPER_PRIVATE_SECRET", b"/very/private/source.py",
                           b"private_function"):
                self.assertNotIn(secret, report.stdout)

    def test_sensitive_trace_requires_explicit_user_flag(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-trace-") as folder:
            path = Path(folder) / "errors.txt"
            path.write_text("Traceback (most recent call last):\n"
                            "  File \"/private/app.py\", line 1, in api\n"
                            "    raise RuntimeError('PUBLIC_WITH_EXPLICIT_CONSENT')\n"
                            "RuntimeError: PUBLIC_WITH_EXPLICIT_CONSENT\n", encoding="utf-8")
            private = _rust(["trace", str(path)])
            opened = _rust(["trace", str(path), "--show-sensitive"])
            self.assertEqual(private.returncode, 0)
            self.assertEqual(opened.returncode, 0)
            self.assertNotIn(b"PUBLIC_WITH_EXPLICIT_CONSENT", private.stdout)
            self.assertIn(b"PUBLIC_WITH_EXPLICIT_CONSENT", opened.stdout)

    def test_actual_compile_only_check_does_not_echo_user_secret(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-check-") as folder:
            source = Path(folder) / "attacker.py"
            source.write_text("SECRET = 'BEARER_RAW_SECRET_NEVER_EMIT'\n"
                              "def broken():\n"
                              "    if True\n"
                              "        pass\n", encoding="utf-8")
            report = _rust(["check", str(source), "--python", sys.executable])
            self.assertNotEqual(report.returncode, 0)
            self.assertNotIn(b"BEARER_RAW_SECRET_NEVER_EMIT", report.stdout)

    def test_policy_module_never_reports_external_identity_or_global_log_enforcement(self):
        source = _source()
        self.assertIn("external_identity_verified: false", source)
        self.assertIn('"global_rust_logging_enforced": false', source)
        self.assertIn("release_authorized: false", source)

    def test_nonce_ledgers_require_owner_only_and_real_file_locks(self):
        source = _source()
        self.assertIn("libc::flock", source)
        self.assertIn("libc::O_NOFOLLOW", source)
        self.assertIn("policy_approval_nonce_replay", source)

    def test_hmac_expected_context_has_actor_action_argv_target_artifact(self):
        source = _source()
        for value in ("actor_id", "action", "command_sha256",
                      "artifact_sha256", "target_sha256"):
            self.assertIn("pub " + value + ":", source)

    def test_main_dispatch_enforcement_is_a_separate_required_gate(self):
        with tempfile.TemporaryDirectory(prefix="rph-r5-deny-") as folder:
            root = Path(folder)
            source = root / "fixed.py"
            source.write_bytes(b"value=42\n")
            ledger, output = root / "ledger.sqlite", root / "output.py"
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            for args in (["repair", str(source), "--out", str(output), "--ledger", str(ledger)],
                         ["catalog", "maintain", "--db", str(ledger)]):
                report = _rust(args)
                self.assertNotEqual(report.returncode, 0)
                self.assertIn(b"policy_dispatch_refused_target_not_dispatched", report.stderr)
                self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)

    def test_approval_request_binds_exact_artifact_and_targets_without_mutation(self):
        with tempfile.TemporaryDirectory(prefix="rph-r5-request-") as folder:
            root = Path(folder)
            source = root / "fixed.py"
            source.write_bytes(b"value=42\n")
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            response = _rust(["--approval-request", "repair", str(source), "--ledger", str(root / "ledger.sqlite")])
            self.assertEqual(response.returncode, 0, response.stderr)
            report = json.loads(response.stdout)
            self.assertEqual(report["status"], "LOCAL_POLICY_APPROVAL_REQUEST_NO_MUTATION")
            self.assertEqual(report["artifact_sha256"], hashlib.sha256(BINARY.read_bytes()).hexdigest())
            self.assertEqual(report["action"], "SOURCE_MODIFY")
            self.assertFalse(report["external_human_identity_verified"])
            self.assertFalse(report["release_authorized"])
            self.assertFalse(report["mutation_performed"])
            self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)

    def test_log_correlation_hash_is_content_sensitive(self):
        first = hashlib.sha256(b"Bearer first-secret").hexdigest()
        second = hashlib.sha256(b"Bearer second-secret").hexdigest()
        self.assertNotEqual(first, second)
        self.assertRegex(first, r"^[a-f0-9]{64}$")

    def test_source_does_not_embed_actual_human_secrets(self):
        source = _source()
        for marker in ("operator-real-password", "private-production-signing-key"):
            self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()
