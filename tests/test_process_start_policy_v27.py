"""F167: real trusted child-method policy, no untrusted project execution.

The requested forkserver remains NOT_RUN when the OS denies AF_UNIX sockets;
an explicitly proven spawn fallback does not convert that into a forkserver PASS.
"""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "python" / "concurrency_probe.py"
SPEC = importlib.util.spec_from_file_location("rph_process_policy_v27", SOURCE)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def primary(state):
    return {"method": "forkserver", "status": state,
            "child_executed_fixed_fixture": state == "PASS",
            "untrusted_source_executed": False}


class ProcessStartPolicyTests(unittest.TestCase):
    def test_fixed_fixture_and_timeout_cannot_accept_arbitrary_work(self):
        for fixture in ("import os", "__import__('os')", "", [], 1, True):
            with self.subTest(fixture=repr(fixture)), mock.patch.object(
                    module.multiprocessing, "get_context") as start, self.assertRaisesRegex(
                    ValueError, "unknown_fixed_process_fixture"):
                module.inspect_method("spawn", fixture=fixture)
            start.assert_not_called()
        for seconds in (0, -1, 6, True, "1", float("inf"), float("nan")):
            with self.subTest(timeout=repr(seconds)), mock.patch.object(
                    module.multiprocessing, "get_context") as start, self.assertRaisesRegex(
                    ValueError, "invalid_process_timeout"):
                module.inspect_method("spawn", timeout_seconds=seconds)
            start.assert_not_called()

    def test_unsupported_windows_methods_never_create_process_or_channels(self):
        for method in ("fork", "forkserver"):
            with self.subTest(method=method), mock.patch.object(
                    module.multiprocessing, "get_all_start_methods", return_value=["spawn"]), \
                    mock.patch.object(module.multiprocessing, "get_context") as start:
                observed = module.inspect_method(method)
            start.assert_not_called()
            self.assertEqual(observed["status"], "UNSUPPORTED_ON_PLATFORM")
            self.assertFalse(observed["child_started"])
            self.assertFalse(observed["cleanup"]["owned_process_created"])
            self.assertTrue(observed["cleanup"]["channels_closed"])

    def test_real_native_spawn_binds_parent_child_and_proves_handle_cleanup(self):
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE),
                                 "--qualify-default"], capture_output=True,
                                check=False, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr[:1024])
        observed = json.loads(result.stdout)["primary"]
        if sys.platform == "win32":
            self.assertEqual(observed["method"], "spawn")
            self.assertEqual(observed["status"], "PASS")
            self.assertTrue(observed["parent_identity_verified"])
            self.assertTrue(observed["child_pid_different"])
            self.assertTrue(observed["cleanup_verified"])
            self.assertEqual(observed["cleanup"]["child_exitcode"], 0)
            self.assertFalse(observed["cleanup"]["alive_after_cleanup"])
            self.assertTrue(observed["cleanup"]["process_handle_closed"])
            self.assertTrue(observed["cleanup"]["channels_closed"])
        else:
            self.assertIn(observed["status"], ("PASS", "NOT_RUN", "UNSUPPORTED_ON_PLATFORM"))

    def test_real_default_policy_executes_trusted_fixture_or_reports_denial(self):
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE),
                                 "--qualify-default"], capture_output=True,
                                check=False, timeout=12)
        self.assertEqual(result.returncode, 0, result.stderr[:1024])
        report = json.loads(result.stdout)
        self.assertEqual(report["requested_method"], module.multiprocessing.get_start_method())
        self.assertFalse(report["explicit_fallback_consent"])
        self.assertFalse(report["untrusted_source_executed"])
        self.assertFalse(report["implicit_security_sandbox"])
        self.assertIn(report["status"], ("PRIMARY_PASS", "NOT_RUN"))
        if report["status"] == "PRIMARY_PASS":
            self.assertEqual(report["effective_method"], report["requested_method"])
            self.assertEqual(report["primary"]["status"], "PASS")
        else:
            self.assertIsNone(report["effective_method"])
            self.assertNotEqual(report["primary"]["status"], "PASS")

    def test_real_explicit_spawn_fallback_is_measured_separately(self):
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE),
                                 "--qualify-default", "--allow-spawn-fallback"],
                                capture_output=True, check=False, timeout=12)
        self.assertEqual(result.returncode, 0, result.stderr[:1024])
        report = json.loads(result.stdout)
        self.assertTrue(report["explicit_fallback_consent"])
        self.assertFalse(report["untrusted_source_executed"])
        self.assertIn(report["status"], ("PRIMARY_PASS",
                                         "EXPLICIT_SPAWN_FALLBACK_PASS", "NOT_RUN"))
        if report["status"] == "EXPLICIT_SPAWN_FALLBACK_PASS":
            self.assertEqual(report["primary"]["status"], "NOT_RUN")
            self.assertEqual(report["effective_method"], "spawn")
            self.assertEqual(report["fallback"]["status"], "PASS")

    def test_primary_pass_without_fallback(self):
        with mock.patch.object(module, "inspect_method", return_value=primary("PASS")) as run:
            report = module.qualify_start_method("forkserver")
        self.assertEqual(report["status"], "PRIMARY_PASS")
        self.assertEqual(report["effective_method"], "forkserver")
        self.assertIsNone(report["fallback"])
        run.assert_called_once_with("forkserver")

    def test_denied_forkserver_does_not_silently_fallback(self):
        with mock.patch.object(module, "inspect_method", return_value=primary("NOT_RUN")) as run:
            report = module.qualify_start_method("forkserver")
        self.assertEqual(report["status"], "NOT_RUN")
        self.assertIsNone(report["effective_method"])
        run.assert_called_once_with("forkserver")

    def test_unsupported_primary_does_not_silently_fallback(self):
        with mock.patch.object(module, "inspect_method", return_value=primary("UNSUPPORTED_ON_PLATFORM")):
            report = module.qualify_start_method("forkserver")
        self.assertEqual(report["status"], "NOT_RUN")
        self.assertIsNone(report["effective_method"])

    def test_explicit_spawn_fallback_requires_its_own_pass(self):
        def fake(method):
            return {"forkserver": primary("NOT_RUN"),
                    "spawn": {"method": "spawn", "status": "PASS"}}[method]
        with mock.patch.object(module, "inspect_method", side_effect=fake) as run:
            report = module.qualify_start_method(
                "forkserver", module.EXPLICIT_SPAWN_FALLBACK_INTENT)
        self.assertEqual(report["status"], "EXPLICIT_SPAWN_FALLBACK_PASS")
        self.assertEqual(report["primary"]["status"], "NOT_RUN")
        self.assertEqual(report["effective_method"], "spawn")
        self.assertEqual([x.args[0] for x in run.call_args_list], ["forkserver", "spawn"])

    def test_denied_spawn_fallback_never_passes(self):
        with mock.patch.object(module, "inspect_method", return_value=primary("NOT_RUN")) as run:
            report = module.qualify_start_method(
                "forkserver", module.EXPLICIT_SPAWN_FALLBACK_INTENT)
        self.assertEqual(report["status"], "NOT_RUN")
        self.assertIsNone(report["effective_method"])
        self.assertEqual(run.call_count, 2)

    def test_explicit_fallback_on_spawn_never_retries_same_method(self):
        with mock.patch.object(module, "inspect_method", return_value=primary("NOT_RUN")) as run:
            report = module.qualify_start_method("spawn", module.EXPLICIT_SPAWN_FALLBACK_INTENT)
        self.assertEqual(report["status"], "NOT_RUN")
        run.assert_called_once_with("spawn")

    def test_invalid_requested_method_cannot_inject_process_target(self):
        for invalid in ("", "forkserver;id", "__import__('os')", [],
                        {}, 12, True):
            with self.subTest(invalid=repr(invalid)), self.assertRaisesRegex(
                    ValueError, "invalid_requested_start_method"):
                module.qualify_start_method(invalid)

    def test_invalid_fallback_intent_rejected_before_execution(self):
        for invalid in ("true", "ALLOW_FORK_FALLBACK", 1, True, "spawn"):
            with self.subTest(invalid=invalid), mock.patch.object(
                    module, "inspect_method") as run, self.assertRaisesRegex(
                    ValueError, "unknown_fallback_intent"):
                module.qualify_start_method("forkserver", invalid)
            run.assert_not_called()

    def test_default_method_is_observed_not_guessed(self):
        with mock.patch.object(module.multiprocessing, "get_start_method", return_value="spawn"), \
                mock.patch.object(module, "inspect_method", return_value=primary("PASS")) as run:
            report = module.qualify_start_method()
        self.assertEqual(report["requested_method"], "spawn")
        self.assertTrue(report["default_was_requested"])
        run.assert_called_once_with("spawn")

    def test_unknown_default_rejected_before_worker(self):
        with mock.patch.object(module.multiprocessing, "get_start_method", return_value="other"), \
                mock.patch.object(module, "inspect_method") as run, self.assertRaisesRegex(
                ValueError, "unsupported_default_start_method"):
            module.qualify_start_method()
        run.assert_not_called()

    def test_cli_blocks_ambiguous_consent_flag(self):
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE),
                                 "--allow-spawn-fallback"], capture_output=True,
                                timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"requires --qualify-default", result.stderr)

    def test_cli_blocks_method_and_default_in_same_command(self):
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE),
                                 "--qualify-default", "--method", "forkserver"],
                                capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"does not accept --method", result.stderr)


if __name__ == "__main__":
    unittest.main()
