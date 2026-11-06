"""Proof of real local opt-in canary swaps/rollback, not binary auto-update."""

import hashlib
import ctypes
from ctypes import wintypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import windows_privacy_fixtures as privacy_fixtures
SCRIPT = ROOT / "python" / "release_canary_v21.py"
spec = importlib.util.spec_from_file_location("release_canary_v21", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class CanaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rph-v21-canary-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        if os.name == "nt":
            privacy_fixtures.set_private_acl(self.folder)
        self.active = self.folder / "active.json"
        self.candidate = self.folder / "candidate.json"
        self.key = b"this-is-trusted-local-human-approval-key"
        self.before = json.dumps({"release": "old", "health": "ready"}, sort_keys=True).encode()
        self.after = json.dumps({"release": "new", "health": "ready"}, sort_keys=True).encode()
        self.active.write_bytes(self.before)
        self.candidate.write_bytes(self.after)
        self.manifest = {"schema": 1, "operation": "local_canary", "actor": "fixture-reviewer",
                         "release": "new", "old_sha256": hashlib.sha256(self.before).hexdigest(),
                         "candidate_sha256": hashlib.sha256(self.after).hexdigest()}
        self.signature = mod.canary_signature(self.manifest, self.key)

    def run_canary(self, **kwargs):
        return mod.local_canary(self.active, self.candidate, self.manifest,
                                self.signature, self.key, **kwargs)

    def test_staged_privacy_refusal_closes_real_descriptor_and_removes_file(self):
        real_mkstemp = mod.tempfile.mkstemp
        captured = []
        def capture(*args, **kwargs):
            result = real_mkstemp(*args, **kwargs)
            captured.append(result)
            return result
        boundary, attribute = ((mod.platform_privacy, "private_descriptor") if os.name == "nt"
                               else (mod.os, "fchmod"))
        def native_handle_count():
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.GetCurrentProcess.restype = wintypes.HANDLE
            kernel.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            count = wintypes.DWORD()
            self.assertTrue(kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), ctypes.byref(count)))
            return count.value
        before_handles = native_handle_count() if os.name == "nt" else None
        with mock.patch.object(mod.tempfile, "mkstemp", side_effect=capture), \
                mock.patch.object(boundary, attribute, side_effect=ValueError("fixture privacy refused")):
            for _ in range(25):
                with self.assertRaisesRegex(ValueError, "fixture privacy refused"):
                    mod._write_unique(self.folder, ".refused-stage-", b"must never be written")
                descriptor, path = captured[-1]
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
                self.assertFalse(Path(path).exists())
        self.assertEqual(len(captured), 25)
        self.assertFalse(list(self.folder.glob(".refused-stage-*")))
        if os.name == "nt":
            after_handles = native_handle_count()
            self.assertLessEqual(after_handles, before_handles)
            print(json.dumps({"fixture": "canary_private_stage_cleanup", "iterations": 25,
                              "handles_before": before_handles, "handles_after": after_handles,
                              "all_original_errors_preserved": True,
                              "all_staged_descriptors_closed": True,
                              "staged_paths_remaining": 0}))

    def test_staged_fdopen_construction_failure_closes_descriptor_and_removes_file(self):
        real_mkstemp = mod.tempfile.mkstemp
        captured = []
        def capture(*args, **kwargs):
            result = real_mkstemp(*args, **kwargs)
            captured.append(result)
            return result
        with mock.patch.object(mod.tempfile, "mkstemp", side_effect=capture), \
                mock.patch.object(mod.os, "fdopen", side_effect=ValueError("fixture fdopen failure")):
            with self.assertRaisesRegex(ValueError, "fixture fdopen failure"):
                mod._write_unique(self.folder, ".failed-wrapper-", b"must never be written")
        descriptor, path = captured[0]
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        self.assertFalse(Path(path).exists())

    def test_real_trusted_subprocess_health_promotes_signed_candidate(self):
        report = self.run_canary()
        self.assertEqual(report["status"], "CANARY_HEALTH_PASS_LOCAL_ONLY")
        self.assertTrue(report["canary_promoted"])
        self.assertTrue(report["health_subprocess_invoked"])
        self.assertFalse(report["unknown_release_executed"])
        self.assertFalse(report["production_binary_self_update_verified"])
        self.assertEqual(self.active.read_bytes(), self.after)

    def test_injected_post_swap_health_failure_restores_exact_old_bytes(self):
        report = self.run_canary(inject_health_failure=True)
        self.assertEqual(report["status"], "CANARY_FAILED_ROLLED_BACK")
        self.assertTrue(report["automatic_rollback_verified"])
        self.assertFalse(report["canary_promoted"])
        self.assertEqual(self.active.read_bytes(), self.before)
        self.assertEqual(report["active_sha256"], self.manifest["old_sha256"])
        self.assertFalse((self.folder / ".canary-active.lock").exists())

    def test_real_health_negative_rejects_wrong_release_field(self):
        self.candidate.write_bytes(json.dumps({"release": "other", "health": "ready"}).encode())
        self.manifest["candidate_sha256"] = hashlib.sha256(self.candidate.read_bytes()).hexdigest()
        self.signature = mod.canary_signature(self.manifest, self.key)
        report = self.run_canary()
        self.assertEqual(report["status"], "CANARY_FAILED_ROLLED_BACK")
        self.assertEqual(self.active.read_bytes(), self.before)

    def test_real_health_negative_rejects_unhealthy_candidate(self):
        self.candidate.write_bytes(json.dumps({"release": "new", "health": "broken"}).encode())
        self.manifest["candidate_sha256"] = hashlib.sha256(self.candidate.read_bytes()).hexdigest()
        self.signature = mod.canary_signature(self.manifest, self.key)
        self.assertTrue(self.run_canary()["automatic_rollback_verified"])
        self.assertEqual(self.active.read_bytes(), self.before)

    def test_invalid_approval_cannot_change_active_file(self):
        with self.assertRaisesRegex(ValueError, "approval"):
            mod.local_canary(self.active, self.candidate, self.manifest, "a" * 64,
                             self.key)
        self.assertEqual(self.active.read_bytes(), self.before)

    def test_mismatch_old_manifest_cannot_change_active_file(self):
        self.manifest["old_sha256"] = "f" * 64
        self.signature = mod.canary_signature(self.manifest, self.key)
        with self.assertRaisesRegex(ValueError, "stale_or_corrupted"):
            self.run_canary()
        self.assertEqual(self.active.read_bytes(), self.before)

    def test_damaged_candidate_rejected_before_swap(self):
        self.candidate.write_text("tampered", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "stale_or_corrupted"):
            self.run_canary()
        self.assertEqual(self.active.read_bytes(), self.before)

    def test_symlinks_or_hardlinks_not_used_for_release_swap(self):
        clone = self.folder / "clone"
        os.link(self.candidate, clone)
        with self.assertRaisesRegex(ValueError, "unsafe_or_unbounded"):
            self.run_canary()
        clone.unlink()
        self.candidate.unlink()
        self.candidate.symlink_to(self.active)
        with self.assertRaisesRegex(ValueError, "unsafe_or_unbounded"):
            self.run_canary()
        self.assertEqual(self.active.read_bytes(), self.before)

    def test_private_canary_directory_is_required(self):
        if os.name == "nt":
            privacy_fixtures.set_public_read_acl(self.folder)
        else:
            self.folder.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private"):
            self.run_canary()
        self.assertEqual(self.active.read_bytes(), self.before)

    def test_duplicate_release_attempt_is_not_a_new_candidate(self):
        self.run_canary()
        with self.assertRaisesRegex(ValueError, "stale_or_corrupted"):
            self.run_canary()
        self.assertEqual(self.active.read_bytes(), self.after)

    def test_cli_full_signature_and_real_subprocess_positive(self):
        approval = self.folder / "approval.json"
        keyfile = self.folder / "key"
        keyfile.write_bytes(self.key)
        keyfile.chmod(0o600)
        approval.write_text(json.dumps({"manifest": self.manifest,
                                        "signature": self.signature}), encoding="utf-8")
        command = [sys.executable, "-I", "-S", "-B", str(SCRIPT),
                   "--active", str(self.active), "--candidate", str(self.candidate),
                   "--key-file", str(keyfile), "--approval", str(approval),
                   "--python", sys.executable]
        run = subprocess.run(command, capture_output=True, check=False, timeout=8)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)["status"], "CANARY_HEALTH_PASS_LOCAL_ONLY")
        self.assertEqual(self.active.read_bytes(), self.after)

    def test_cli_rejects_public_review_key(self):
        approval = self.folder / "approval.json"
        keyfile = self.folder / "key"
        keyfile.write_bytes(self.key)
        if os.name == "nt":
            privacy_fixtures.set_public_read_acl(keyfile)
        else:
            keyfile.chmod(0o644)
        approval.write_text(json.dumps({"manifest": self.manifest,
                                        "signature": self.signature}), encoding="utf-8")
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                     "--active", str(self.active), "--candidate", str(self.candidate),
                     "--key-file", str(keyfile), "--approval", str(approval)],
                     capture_output=True, check=False, timeout=8)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(self.active.read_bytes(), self.before)


if __name__ == "__main__":
    unittest.main()
