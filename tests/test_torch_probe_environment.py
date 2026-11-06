"""Windows native system root is necessary; parent secrets and import paths remain excluded."""

import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("torch_probe_env", ROOT / "python/pytorch_runtime_v27.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TorchProbeEnvironmentTests(unittest.TestCase):
    def _run_captured(self, platform, parent):
        identity = {"status": "REAL_INSTALLED_TORCH_CPU_FIXED_FIXTURE_PASS",
                    "cpu_sum": [5., 7., 9.], "checkpoint_from_user_loaded": False,
                    "gpu_verified": False, "torch_version": "2.11.0+cu128",
                    "fixed_negative_oracles": ["INVALID_DEVICE_REJECTED"]}
        child = subprocess.CompletedProcess([], 0, json.dumps(identity).encode(), b"")
        with mock.patch.object(module.sys, "platform", platform), \
                mock.patch.dict(module.os.environ, parent, clear=True), \
                mock.patch.object(module, "installed_torch_metadata", return_value={
                    "status": "LOCAL_TORCH_METADATA_ONLY", "distribution_version": "2.11.0+cu128"}), \
                mock.patch.object(module.subprocess, "run", return_value=child) as run:
            result = module.probe_installed_torch_cpu()
        self.assertEqual(result["status"], "PASS_REAL_INSTALLED_TORCH_CPU_FIXED_FIXTURE_ONLY")
        self.assertEqual(run.call_args.args[0][-1], module.CPU_FIXTURE)
        self.assertIn("-I", run.call_args.args[0])
        return run.call_args.kwargs["env"]

    def test_windows_only_systemroot_added_without_secrets_or_import_overrides(self):
        parent = {"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows",
                  "PATH": r"C:\untrusted-bin", "PYTHONPATH": r"C:\untrusted-python",
                  "PYTHONHOME": r"C:\untrusted-home", "API_TOKEN": "never-copy-me"}
        env = self._run_captured("win32", parent)
        self.assertEqual(set(env), {"SystemRoot", "PATH", "OMP_NUM_THREADS", "MKL_NUM_THREADS", "PYTHONIOENCODING"})
        self.assertEqual(env["SystemRoot"], parent["SystemRoot"])
        self.assertEqual(env["PATH"], module.os.defpath)
        self.assertNotIn("never-copy-me", json.dumps(env))
        self.assertNotIn("PYTHONPATH", env)
        self.assertNotIn("PYTHONHOME", env)
        self.assertNotIn("WINDIR", env)

    def test_missing_systemroot_does_not_expand_environment_allowlist(self):
        env = self._run_captured("win32", {"WINDIR": r"C:\Windows", "API_TOKEN": "never-copy-me"})
        self.assertEqual(set(env), {"PATH", "OMP_NUM_THREADS", "MKL_NUM_THREADS", "PYTHONIOENCODING"})

    def test_non_windows_environment_behavior_is_preserved(self):
        env = self._run_captured("linux", {"SystemRoot": r"C:\Windows", "PYTHONPATH": "bad", "API_TOKEN": "never-copy-me"})
        self.assertEqual(env, {"PATH": module.os.defpath, "OMP_NUM_THREADS": "1", "MKL_NUM_THREADS": "1", "PYTHONIOENCODING": "utf-8"})


if __name__ == "__main__":
    unittest.main()
