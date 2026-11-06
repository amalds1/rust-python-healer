"""Windows must be able to import the legacy updater without activating ELF."""

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))
SPEC = importlib.util.spec_from_file_location(
    "windows_gate_binary_update_v27", ROOT / "python" / "binary_self_update_v27.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class LegacyUpdaterWindowsGateTests(unittest.TestCase):
    def test_windows_preview_and_apply_refuse_before_verifier_or_filesystem(self):
        with tempfile.TemporaryDirectory() as folder:
            release = Path(folder) / "release"
            for apply in (False, True):
                with self.subTest(apply=apply), \
                     mock.patch.object(module.sys, "platform", "win32"), \
                     mock.patch.object(module, "_verify_crypto_verifier_pin") as verifier, \
                     mock.patch.object(module, "verify_signed") as signature, \
                     self.assertRaisesRegex(ValueError, "windows_no_mutation"):
                    module.offline_self_update(
                        release, {}, b"bad", b"bad", b"MZ", b"bad", {},
                        openssl_bin="C:\\fake\\openssl.exe", apply=apply)
                verifier.assert_not_called()
                signature.assert_not_called()
                self.assertFalse(release.exists())

    def test_non_linux_platform_refused_too(self):
        with mock.patch.object(module.sys, "platform", "darwin"), \
             self.assertRaisesRegex(ValueError, "windows_no_mutation"):
            module.offline_self_update(None, None, None, None, None, None,
                                       None, apply=False)

    def test_linux_lock_requires_actual_fcntl(self):
        with mock.patch.object(module, "fcntl", None), \
             self.assertRaisesRegex(ValueError, "not_available_on_windows"):
            module._lock(Path("not-existing"))

    def test_boolean_apply_remains_required_before_platform_gate(self):
        with mock.patch.object(module.sys, "platform", "win32"), \
             self.assertRaisesRegex(ValueError, "explicit_boolean_apply_required"):
            module.offline_self_update(None, None, None, None, None, None,
                                       None, apply="true")


if __name__ == "__main__":
    unittest.main()
