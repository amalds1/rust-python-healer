"""F245 real pip install into private disposable target on selected interpreter."""

from contextlib import closing
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "distribution_probe_v21.py"
spec = importlib.util.spec_from_file_location("distribution_probe_v21", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def selected_bundle():
    match = re.search(r'(?m)^version = "(\d+\.\d+)\.\d+"',
                      (ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    assert match, "Cargo version missing"
    return ROOT / "dist" / ("offline-v" + match.group(1))


class DistributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = selected_bundle()
        cls.metadata = json.loads((cls.bundle / "release_manifest.json").read_text())
        cls.pin = cls.metadata["sha256"][cls.metadata["python_wheel"]]

    def test_actual_offline_wheel_installs_and_owned_cli_imports(self):
        detail = mod.verify_offline_install(self.bundle, sys.executable, self.pin)
        self.assertEqual(detail["status"], "OFFLINE_WHEEL_INSTALLED_TO_PRIVATE_TARGET")
        self.assertEqual(detail["python_minor"], "{}.{}".format(*sys.version_info[:2]))
        self.assertTrue(detail["owned_python_cli_imported"])
        self.assertFalse(detail["global_install_performed"])
        self.assertFalse(detail["installer_used_network"])
        self.assertFalse(detail["publisher_authenticated"])

    def test_private_pip_wheel_override_cannot_bypass_official_digest(self):
        with tempfile.TemporaryDirectory(prefix="rph-pip-pin-") as folder:
            forged = Path(folder) / "pip.whl"
            forged.write_bytes(b"forged installer")
            with mock.patch.dict(mod.__dict__, {"_RPH_PINNED_PIP_WHEEL": str(forged)}):
                with self.assertRaisesRegex(ValueError, "private_pip_tool_wheel_pin_mismatch"):
                    mod._windows_pip_bootstrap(sys.executable)

    def test_split_own_wheel_binary_and_launcher_are_independent_files(self):
        detail = mod.inspect_split_bundle(self.bundle)
        self.assertEqual(detail["status"], "SPLIT_OFFLINE_RELEASE_HASHES_VERIFIED")
        self.assertEqual(len({detail["wheel"], detail["rust_archive"], detail["launcher"]}), 3)
        self.assertTrue((self.bundle / detail["wheel"]).is_file())
        self.assertTrue((self.bundle / detail["rust_archive"]).is_file())
        self.assertTrue((self.bundle / detail["launcher"]).is_file())

    def test_out_of_band_pin_is_mandatory_before_install(self):
        with self.assertRaisesRegex(ValueError, "out_of_band"):
            mod.verify_offline_install(self.bundle, sys.executable, "")
        with self.assertRaisesRegex(ValueError, "trust_pin"):
            mod.verify_offline_install(self.bundle, sys.executable, "f" * 64)

    def test_forged_manifest_hash_does_not_defeat_independent_pin(self):
        with tempfile.TemporaryDirectory(prefix="rph-v21-manifest-") as folder:
            target = Path(folder)
            for filename in ("release_manifest.json", self.metadata["python_wheel"],
                             self.metadata["rust_archive"], self.metadata["launcher"]):
                shutil.copy2(self.bundle / filename, target / filename)
            wheel = target / self.metadata["python_wheel"]
            wheel.write_bytes(wheel.read_bytes() + b"tamper")
            manifest = json.loads((target / "release_manifest.json").read_text())
            manifest["sha256"][wheel.name] = hashlib.sha256(wheel.read_bytes()).hexdigest()
            (target / "release_manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "trust_pin"):
                mod.verify_offline_install(target, sys.executable, self.pin)

    def test_declared_release_digest_mismatch_rejected(self):
        with tempfile.TemporaryDirectory(prefix="rph-v21-hash-") as folder:
            target = Path(folder)
            for filename in ("release_manifest.json", self.metadata["python_wheel"],
                             self.metadata["rust_archive"], self.metadata["launcher"]):
                shutil.copy2(self.bundle / filename, target / filename)
            wheel = target / self.metadata["python_wheel"]
            wheel.write_bytes(wheel.read_bytes() + b"tamper")
            with self.assertRaisesRegex(ValueError, "sha256_mismatch"):
                mod.inspect_split_bundle(target)

    def test_reject_symlink_to_release_wheel(self):
        with tempfile.TemporaryDirectory(prefix="rph-v21-symlink-") as folder:
            target = Path(folder)
            for filename in ("release_manifest.json", self.metadata["python_wheel"],
                             self.metadata["rust_archive"], self.metadata["launcher"]):
                shutil.copy2(self.bundle / filename, target / filename)
            wheel = target / self.metadata["python_wheel"]
            wheel.unlink()
            wheel.symlink_to(self.bundle / self.metadata["python_wheel"])
            with self.assertRaisesRegex(ValueError, "unsafe"):
                mod.inspect_split_bundle(target)

    def test_reject_hardlink_to_release_wheel(self):
        with tempfile.TemporaryDirectory(prefix="rph-v21-hardlink-") as folder:
            target = Path(folder)
            for filename in ("release_manifest.json", self.metadata["python_wheel"],
                             self.metadata["rust_archive"], self.metadata["launcher"]):
                shutil.copy2(self.bundle / filename, target / filename)
            wheel = target / self.metadata["python_wheel"]
            shadow = target / "shadow"
            os.link(wheel, shadow)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                mod.inspect_split_bundle(target)

    def test_reject_member_traversal_even_when_manifest_matches(self):
        with tempfile.TemporaryDirectory(prefix="rph-v21-zip-") as folder:
            target = Path(folder)
            for filename in ("release_manifest.json", self.metadata["python_wheel"],
                             self.metadata["rust_archive"], self.metadata["launcher"]):
                shutil.copy2(self.bundle / filename, target / filename)
            wheel = target / self.metadata["python_wheel"]
            with closing(zipfile.ZipFile(io.BytesIO(wheel.read_bytes()), "r")) as original:
                files = [(entry.filename, original.read(entry)) for entry in original.infolist()]
            with zipfile.ZipFile(wheel, "w") as forged:
                for filename, payload in files:
                    forged.writestr(filename, payload)
                forged.writestr("../escape.py", b"# no execution\n")
            metadata = json.loads((target / "release_manifest.json").read_text())
            metadata["sha256"][wheel.name] = hashlib.sha256(wheel.read_bytes()).hexdigest()
            (target / "release_manifest.json").write_text(json.dumps(metadata))
            with self.assertRaisesRegex(ValueError, "unsafe_wheel_members"):
                mod.inspect_split_bundle(target)

    def test_cli_from_selected_real_interpreter(self):
        completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                           "--release-dir", str(self.bundle), "--python", sys.executable,
                           "--trusted-wheel-sha256", self.pin],
                           capture_output=True, check=False, timeout=45)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"],
                         "OFFLINE_WHEEL_INSTALLED_TO_PRIVATE_TARGET")


if __name__ == "__main__":
    unittest.main()
