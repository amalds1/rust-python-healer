"""F245 offline wheel and Rust archive build/launcher qualification 3.9--3.15."""

import base64
import csv
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
RUST_BINARY = ROOT / "target" / ("release" if sys.platform == "win32" else "debug") / ("rust-python-healer.exe" if sys.platform == "win32" else "rust-python-healer")
RUST_MEMBER = "bin/rust-python-healer.exe" if sys.platform == "win32" else "bin/rust-python-healer"
BUILDER = ROOT / "packaging" / "build_release.py"
LAUNCHER = ROOT / "packaging" / "run_bundle.py"


def import_file(name, path):
    spec = spec_from_file_location(name, path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = import_file("release_builder", BUILDER)
launcher = import_file("release_launcher", LAUNCHER)


class DistributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not RUST_BINARY.exists():
            raise unittest.SkipTest("Pre-built Rust binary unavailable; rustc not installed in test environment")
        cls.temporary = tempfile.TemporaryDirectory()
        cls.folder = Path(cls.temporary.name)
        cls.manifest = builder.build_release(cls.folder, RUST_BINARY)
        cls.python_wheel = cls.folder / cls.manifest["python_wheel"]
        cls.rust_archive = cls.folder / cls.manifest["rust_archive"]

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temporary"):
            cls.temporary.cleanup()

    def cli(self, command, *args):
        return subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(LAUNCHER),
             "--dist-dir", str(self.folder), command, "--"] + list(args),
            text=True, capture_output=True, timeout=35)

    def test_artifacts_are_distinct_and_source_helpers_are_included(self):
        self.assertTrue(self.python_wheel.is_file())
        self.assertTrue(self.rust_archive.is_file())
        self.assertEqual(self.manifest["schema"], 1)
        self.assertGreaterEqual(self.manifest["python_helper_modules"], 20)
        self.assertEqual(self.manifest["version"], builder.project_version())
        self.assertTrue(self.manifest["python_wheel"].endswith("-py3-none-any.whl"))

    def test_wheel_has_pep427_metadata_and_consistent_sha256_record(self):
        with zipfile.ZipFile(self.python_wheel) as archive:
            names = archive.namelist()
            self.assertEqual(len(names), len(set(names)))
            self.assertIn("rust_python_healer_cli/__main__.py", names)
            self.assertIn("rust_python_healer_helpers/abi_tags.py", names)
            self.assertIn("rust_python_healer_helpers/static_quality.py", names)
            self.assertIn("rust_python_healer_helpers/knowledge_updater.py", names)
            metadata = "rust_python_healer_helpers-{}.dist-info".format(self.manifest["version"])
            self.assertIn("Tag: py3-none-any", archive.read(metadata + "/WHEEL").decode())
            self.assertIn("Requires-Python: >=3.9, <3.16", archive.read(metadata + "/METADATA").decode())
            self.assertIn("rph-python =", archive.read(metadata + "/entry_points.txt").decode())
            rows = list(csv.reader(io.StringIO(archive.read(metadata + "/RECORD").decode("ascii"))))
            self.assertEqual(len(rows), len(names))
            for name, encoded, size in rows:
                self.assertIn(name, names)
                if name.endswith("/RECORD"):
                    self.assertEqual((encoded, size), ("", ""))
                    continue
                content = archive.read(name)
                self.assertEqual(int(size), len(content))
                self.assertTrue(encoded.startswith("sha256="))
                encoded_digest = encoded[7:]
                expected = base64.urlsafe_b64decode(encoded_digest + "=")
                self.assertEqual(hashlib.sha256(content).digest(), expected)

    def test_wheel_zip_is_deterministic(self):
        sources = builder.collect_helpers()
        name, first, count = builder.build_wheel(self.manifest["version"], sources)
        other_name, second, other_count = builder.build_wheel(self.manifest["version"], sources)
        self.assertEqual(first, second)
        self.assertEqual(name, other_name)
        self.assertEqual(count, other_count)
        # Other agents can add helper files while tests run; determinism is
        # defined over the same source snapshot, not over different snapshots.

    def test_binary_archive_contains_exact_executable_and_notice(self):
        with zipfile.ZipFile(self.rust_archive) as archive:
            self.assertEqual(set(archive.namelist()), {"NOTICE.txt", RUST_MEMBER})
            self.assertEqual(archive.read(RUST_MEMBER), RUST_BINARY.read_bytes())
            self.assertIn(b"NOT compiled", archive.read("NOTICE.txt"))
        self.assertFalse(self.manifest["rust_compiled_in_this_build"])
        self.assertFalse(self.manifest["provenance_authenticated"])
        self.assertFalse(self.manifest["native_compatibility_verified"])

    def test_sha256sums_manifest_matches_every_artifact(self):
        expected = []
        for name, digest in sorted(self.manifest["sha256"].items()):
            content = (self.folder / name).read_bytes()
            self.assertEqual(hashlib.sha256(content).hexdigest(), digest)
            expected.append("{}  {}\n".format(digest, name))
        self.assertEqual((self.folder / "SHA256SUMS").read_text(), "".join(expected))
        _, files = launcher.verify_bundle(self.folder)
        self.assertEqual(set(files), set(self.manifest["sha256"]))

    def test_python_bundle_cli_lists_packaged_helpers_all_real_interpreters(self):
        result = self.cli("python", "list")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["status"], "PACKAGED_HELPERS")
        self.assertIn("abi_tags", data["helpers"])
        self.assertIn("static_quality", data["helpers"])
        self.assertFalse(data["network_used"])

    def test_python_bundle_cli_wheel_abi(self):
        result = self.cli("python", "abi-tags", "--wheel", "offline-1.0-py3-none-any.whl")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["compatibility"], "POSSIBLE_TAG_MATCH_NOT_INSTALLED")
        self.assertEqual(data["python_version"], "{}.{}".format(*sys.version_info[:2]))
        self.assertFalse(data["native_extensions_loaded"])

    def test_python_bundle_cli_static_file_offline(self):
        with tempfile.TemporaryDirectory() as location:
            source = Path(location) / "clean.py"
            source.write_text("def good():\n    return 9\n", encoding="utf-8")
            result = self.cli("python", "static", "--file", str(source))
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual(data["status"], "INSPECTED_PARTIAL")
            self.assertFalse(data["source_executed"])

    def test_rust_bundle_cli_launches_version_from_local_binary(self):
        if sys.platform not in ("linux", "win32"):
            self.skipTest("Native fixture is only qualified on Linux and Windows hosts")
        result = self.cli("rust", "--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rust-python-healer", result.stdout)
        self.assertIn(self.manifest["version"], result.stdout)

    def test_rust_bundle_cli_runtime_uses_explicit_current_python(self):
        if sys.platform not in ("linux", "win32"):
            self.skipTest("Native fixture is only qualified on Linux and Windows hosts")
        result = self.cli("rust", "runtime", "--python", sys.executable)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cpython", result.stdout.lower())

    def test_builder_does_not_overwrite_artifacts(self):
        old = self.python_wheel.stat().st_mtime_ns
        with self.assertRaisesRegex(ValueError, "output_file_exists"):
            builder.build_release(self.folder, RUST_BINARY)
        self.assertEqual(old, self.python_wheel.stat().st_mtime_ns)

    def test_builder_rejects_symlinked_binary_without_reading(self):
        with tempfile.TemporaryDirectory() as location:
            symlink = Path(location) / "rust-bin"
            symlink.symlink_to(RUST_BINARY)
            with self.assertRaisesRegex(ValueError, "input_not_regular_file"):
                builder.build_rust_archive("0.0.1", symlink)

    def test_builder_rejects_malformed_rust_binary(self):
        with tempfile.TemporaryDirectory() as location:
            file = Path(location) / "not_executable"
            file.write_text("PRIVATE_TOKEN_36785")
            with self.assertRaisesRegex(ValueError, "rust_binary_format_unrecognized"):
                builder.build_rust_archive("0.0.1", file)

    def test_builder_rejects_excessively_large_fake_binary(self):
        with tempfile.TemporaryDirectory() as location:
            file = Path(location) / "oversize"
            with file.open("wb") as output:
                output.truncate(builder.MAX_RUST_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "input_size_limit"):
                builder.build_rust_archive("0.0.1", file)

    def test_launcher_rejects_malformed_modes_and_missing_arguments(self):
        for argv in (("badmode", "--version"), ("rust",), ("python",)):
            result = self.cli(*argv)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")

    def test_launcher_rejects_malformed_wheel_argument_without_crashing(self):
        result = self.cli("python", "abi-tags", "--wheel", "../secrets-1-py3-none-any.whl")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["status"], "INVALID_WHEEL_FILENAME")
        self.assertNotIn("secrets", result.stdout)

    def test_bundle_manifest_is_not_claimed_authenticated(self):
        self.assertFalse(self.manifest["provenance_authenticated"])
        self.assertTrue(self.manifest["offline"])
        self.assertFalse(self.manifest["global_install_performed"])
        self.assertTrue(self.manifest["rust_archive"].endswith(".zip"))

    def test_launcher_rejects_mutated_hash_file(self):
        sums = self.folder / "SHA256SUMS"
        original = sums.read_bytes()
        try:
            sums.write_bytes(b"sha256sum file corrupted\n")
            with self.assertRaisesRegex(launcher.BundleError, "checksum_file_mismatch"):
                launcher.verify_bundle(self.folder)
        finally:
            sums.write_bytes(original)

    def test_launcher_rejects_mutated_wheel_bytes(self):
        with self.python_wheel.open("r+b") as output:
            original = output.read(1)
            try:
                output.seek(0)
                output.write(b"Z" if original != b"Z" else b"Y")
                output.flush()
                with self.assertRaisesRegex(launcher.BundleError, "artifact_checksum_mismatch"):
                    launcher.verify_bundle(self.folder)
            finally:
                output.seek(0)
                output.write(original)

    def test_launcher_rejects_symlinked_manifest(self):
        manifest = self.folder / "release_manifest.json"
        original = manifest.read_bytes()
        with tempfile.TemporaryDirectory() as other:
            duplicate = Path(other) / "manifest.json"
            duplicate.write_bytes(original)
            manifest.unlink()
            try:
                manifest.symlink_to(duplicate)
                with self.assertRaisesRegex(launcher.BundleError,
                                            "artifact_not_private_regular_file"):
                    launcher.verify_bundle(self.folder)
            finally:
                manifest.unlink()
                manifest.write_bytes(original)

    def test_launcher_rejects_hardlinked_manifest(self):
        manifest = self.folder / "release_manifest.json"
        with tempfile.TemporaryDirectory() as other:
            link = Path(other) / "manifest.json"
            os.link(manifest, link)
            with self.assertRaisesRegex(launcher.BundleError,
                                        "artifact_not_private_regular_file"):
                launcher.verify_bundle(self.folder)

    def test_launcher_rejects_unexpected_archive_members(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("bin/../../evil", b"payload")
        with self.assertRaisesRegex(launcher.BundleError, "invalid_rust_archive_members"):
            launcher.rust_executable(output.getvalue())

    def test_launcher_rejects_duplicate_fields_and_manifest_traversal(self):
        with self.assertRaisesRegex(launcher.BundleError, "duplicate_manifest_field"):
            launcher._unique_pairs([("sha256", {}), ("sha256", {})])
        invalid = {**self.manifest, "rust_archive": "../outside.zip"}
        with tempfile.TemporaryDirectory() as location:
            target = Path(location) / "release_manifest.json"
            target.write_text(json.dumps(invalid))
            with self.assertRaisesRegex(launcher.BundleError, "invalid_artifact_names"):
                launcher.verify_bundle(location)


if __name__ == "__main__":
    unittest.main()
