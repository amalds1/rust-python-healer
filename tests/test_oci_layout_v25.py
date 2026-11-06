"""Actual offline OCI layout digest/reproducibility tests, never OCI runtime execution."""

import hashlib
import importlib.util
import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "python" / "oci_layout_v25.py"
SPEC = importlib.util.spec_from_file_location("oci_layout_v25", MODULE)
OCI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OCI)


def synthetic_elf():
    image = bytearray(128)
    image[:4] = b"\x7fELF"
    image[4] = 2
    image[5] = 1
    image[6] = 1
    image[16:18] = (3).to_bytes(2, "little")
    image[18:20] = (62).to_bytes(2, "little")
    return bytes(image)


class OciLayoutTests(unittest.TestCase):
    def test_actual_interpreter_is_cpython(self):
        self.assertEqual(sys.implementation.name, "cpython")
        self.assertGreaterEqual(sys.version_info[:2], (3, 9))

    def test_reproducible_image_byte_for_byte(self):
        left, right = OCI.candidate_bytes(synthetic_elf()), OCI.candidate_bytes(synthetic_elf())
        self.assertEqual(left, right)
        self.assertEqual(hashlib.sha256(left).hexdigest(), hashlib.sha256(right).hexdigest())

    def test_spec_layout_and_sha256_descriptor_closure(self):
        archive = OCI.candidate_bytes(synthetic_elf())
        report = OCI.inspect_bytes(archive)
        self.assertEqual(report["status"], "OCI_LAYOUT_INTEGRITY_VERIFIED_RUNTIME_NOT_RUN")
        self.assertEqual(report["binary_sha256"], OCI._sha(synthetic_elf()))

    def test_output_created_atomically_without_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            binary, output = Path(folder) / "trusted-elf", Path(folder) / "layout.tar"
            binary.write_bytes(synthetic_elf())
            report = OCI.build(binary, output, OCI._sha(synthetic_elf()))
            self.assertEqual(report["archive_sha256"], OCI._sha(output.read_bytes()))
            before = output.read_bytes()
            with self.assertRaisesRegex(ValueError, "output_must_be_new_regular_path"):
                OCI.build(binary, output, OCI._sha(synthetic_elf()))
            self.assertEqual(output.read_bytes(), before)

    def test_output_symlink_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            binary, existing = folder / "trusted-elf", folder / "existing"
            binary.write_bytes(synthetic_elf())
            existing.write_bytes(b"important-original")
            (folder / "layout.tar").symlink_to(existing)
            with self.assertRaises(ValueError):
                OCI.build(binary, folder / "layout.tar", OCI._sha(synthetic_elf()))
            self.assertEqual(existing.read_bytes(), b"important-original")

    def test_untrusted_binary_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            original = folder / "original"
            original.write_bytes(synthetic_elf())
            (folder / "shortcut").symlink_to(original)
            with self.assertRaisesRegex(ValueError, "untrusted_binary_file_type_or_size"):
                OCI.build(folder / "shortcut", folder / "output.tar", OCI._sha(synthetic_elf()))

    def test_sha_pin_missing_or_wrong_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / "trusted-elf"
            binary.write_bytes(synthetic_elf())
            with self.assertRaisesRegex(ValueError, "explicit_sha256_pin_required"):
                OCI.build(binary, Path(folder) / "archive.tar", "")
            with self.assertRaisesRegex(ValueError, "binary_sha256_mismatch"):
                OCI.build(binary, Path(folder) / "archive.tar", "0" * 64)

    def test_wrong_architecture_and_non_elf_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / "wrong"
            wrong = bytearray(synthetic_elf())
            wrong[18:20] = (183).to_bytes(2, "little")
            binary.write_bytes(wrong)
            with self.assertRaisesRegex(ValueError, "not_linux_amd64_elf"):
                OCI.build(binary, Path(folder) / "archive.tar", OCI._sha(wrong))
            binary.write_bytes(b"Z" * 128)
            with self.assertRaisesRegex(ValueError, "not_linux_amd64_elf"):
                OCI.build(binary, Path(folder) / "archive.tar", OCI._sha(b"Z" * 128))

    def test_tampered_layer_cannot_verify(self):
        original = OCI.candidate_bytes(synthetic_elf())
        changed = original.replace(b"\x7fELF", b"\x7fELX", 1)
        self.assertNotEqual(original, changed)
        with self.assertRaisesRegex(ValueError, "oci_blob_digest_mismatch"):
            OCI.inspect_bytes(changed)

    def test_duplicate_oci_members_rejected(self):
        original = OCI.candidate_bytes(synthetic_elf())
        with tarfile.open(fileobj=io.BytesIO(original), mode="r:") as archive:
            entries = [(m.name, archive.extractfile(m).read(), m.mode)
                       for m in archive.getmembers()]
        duplicate = OCI._tar(entries + [entries[0]])
        with self.assertRaisesRegex(ValueError, "oci_layout_members_not_unique"):
            OCI.inspect_bytes(duplicate)

    def test_security_gate_explicitly_not_proven(self):
        report = OCI.inspect_bytes(OCI.candidate_bytes(synthetic_elf()))
        self.assertIs(report["sandbox_isolation_verified"], False)
        self.assertIs(report["external_client_run"], False)
        self.assertIs(report["release_authorized"], False)
        self.assertIs(report["independent_audit"], False)

    def test_cli_rejects_unknown_binary_without_writing(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            invalid, output = folder / "invalid", folder / "output.tar"
            invalid.write_bytes(b"not a compiled ELF")
            proc = subprocess.run([sys.executable, "-I", "-S", "-B", str(MODULE),
                                   "--binary", str(invalid), "--expected-sha256",
                                   OCI._sha(invalid.read_bytes()), "--output", str(output)],
                                  capture_output=True, timeout=10, check=False)
            self.assertEqual(proc.returncode, 2)
            self.assertNotIn(b"PASS", proc.stdout)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
