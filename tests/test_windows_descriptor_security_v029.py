"""Actual NTFS enumeration/race/cleanup checks on owned fixture paths."""
import ctypes
from ctypes import wintypes
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("windows_security", Path(__file__).resolve().parents[1] / "python/windows_descriptor_security_v029.py")
security = importlib.util.module_from_spec(spec)
spec.loader.exec_module(security)


@unittest.skipUnless(os.name == "nt", "Windows HANDLE enumeration contract")
class NativeSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "project"
        self.root.mkdir()
        (self.root / "main.py").write_bytes(b"x=7\n")

    def scan(self, files=512, size=16000000):
        return security.scan_project(self.root, files, size, 16)

    def test_multiple_enumeration_batches_preserve_all_ids(self):
        for index in range(600):
            (self.root / ("fixture_%04d.py" % index)).write_bytes(b"")
        result = self.scan(files=700)
        self.assertEqual(result["python_files"], 601)
        self.assertEqual(result["bytes_scanned"], 4)
        self.assertFalse(result["sandbox_proven"])

    def test_regular_file_replacement_attempt_blocked_by_root_handle(self):
        replacement = self.root / "replacement"
        replacement.write_bytes(b"evil")
        original = security._entries
        def entries(*args):
            rows = original(*args)
            # MoveFileEx replacement is itself denied by the held root HANDLE.
            # Link an already distinct inode instead, then remove its old name.
            (self.root / "main.py").unlink()
            os.link(replacement, self.root / "main.py")
            replacement.unlink()
            return rows
        with patch.object(security, "_entries", entries), self.assertRaises(PermissionError):
            self.scan()

    def test_enumeration_identity_mismatch_refused(self):
        original = security._entries
        def entries(*args):
            return [(name, attributes, identity ^ 1) for name, attributes, identity in original(*args)]
        with patch.object(security, "_entries", entries), self.assertRaisesRegex(ValueError, "REPLACED"):
            self.scan()

    def test_enumerated_file_replaced_by_external_symlink_rejected(self):
        outside = Path(self.temp.name) / "outside"
        outside.write_bytes(b"outside bytes never read")
        original = security._entries
        def entries(*args):
            rows = original(*args)
            (self.root / "main.py").unlink()
            (self.root / "main.py").symlink_to(outside)
            return rows
        with patch.object(security, "_entries", entries), self.assertRaises(ValueError):
            self.scan()

    def test_unicode_and_space_names_are_data(self):
        (self.root / "ruimte één.py").write_bytes(b"# fixed\n")
        (self.root / "nested space").mkdir()
        (self.root / "nested space/item.py").write_bytes(b"# nested\n")
        self.assertEqual(self.scan()["python_files"], 3)
        self.assertEqual(security.read_project_file(self.root, ["ruimte één.py"], 64), b"# fixed\n")

    def test_overlapping_directory_record_name_is_rejected(self):
        opened = security.Root(self.root)
        self.addCleanup(opened.close)
        def malformed(handle, kind, buffer, capacity):
            row = security.DirectoryEntry.from_buffer(buffer)
            row.next = 112
            row.name_bytes = 40  # starts at 104, extends beyond next record
            ctypes.memmove(ctypes.addressof(buffer) + security.DirectoryEntry.name.offset,
                           ("a" * 20).encode("utf-16-le"), 40)
            return True
        with patch.object(opened.kernel, "GetFileInformationByHandleEx", side_effect=malformed):
            with self.assertRaisesRegex(ValueError, "DIRECTORY_NEXT_BOUNDS"):
                security._entries(opened, opened.handles[0], 16)

    def test_snapshot_failed_write_deletes_exact_owned_partial_file(self):
        from windows_privacy_fixtures import set_private_acl
        set_private_acl(self.root)
        # Initialize the API before injecting only the real write failure.
        security.write_private_snapshot(self.root, "initial.json", b"{}")
        kernel = security._blob()._libraries()[1]
        with patch.object(kernel, "WriteFile", return_value=False), self.assertRaisesRegex(ValueError, "WRITE_FAILED"):
            security.write_private_snapshot(self.root, "failed.json", b"{}")
        self.assertFalse((self.root / "failed.json").exists())
        self.assertEqual((self.root / "initial.json").read_bytes(), b"{}")

    def test_success_and_failure_leave_no_handle_growth(self):
        self.scan()
        kernel = security._blob()._libraries()[1]
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        def count():
            value = wintypes.DWORD()
            self.assertTrue(kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), ctypes.byref(value)))
            return value.value
        before = count()
        for _ in range(40):
            self.scan()
            with self.assertRaises(ValueError):
                security.read_project_file(self.root, ["missing.py"], 64)
        self.assertEqual(count(), before)


if __name__ == "__main__":
    unittest.main()
