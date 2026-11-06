"""Real HANDLE confinement and cleanup; fixed fixture bytes are never executed."""

import ctypes
from ctypes import wintypes
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "blob_reader",
    Path(__file__).resolve().parents[1] / "python/windows_blob_reader_v029.py",
)
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


@unittest.skipUnless(os.name == "nt", "Windows HANDLE contract")
class WindowsBlobTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "blobs"
        (self.root / "nested").mkdir(parents=True)
        (self.root / "nested/item.py").write_bytes(b"x=7\n")

    def read(self, parts=None, limit=64):
        return reader.read_blob_beneath(
            self.root, parts or ["nested", "item.py"], limit
        )

    def test_nested_exact_bytes_and_empty_file(self):
        self.assertEqual(self.read(), b"x=7\n")
        (self.root / "empty.py").write_bytes(b"")
        self.assertEqual(self.read(["empty.py"]), b"")

    def test_budget_and_reserved_names(self):
        for parts in (
            ["..", "item.py"],
            ["nested/item.py"],
            ["item.py:stream"],
            ["NUL.py"],
            ["COM1"],
            ["nested", "item.py."],
        ):
            with self.subTest(parts=parts), self.assertRaises(ValueError):
                self.read(parts)
        with self.assertRaises(ValueError):
            self.read(limit=1)

    def test_file_and_directory_reparse_rejected(self):
        (self.root / "alias.py").symlink_to(self.root / "nested/item.py")
        (self.root / "alias").symlink_to(self.root / "nested", target_is_directory=True)
        for parts in (["alias.py"], ["alias", "item.py"]):
            with self.assertRaises(ValueError):
                self.read(parts)

    def test_hardlink_rejected(self):
        os.link(self.root / "nested/item.py", self.root / "other.py")
        with self.assertRaisesRegex(ValueError, "not_unique"):
            self.read()

    def test_root_and_ancestor_alias_rejected(self):
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            reader.read_blob_beneath(alias, ["nested", "item.py"], 64)
        ancestor = self.base / "ancestor"
        ancestor.symlink_to(self.base, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "ancestor_alias"):
            reader.read_blob_beneath(ancestor / "blobs", ["nested", "item.py"], 64)

    def test_parent_handles_prevent_directory_replacement(self):
        original = reader._relative_open
        attempts = []

        def opening(parent, name, directory):
            if name == "item.py":
                with self.assertRaises(PermissionError):
                    (self.root / "nested").rename(self.root / "moved")
                attempts.append(True)
            return original(parent, name, directory)

        with patch.object(reader, "_relative_open", opening):
            self.assertEqual(self.read(), b"x=7\n")
        self.assertEqual(attempts, [True])

    def test_leaf_handle_blocks_write_and_delete(self):
        original = reader._information
        checked = []

        def information(handle, directory, limit):
            if not directory:
                with self.assertRaises(PermissionError):
                    (self.root / "nested/item.py").write_bytes(b"changed")
                with self.assertRaises(PermissionError):
                    (self.root / "nested/item.py").unlink()
                checked.append(True)
            return original(handle, directory, limit)

        with patch.object(reader, "_information", information):
            self.assertEqual(self.read(), b"x=7\n")
        self.assertEqual(len(checked), 2)

    def test_repeated_success_and_failure_close_handles(self):
        kernel = reader._libraries()[1]
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.GetProcessHandleCount.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        ]

        def count():
            result = wintypes.DWORD()
            self.assertTrue(
                kernel.GetProcessHandleCount(
                    kernel.GetCurrentProcess(), ctypes.byref(result)
                )
            )
            return result.value

        self.read()  # initialize ctypes before baseline
        before = count()
        for _ in range(40):
            self.read()
            with self.assertRaises(ValueError):
                self.read(["nested", "missing.py"])
        self.assertEqual(count(), before)


if __name__ == "__main__":
    unittest.main()
