"""Native owner/DACL/handle tests; no fake POSIX chmod equivalence on Windows."""
import ctypes
from ctypes import wintypes
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import windows_privacy_fixtures as fixtures
privacy = fixtures.privacy


@unittest.skipUnless(os.name == "nt", "actual Windows security APIs required")
class WindowsPrivatePathsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rph-private-acl-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.private = fixtures.create_private_directory(self.base / "private")

    def test_private_directory_and_inherited_file_pass_actual_native_acl(self):
        file = self.private / "private.dat"
        file.write_bytes(b"fixed private fixture")
        for path, function in ((self.private, privacy.assert_private_directory),
                               (file, privacy.assert_private_file)):
            report = function(path)
            self.assertEqual(report["status"], "PRIVATE_WINDOWS_LEAF_CONFIRMED")
            self.assertTrue(report["owner_is_current_effective_user"])
            self.assertFalse(report["acl_mutated"])
            self.assertFalse(report["sandbox_proven"])

    def test_everyone_read_only_directory_is_rejected_and_not_repaired(self):
        fixtures.set_public_read_acl(self.private)
        for _ in range(2):
            with self.assertRaisesRegex(privacy.WindowsPrivacyRejected, "untrusted_effective_allow"):
                privacy.assert_private_directory(self.private)
        fixtures.set_private_acl(self.private)
        privacy.assert_private_directory(self.private)

    def test_everyone_read_only_file_is_rejected(self):
        file = self.private / "public.dat"; file.write_bytes(b"fixed")
        fixtures.set_public_read_acl(file)
        with self.assertRaisesRegex(privacy.WindowsPrivacyRejected, "untrusted_effective_allow"):
            privacy.assert_private_file(file)

    def test_null_dacl_is_rejected(self):
        fixtures.set_null_dacl(self.private)
        with self.assertRaisesRegex(privacy.WindowsPrivacyRejected, "null_dacl"):
            privacy.assert_private_directory(self.private)
        fixtures.set_private_acl(self.private)

    def test_owner_mismatch_is_rejected_without_owner_mutation(self):
        with mock.patch.object(privacy, "_current_user_sid", return_value=privacy.SYSTEM_SID):
            with self.assertRaisesRegex(privacy.WindowsPrivacyRejected, "owner_mismatch"):
                privacy.assert_private_directory(self.private)

    def test_native_mkdir700_owner_rights_alias_and_inherited_file_are_private(self):
        directory = self.private / "python-mkdir700"
        directory.mkdir(mode=0o700)
        privacy.assert_private_directory(directory)
        file = directory / "inherited.dat"; file.write_bytes(b"fixed")
        privacy.assert_private_file(file)

    def test_owner_rights_alias_cannot_bypass_current_owner_verification(self):
        directory = self.private / "python-mkdir700"
        directory.mkdir(mode=0o700)
        with mock.patch.object(privacy, "_current_user_sid", return_value=privacy.SYSTEM_SID):
            with self.assertRaisesRegex(privacy.WindowsPrivacyRejected, "owner_mismatch"):
                privacy.assert_private_directory(directory)

    def test_actual_open_descriptor_is_checked_without_closing_or_reopening(self):
        file = self.private / "descriptor.dat"; file.write_bytes(b"fixed")
        descriptor = os.open(str(file), os.O_RDONLY)
        try:
            privacy.assert_private_file_descriptor(descriptor)
            self.assertEqual(os.read(descriptor, 5), b"fixed")
            fixtures.set_public_read_acl(file)
            with self.assertRaisesRegex(privacy.WindowsPrivacyRejected, "untrusted_effective_allow"):
                privacy.assert_private_file_descriptor(descriptor)
        finally:
            os.close(descriptor)

    def test_readonly_opener_returns_same_private_binary_fd_and_blocks_writers(self):
        file = self.private / "binary-key.dat"
        payload = b"fixed\x00\x1a\r\nprivate"
        file.write_bytes(payload)
        descriptor = privacy.open_private_readonly(file)
        try:
            privacy.assert_private_file_descriptor(descriptor)
            self.assertEqual(os.read(descriptor, 128), payload)
            self.assertFalse(os.get_inheritable(descriptor))
            with self.assertRaises(OSError):
                os.open(str(file), os.O_WRONLY)
            with self.assertRaises(OSError):
                file.unlink()
        finally:
            os.close(descriptor)
        file.unlink()

    def test_readonly_opener_refuses_same_original_inode_through_new_leaf_alias(self):
        file = self.private / "key.dat"; backing = self.private / "backing.dat"
        file.write_bytes(b"fixed private key")
        before = file.lstat()
        file.rename(backing); file.symlink_to(backing)
        # The previous lstat/fstat-only approach would still see the same inode.
        unsafe_fd = os.open(str(file), os.O_RDONLY)
        try:
            opened = os.fstat(unsafe_fd)
            self.assertEqual((before.st_dev, before.st_ino), (opened.st_dev, opened.st_ino))
        finally:
            os.close(unsafe_fd)
        with self.assertRaises(privacy.WindowsPrivacyRejected):
            privacy.open_private_readonly(file)

    def test_readonly_opener_refuses_public_hardlinked_and_directory_leaves(self):
        file = self.private / "key.dat"; file.write_bytes(b"fixed")
        fixtures.set_public_read_acl(file)
        with self.assertRaises(privacy.WindowsPrivacyRejected):
            privacy.open_private_readonly(file)
        fixtures.set_private_acl(file)
        alias = self.private / "hardlink.dat"; os.link(file, alias)
        for path in (file, self.private):
            with self.assertRaises(privacy.WindowsPrivacyRejected):
                privacy.open_private_readonly(path)

    def test_readonly_opener_closes_native_handle_if_crt_transfer_fails(self):
        import msvcrt
        file = self.private / "key.dat"; file.write_bytes(b"fixed")
        kernel, _security = privacy._libraries()
        real_open = kernel.CreateFileW
        captured = []
        def capture(*args):
            handle = real_open(*args); captured.append(handle); return handle
        with mock.patch.object(kernel, "CreateFileW", side_effect=capture), \
                mock.patch.object(msvcrt, "open_osfhandle", side_effect=OSError("fixed transfer failure")):
            with self.assertRaisesRegex(OSError, "fixed transfer failure"):
                privacy.open_private_readonly(file)
        info = privacy._FileInformation()
        self.assertEqual(len(captured), 1)
        self.assertFalse(kernel.GetFileInformationByHandle(captured[0], ctypes.byref(info)))
        self.assertEqual(ctypes.get_last_error(), 6)
        file.unlink()

    def test_hardlink_file_is_rejected_before_acl_success(self):
        file = self.private / "original.dat"; file.write_bytes(b"fixed")
        alias = self.private / "alias.dat"
        os.link(file, alias)
        with self.assertRaisesRegex(privacy.WindowsPrivacyRejected, "single_link"):
            privacy.assert_private_file(alias)

    def test_wrong_leaf_type_and_missing_path_are_rejected(self):
        file = self.private / "plain.dat"; file.write_bytes(b"fixed")
        for path, function in ((file, privacy.assert_private_directory),
                               (self.private, privacy.assert_private_file),
                               (self.private / "missing", privacy.assert_private_file)):
            with self.subTest(path=path), self.assertRaises(privacy.WindowsPrivacyRejected):
                function(path)

    def test_unknown_callback_allow_ace_is_rejected(self):
        # Conditional allow ACEs require separate semantics and are not accepted.
        sid = fixtures.current_user_sid_string()
        sddl = fixtures.private_sddl('(XA;;FR;;;WD;(@User.fixture == "value"))')
        fixtures.set_test_sddl(self.private, sddl)
        with self.assertRaisesRegex(privacy.WindowsPrivacyRejected, "ace_type_unsupported"):
            privacy.assert_private_directory(self.private)
        fixtures.set_private_acl(self.private)

    def test_inherit_only_public_directory_grant_refused_to_protect_future_children(self):
        fixtures.set_test_sddl(self.private, fixtures.private_sddl("(A;OICIIO;FR;;;WD)"))
        with self.assertRaisesRegex(privacy.WindowsPrivacyRejected, "untrusted_inheritable_allow"):
            privacy.assert_private_directory(self.private)
        child = self.private / "inherited.dat"; child.write_bytes(b"fixed")
        with self.assertRaisesRegex(privacy.WindowsPrivacyRejected, "untrusted_effective_allow"):
            privacy.assert_private_file(child)

    def test_local_absolute_path_required_before_open(self):
        for value in ("relative", "C:relative", "\\\\server\\share\\file", "\\\\.\\pipe\\name", "bad\0path"):
            with self.subTest(value=value), self.assertRaises(privacy.WindowsPrivacyRejected):
                privacy.assert_private_directory(value)

    def test_rejected_acl_and_success_do_not_leak_kernel_handles(self):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        def count():
            value = wintypes.DWORD()
            self.assertTrue(kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), ctypes.byref(value)))
            return value.value
        privacy.assert_private_directory(self.private)
        before = count()
        for _ in range(40):privacy.assert_private_directory(self.private)
        fixtures.set_public_read_acl(self.private)
        for _ in range(40):
            with self.assertRaises(privacy.WindowsPrivacyRejected):
                privacy.assert_private_directory(self.private)
        self.assertLessEqual(count(), before + 1)
        fixtures.set_private_acl(self.private)

    def test_junction_leaf_is_rejected(self):
        junction = self.base / "junction"
        fixtures.create_test_junction(junction, self.private)
        try:
            with self.assertRaisesRegex(privacy.WindowsPrivacyRejected, "reparse_leaf"):
                privacy.assert_private_directory(junction)
        finally:
            os.rmdir(junction)


if __name__ == "__main__":unittest.main()
