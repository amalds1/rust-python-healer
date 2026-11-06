"""New explicit-owner storage creation; requires actual Windows APIs.

Run only after review, in a source overlay containing the unchanged checker.
No impersonation, token changes, global TEMP changes or owner repair.
"""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('creation_platform', ROOT/'python/platform_privacy_v028.py')
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)


@unittest.skipUnless(os.name == 'nt', 'real Windows owner/DACL APIs required')
class NativePrivateCreationTests(unittest.TestCase):
    def setUp(self):
        self.outer = tempfile.TemporaryDirectory(prefix='rph-private-create-')
        self.addCleanup(self.outer.cleanup)
        self.base = platform.create_private_directory(Path(self.outer.name)/'private')
        self.privacy = platform.windows_privacy()

    def test_explicit_directory_owner_and_inherited_private_file(self):
        report = self.privacy.assert_private_directory(self.base)
        self.assertTrue(report['owner_is_current_effective_user'])
        self.assertFalse(report['acl_mutated'])
        path = self.base/'native.dat'
        fd = platform.create_private_file(path)
        try:
            report = self.privacy.assert_private_file_descriptor(fd)
            self.assertTrue(report['owner_is_current_effective_user'])
            os.write(fd, b'fixed-creator-fixture')
            os.fsync(fd)
        finally:
            os.close(fd)
        self.assertEqual(path.read_bytes(), b'fixed-creator-fixture')
        self.privacy.assert_private_file(path)

    def test_existing_file_is_not_overwritten(self):
        path = self.base/'existing.dat'
        fd = platform.create_private_file(path)
        os.write(fd, b'preserve')
        os.close(fd)
        before = path.stat()
        with self.assertRaises(FileExistsError):
            platform.create_private_file(path)
        self.assertEqual(path.read_bytes(), b'preserve')
        self.assertEqual(path.stat().st_ino, before.st_ino)

    def test_existing_directory_is_not_repaired(self):
        before = self.base.stat()
        with self.assertRaises(FileExistsError):
            platform.create_private_directory(self.base)
        self.assertEqual(self.base.stat().st_ino, before.st_ino)

    def test_rejected_postcreate_handle_is_deleted_without_neighbor_changes(self):
        path = self.base/'rejected.dat'
        neighbor = self.base/'neighbor.dat'
        fd = platform.create_private_file(neighbor)
        os.write(fd, b'preserve')
        os.close(fd)
        original = self.privacy._inspect_private_handle
        def inspect(handle, directory, kernel, security):
            if not directory:
                raise ValueError('fixed_reject')
            return original(handle, directory, kernel, security)
        with mock.patch.object(self.privacy, '_inspect_private_handle', side_effect=inspect):
            with self.assertRaisesRegex(ValueError, 'fixed_reject'):
                platform.create_private_file(path)
        self.assertFalse(path.exists())
        self.assertEqual(neighbor.read_bytes(), b'preserve')

    def test_descriptor_transfer_failure_deletes_only_created_handle(self):
        import msvcrt
        path = self.base/'transfer.dat'
        with mock.patch.object(msvcrt, 'open_osfhandle', side_effect=OSError('fixed_transfer_failure')):
            with self.assertRaisesRegex(OSError, 'fixed_transfer_failure'):
                platform.create_private_file(path)
        self.assertFalse(path.exists())
        fd = platform.create_private_file(path)
        os.close(fd)
        self.privacy.assert_private_file(path)

    def test_unsafe_component_is_rejected_without_creation(self):
        for leaf in ('fixed:stream', 'NUL', 'CON.txt', 'bad.', 'bad '):
            with self.subTest(leaf=leaf):
                with self.assertRaisesRegex(ValueError, 'private_create_unsafe_leaf'):
                    platform.create_private_file(self.base/leaf)
        self.assertEqual(list(self.base.iterdir()), [])

    def test_owner_mismatch_still_fails_without_repair(self):
        # Same original negative oracle, after creating with the new adapter.
        with mock.patch.object(self.privacy, '_current_user_sid', return_value=self.privacy.SYSTEM_SID):
            with self.assertRaisesRegex(self.privacy.WindowsPrivacyRejected, 'owner_mismatch'):
                self.privacy.assert_private_directory(self.base)
        self.privacy.assert_private_directory(self.base)


if __name__ == '__main__':
    unittest.main()
