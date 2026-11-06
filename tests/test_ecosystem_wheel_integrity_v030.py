"""Real private-HANDLE identity negatives; no third-party package imports."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('wheel_integrity',ROOT/'python/ecosystem_wheel_integrity_v030.py')
MOD=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(MOD)
if os.name=='nt':
    import windows_privacy_fixtures as acl


class WheelIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rph-fixed-byte-policy-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        if os.name=='nt':acl.set_private_acl(self.root)
        else:self.root.chmod(0o700)
        self.target=self.root/'packages'
        if os.name=='nt':acl.create_private_directory(self.target)
        else:self.target.mkdir(mode=0o700)
        self.member=self.target/'fixed.py';self.member.write_bytes(b'# fixed fixture, never executed\n')
        if os.name!='nt':self.member.chmod(0o600)
        self.manifest=self.root/'installed-byte-manifest.json'
        self.map={'fixed.py':hashlib.sha256(self.member.read_bytes()).hexdigest()}
        self.write_manifest(self.map)

    def write_manifest(self,mapping):
        self.manifest.write_text(json.dumps({'runtime':'fixture-not-package-pass','all_installed_file_sha256':mapping}))
        if os.name!='nt':self.manifest.chmod(0o600)
        self.pin=hashlib.sha256(self.manifest.read_bytes()).hexdigest()

    def verify(self):
        return MOD.verify_private_target(self.target,self.pin)

    def test_actual_private_bytes_accepted(self):
        self.assertEqual(self.verify()['verified_files'],1)

    def test_changed_source_bytes_rejected(self):
        self.member.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'byte_mismatch'):self.verify()

    def test_added_importable_file_rejected(self):
        extra=self.target/'unreviewed.py';extra.write_bytes(b'# never run')
        if os.name!='nt':extra.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'unreviewed'):self.verify()

    def test_missing_member_rejected(self):
        self.member.unlink()
        with self.assertRaisesRegex(ValueError,'file_missing'):self.verify()

    def test_manifest_tamper_rejected(self):
        self.manifest.write_bytes(self.manifest.read_bytes()+b' ')
        with self.assertRaisesRegex(ValueError,'manifest_hash'):self.verify()

    def test_absent_manifest_rejected_as_explicit_contract_error(self):
        self.manifest.unlink()
        with self.assertRaisesRegex(ValueError,'reviewed_wheel_manifest_missing') as caught:
            self.verify()
        self.assertIs(type(caught.exception),ValueError)

    def test_unpinned_manifest_rejected(self):
        with self.assertRaisesRegex(ValueError,'manifest_sha_required'):MOD.verify_private_target(self.target,None)

    def test_traversal_manifest_rejected(self):
        self.write_manifest({'../escape.py':'0'*64})
        with self.assertRaisesRegex(ValueError,'manifest_member'):self.verify()

    def test_alternate_stream_manifest_rejected(self):
        self.write_manifest({'fixed.py:stream':'0'*64})
        with self.assertRaisesRegex(ValueError,'manifest_member'):self.verify()

    def test_hardlink_member_rejected(self):
        os.link(self.member,self.root/'alias.py')
        with self.assertRaises(ValueError):self.verify()

    def test_symlink_member_rejected(self):
        outside=self.root/'original.py';self.member.rename(outside);self.member.symlink_to(outside)
        with self.assertRaises((ValueError,OSError)):self.verify()

    def test_symlink_directory_rejected(self):
        alias=self.root/'alias';alias.symlink_to(self.target,target_is_directory=True)
        with self.assertRaises((ValueError,OSError)):MOD.verify_private_target(alias,self.pin,self.manifest)

    def test_public_target_rejected_by_real_policy(self):
        if os.name=='nt':acl.set_public_read_acl(self.target)
        else:self.target.chmod(0o755)
        with self.assertRaises(ValueError):self.verify()

    def test_public_file_rejected_by_real_policy(self):
        if os.name=='nt':acl.set_public_read_acl(self.member)
        else:self.member.chmod(0o644)
        with self.assertRaises(ValueError):self.verify()

    def test_public_manifest_rejected_by_real_policy(self):
        if os.name=='nt':acl.set_public_read_acl(self.manifest)
        else:self.manifest.chmod(0o644)
        with self.assertRaises(ValueError):self.verify()

    def test_relative_target_rejected(self):
        with self.assertRaisesRegex(ValueError,'absolute'):MOD.verify_private_target(Path('packages'),self.pin)


if __name__=='__main__':unittest.main()
