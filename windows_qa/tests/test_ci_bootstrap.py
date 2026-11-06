"""Acquisition boundaries: no downloaded executable is invoked by bootstrap."""
import hashlib,importlib.util,io,json,tarfile,tempfile,unittest
from pathlib import Path
from unittest import mock
P=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('ci_tools',P/'ci_bootstrap.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

def tar(path,members):
    with tarfile.open(path,'w:gz') as archive:
        for name,kind in members:
            member=tarfile.TarInfo(name);member.size=1
            if kind=='symlink':member.type=tarfile.SYMTYPE;member.linkname='/outside';member.size=0
            archive.addfile(member,io.BytesIO(b'x') if kind!='symlink' else None)

class CIBootstrapTests(unittest.TestCase):
    def test_undeclared_minor_does_not_create_destination_or_download(self):
        with tempfile.TemporaryDirectory() as folder,mock.patch.object(m,'acquire') as download:
            target=Path(folder)/'new'
            with self.assertRaisesRegex(ValueError,'undeclared_runtime'):m.prepare('3.99',target,{'runtimes':{}})
            download.assert_not_called();self.assertFalse(target.exists())
    def test_wrong_download_pin_retains_bytes_but_does_not_accept_them(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'source';source.write_bytes(b'own fixture')
            out=Path(folder)/'download'
            with self.assertRaisesRegex(ValueError,'sha256_mismatch'):m.acquire(source.as_uri(),out,'0'*64,100)
            self.assertEqual(out.read_bytes(),source.read_bytes())
    def test_download_is_bounded_before_untrusted_archive_processing(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'source';source.write_bytes(b'x'*100)
            with self.assertRaisesRegex(ValueError,'budget_exceeded'):m.acquire(source.as_uri(),Path(folder)/'out',hashlib.sha256(source.read_bytes()).hexdigest(),20)
    def test_archive_traversal_refused_before_extraction(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'bad.tar.gz';target=Path(folder)/'runtime'
            tar(source,[('python/../../outside','file')])
            with self.assertRaisesRegex(ValueError,'unsafe_archive_member'):m.unpack_runtime(source,target)
            self.assertFalse(target.exists());self.assertFalse((Path(folder)/'outside').exists())
    def test_archive_symlink_and_casefold_collision_refused(self):
        for members,reason in [([('python/alias','symlink')],'regular_members_only'),([('python/Python.exe','file'),('python/python.exe','file')],'duplicate_casefold')]:
            with self.subTest(reason=reason),tempfile.TemporaryDirectory() as folder:
                source=Path(folder)/'bad.tar.gz';target=Path(folder)/'runtime';tar(source,members)
                with self.assertRaisesRegex(ValueError,reason):m.unpack_runtime(source,target)
                self.assertFalse(target.exists())
    def test_valid_regular_fixture_is_extracted_without_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'good.tar.gz';target=Path(folder)/'runtime';tar(source,[('python/python.exe','file')])
            self.assertEqual(m.unpack_runtime(source,target).read_bytes(),b'x')
    def test_windows_device_ads_absolute_and_alias_paths_rejected(self):
        for name in ['../escape','/python/x','python/NUL','python/file:stream','python/file.','python\\alias']:
            with self.subTest(name=name),self.assertRaises(ValueError):m.safe_parts(name)

if __name__=='__main__':unittest.main()
