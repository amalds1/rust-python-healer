"""Real native path/ACL and bounded inference CPU-counter regression checks."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
import model_evidence_io_v029 as evidence

@unittest.skipUnless(os.name == "nt", "native Windows evidence contract")
class WindowsModelEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="r6-model-evidence-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.key = self.folder / "private.key"
        self.key.write_bytes(b"independent-fixed-test-key-at-least-32-bytes")
        import windows_privacy_fixtures
        self.acl = windows_privacy_fixtures
        self.acl.set_private_acl(self.key)

    def test_private_key_success_public_dacl_and_aliases_refused(self):
        self.assertEqual(evidence.read_regular(self.key,128,True),self.key.read_bytes())
        alias = self.folder / "alias.key"
        alias.symlink_to(self.key)
        with self.assertRaises(ValueError):
            evidence.read_regular(alias,128,True)
        alias.unlink()
        os.link(self.key,alias)
        with self.assertRaises(ValueError):
            evidence.read_regular(self.key,128,True)
        alias.unlink()
        self.acl.set_public_read_acl(self.key)
        with self.assertRaises(ValueError):
            evidence.read_regular(self.key,128,True)

    def test_public_evidence_no_follow_and_size_limits_are_real(self):
        raw = self.key.read_bytes()
        self.assertEqual(evidence.read_regular(self.key,128),raw)
        with self.assertRaises(ValueError):
            evidence.read_regular(self.key,8)
        alias = self.folder / "evidence.json"
        alias.symlink_to(self.key)
        with self.assertRaises(ValueError):
            evidence.read_regular(alias,128)
        alias.unlink()
        os.link(self.key,alias)
        with self.assertRaises(ValueError):
            evidence.read_regular(self.key,128)

    def test_relative_unicode_and_long_ordinary_filename_keep_their_contract(self):
        name = "model evidence "+"x"*70+"\u00e9.json"
        path = self.folder / name
        path.write_bytes(b'{"fixed":42}')
        self.acl.set_private_acl(path)
        relative = os.path.relpath(path,Path.cwd())
        self.assertEqual(evidence.read_regular(relative,128),b'{"fixed":42}')
        self.assertEqual(evidence.read_regular(relative,128,True),b'{"fixed":42}')

    def test_inference_reports_actual_positive_batch_counters(self):
        import real_model_router_v23 as router
        models = router.train_pair()
        for family,model in models.items():
            response,wall_ns,cpu_ns,repetitions = router._measure_inference(family,model,"greatest common divisor")
            self.assertEqual(response["results"][0]["doc_id"],"math.gcd")
            self.assertGreater(wall_ns,0)
            self.assertGreater(cpu_ns,0)
            self.assertGreaterEqual(repetitions,1)
            self.assertLessEqual(repetitions,4096)

if __name__ == "__main__":
    unittest.main()
