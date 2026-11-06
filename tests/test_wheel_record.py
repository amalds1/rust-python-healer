"""Synthetic installed wheel RECORD fixtures; no package imports or source execution."""

import base64
import csv
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("wheel_record", ROOT / "python" / "wheel_record.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(folder, code="SECRET_SOURCE = 123\n"):
    site = Path(folder)
    info = site / "demo-1.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_text("Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n")
    (site / "demo.py").write_text(code)
    rows = []
    for relative in ("demo.py", "demo-1.0.dist-info/METADATA"):
        body = (site / relative).read_bytes()
        digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode("ascii")
        rows.append((relative, "sha256=" + digest, str(len(body))))
    rows.append(("demo-1.0.dist-info/RECORD", "", ""))
    with (info / "RECORD").open("w", newline="") as output:
        csv.writer(output).writerows(rows)
    return info


class RecordTests(unittest.TestCase):
    def test_valid_record_checks_file_hashes_without_running_code(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / "would_run"
            script = "open({!r},'w').write('executed')\n".format(str(marker))
            fixture(folder, script)
            result = module.inspect(["demo"], [folder])["packages"][0]
            self.assertEqual(result["status"], "FOUND")
            record = result["distributions"][0]["record"]
            self.assertEqual(record["status"], "RECORDED_HASHES_MATCH_NOT_PROVENANCE")
            self.assertEqual(record["verified"], 2)
            self.assertFalse(record["provenance_verified"])
            self.assertFalse(marker.exists())

    def test_tampering_after_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            info = fixture(folder)
            (Path(folder) / "demo.py").write_text("different content same length\n")
            result = module.inspect_record(type("Fake", (), {"_path": info})())
            self.assertEqual(result["status"], "INVALID")
            self.assertIn(result["reason"], ("record_size_mismatch", "record_sha256_mismatch"))

    def test_record_traversal_cannot_read_outside_site_packages(self):
        with tempfile.TemporaryDirectory() as folder:
            info = fixture(folder)
            with (info / "RECORD").open("a", newline="") as output:
                csv.writer(output).writerow(("../private.txt", "sha256=" + "A" * 43, "1"))
            result = module.inspect_record(type("Fake", (), {"_path": info})())
            self.assertEqual(result["status"], "INVALID")
            self.assertEqual(result["reason"], "record_path_traversal")

    def test_symlinks_and_hardlinks_are_not_accepted_as_verified(self):
        with tempfile.TemporaryDirectory() as folder:
            info = fixture(folder)
            (Path(folder) / "demo.py").unlink()
            (Path(folder) / "demo.py").symlink_to(info / "METADATA")
            result = module.inspect_record(type("Fake", (), {"_path": info})())
            self.assertEqual(result["reason"], "record_symlink_refused")
        with tempfile.TemporaryDirectory() as folder:
            info = fixture(folder)
            import os
            os.link(Path(folder) / "demo.py", Path(folder) / "hardlink.py")
            result = module.inspect_record(type("Fake", (), {"_path": info})())
            self.assertEqual(result["reason"], "record_not_plain_file")

    def test_unhashed_installation_never_claims_full_integrity(self):
        with tempfile.TemporaryDirectory() as folder:
            info = fixture(folder)
            with (info / "RECORD").open("a", newline="") as output:
                csv.writer(output).writerow(("unhashed.py", "", ""))
            result = module.inspect_record(type("Fake", (), {"_path": info})())
            self.assertEqual(result["status"], "PARTIAL_UNVERIFIED")
            self.assertEqual(result["unhashed"], 1)

    def test_missing_or_oversized_record_is_not_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            info = fixture(folder)
            (info / "RECORD").unlink()
            result = module.inspect_record(type("Fake", (), {"_path": info})())
            self.assertEqual(result["status"], "NOT_DECLARED")
            (info / "RECORD").write_bytes(b"x" * (module.MAX_RECORD_BYTES + 1))
            result = module.inspect_record(type("Fake", (), {"_path": info})())
            self.assertEqual(result["status"], "INVALID")


if __name__ == "__main__":
    unittest.main()
