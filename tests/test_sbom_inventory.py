"""Hermetic SBOM inventory fixtures; no installed code is ever executed."""

from importlib.util import module_from_spec, spec_from_file_location
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("sbom_inventory", ROOT / "python" / "sbom_inventory.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(root, folder="example-1.0.dist-info", name="Example", version="1.0", body=None):
    location = Path(root) / folder
    location.mkdir()
    data = body or (
        "Metadata-Version: 2.1\nName: {}\nVersion: {}\n"
        "Requires-Python: >=3.9\nRequires-Dist: requests>=2\n"
    ).format(name, version)
    (location / "METADATA").write_text(data, encoding="utf-8")
    return location


class SBOMInventoryTests(unittest.TestCase):
    def test_static_inventory_reports_versions_without_executing_package_code(self):
        with tempfile.TemporaryDirectory() as root:
            fixture(root)
            marker = Path(root) / "would_have_executed"
            (Path(root) / "example.py").write_text(
                "open({!r}, 'w').write('bad')".format(str(marker)))
            output = module.inspect([root], include_installed=False)
            self.assertEqual(output["status"], "INVENTORIED_UNVERIFIED")
            self.assertEqual(output["packages_recorded"], 1)
            package = output["packages"][0]
            self.assertEqual(package["name"], "example")
            self.assertEqual(package["version"], "1.0")
            self.assertEqual(package["requires_python"], ">=3.9")
            self.assertEqual(package["requires_dist_count"], 1)
            self.assertEqual(len(package["metadata_sha256"]), 64)
            for denied in ("modules_executed", "source_executed", "installation_performed",
                           "network_used", "vulnerabilities_scanned", "publisher_verified"):
                self.assertIs(output[denied], False)
            self.assertEqual(output["dependency_resolution"], "NOT_RUN")
            self.assertFalse(marker.exists())

    def test_command_line_helper_is_isolated_and_read_only(self):
        with tempfile.TemporaryDirectory() as root:
            fixture(root)
            proc = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-c",
                 (ROOT / "python" / "sbom_inventory.py").read_text(encoding="utf-8"),
                 "--metadata-dir", root, "--only-metadata-dir"],
                capture_output=True, text=True, timeout=10, check=True)
            data = json.loads(proc.stdout)
            self.assertEqual(data["packages_recorded"], 1)
            self.assertFalse(data["vulnerabilities_scanned"])

    def test_malicious_duplicate_name_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            fixture(root, body="Metadata-Version: 2.1\nName: Demo\nName: Stolen\nVersion: 1.0\n")
            result = module.inspect([root], include_installed=False)
            self.assertEqual(result["status"], "PARTIAL_UNVERIFIED")
            self.assertEqual(result["metadata_refused"], 1)
            self.assertEqual(result["packages_recorded"], 0)

    def test_oversized_and_invalid_metadata_cannot_get_inventory_status(self):
        with tempfile.TemporaryDirectory() as root:
            info = fixture(root)
            (info / "METADATA").write_bytes(b"x" * (module.MAX_METADATA_BYTES + 1))
            result = module.inspect([root], include_installed=False)
            self.assertEqual(result["status"], "PARTIAL_UNVERIFIED")
            self.assertEqual(result["metadata_refused"], 1)

    def test_symlinked_metadata_is_refused_without_leaking_private_content(self):
        with tempfile.TemporaryDirectory() as root:
            info = fixture(root)
            sensitive = Path(root) / "outside_private"
            sensitive.write_text("secret credential PRIVATE_DATA")
            (info / "METADATA").unlink()
            (info / "METADATA").symlink_to(sensitive)
            result = module.inspect([root], include_installed=False)
            self.assertEqual(result["metadata_refused"], 1)
            self.assertNotIn("PRIVATE_DATA", json.dumps(result))

    def test_direct_url_is_hashed_without_credentials_or_paths(self):
        with tempfile.TemporaryDirectory() as root:
            info = fixture(root)
            secret_url = "git+https://alice:password@code.example.invalid/private/repo?token=hidden"
            (info / "direct_url.json").write_text(json.dumps({
                "url": secret_url, "vcs_info": {"vcs": "git"}
            }), encoding="utf-8")
            item = module.inspect([root], include_installed=False)["packages"][0]
            self.assertEqual(item["origin"]["status"], "RECORDED_NOT_VERIFIED")
            self.assertEqual(item["origin"]["url_sha256"],
                             hashlib.sha256(secret_url.encode("utf-8")).hexdigest())
            rendered = json.dumps(item)
            for part in ("alice", "password", "/private/repo", "token=hidden"):
                self.assertNotIn(part, rendered)

    def test_direct_url_symlink_or_oversize_never_claims_verified(self):
        with tempfile.TemporaryDirectory() as root:
            info = fixture(root)
            private = Path(root) / "private-origin.json"
            private.write_text('{"url":"https://private.example"}')
            origin = info / "direct_url.json"
            origin.symlink_to(private)
            row = module.inspect([root], include_installed=False)["packages"][0]
            self.assertEqual(row["origin"]["status"], "INVALID_NOT_VERIFIED")
            origin.unlink()
            origin.write_bytes(b"x" * (module.MAX_DIRECT_URL_BYTES + 1))
            row = module.inspect([root], include_installed=False)["packages"][0]
            self.assertEqual(row["origin"]["status"], "INVALID_NOT_VERIFIED")

    def test_duplicate_distributions_are_explicitly_ambiguous(self):
        with tempfile.TemporaryDirectory() as root:
            fixture(root, folder="Example-1.0.dist-info", name="Example", version="1.0")
            fixture(root, folder="Example-2.0.dist-info", name="Example", version="2.0")
            result = module.inspect([root], include_installed=False)
            self.assertEqual(result["packages_recorded"], 2)
            self.assertEqual(result["ambiguous_names"], ["example"])

    def test_distribution_budget_refuses_false_full_inventory(self):
        with tempfile.TemporaryDirectory() as root:
            fixture(root, folder="Alpha-1.0.dist-info", name="Alpha")
            fixture(root, folder="Beta-1.0.dist-info", name="Beta")
            with patch.object(module, "MAX_DISTRIBUTIONS", 1):
                result = module.inspect([root], include_installed=False)
            self.assertEqual(result["status"], "PARTIAL_UNVERIFIED")
            self.assertTrue(result["limit_hit"])
            self.assertEqual(result["packages_recorded"], 1)

    def test_empty_inventory_and_untrusted_root_never_claim_success(self):
        with tempfile.TemporaryDirectory() as root:
            result = module.inspect([root], include_installed=False)
            self.assertEqual(result["status"], "NO_METADATA_FOUND")
            outside = Path(root) / "empty"
            outside.mkdir()
            link = Path(root) / "symlink-root"
            link.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "invalid_metadata_directory"):
                module.inspect([link], include_installed=False)


if __name__ == "__main__":
    unittest.main()
