"""Official PyPI PEP740 Sigstore+Rekor and OSV proof, on all seven CPythons."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "python" / "official_supply_chain_v23.py"
EVIDENCE = ROOT / ".v23-official-evidence"
TOOLS = ROOT / ".v23-pypi-verify"
VERIFIER_PYTHON = (str(ROOT.parent / "python-runtimes/cpython-3.12.16-windows-x86_64-none/python.exe")
                   if os.name == "nt" else shutil.which("python3.12"))
if os.name == "nt":
    from windows_privacy_fixtures import set_private_acl, set_public_read_acl
spec = importlib.util.spec_from_file_location("official_supply_chain_v23", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OfficialSigstoreAndOsvTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (VERIFIER_PYTHON is None or not EVIDENCE.is_dir() or not TOOLS.is_dir()):
            raise RuntimeError("real_official_signed_evidence_and_verifier_required")
        cls.evidence = module._check_evidence(EVIDENCE)
        module._tool_preflight(TOOLS)

    def _report(self):
        return module.verify_pinned_evidence(ROOT, EVIDENCE, TOOLS, VERIFIER_PYTHON)

    def _cli(self, args):
        return subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE)] + args,
                              capture_output=True, timeout=20, check=False)

    def _clone_evidence(self):
        temp = tempfile.TemporaryDirectory(prefix="rph-sigstore-proof-")
        self.addCleanup(temp.cleanup)
        p = Path(temp.name)
        paths = [module.WHEEL_FILE, module.PROVENANCE_FILE, module.active_osv_file(EVIDENCE),
                 module.TRUSTED_ROOT_RELATIVE]
        if os.name == "nt":paths.append(module.WINDOWS_R6_PROFILE_FILE)
        for rel in paths:
            target = p / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((EVIDENCE / rel).read_bytes())
        return p

    def _mutated_attestation(self, callback):
        temp = tempfile.TemporaryDirectory(prefix="rph-tampered-bundle-")
        self.addCleanup(temp.cleanup)
        target = Path(temp.name) / "tampered-provenance.json"
        doc = json.loads((EVIDENCE / module.PROVENANCE_FILE).read_text())
        callback(doc["attestation_bundles"][0]["attestations"][0])
        target.write_text(json.dumps(doc))
        return target

    def test_real_production_sigstore_verifier_accepts_genuine_pypi_publisher(self):
        report = self._report()
        self.assertEqual(report["status"], "OFFICIAL_PYPI_SIGSTORE_AND_BOUNDED_OSV_SBOM_VERIFIED")
        self.assertEqual(report["expected_trusted_publisher"],
                         "https://github.com/pypa/sampleproject")
        self.assertTrue(report["pypi_attestation_verification"]["accepted"])
        self.assertTrue(report["pypi_attestation_verification"]["real_official_sigstore_cli_executed"])
        self.assertTrue(report["pypi_attestation_verification"]["sigstore_production_tuf_offline"])

    def test_real_cwd_shadow_module_cannot_replace_official_verifier(self):
        evidence = self._clone_evidence()
        marker = evidence / "forged-verifier-ran"
        (evidence / "pypi_attestations.py").write_text(
            "from pathlib import Path\nPath('forged-verifier-ran').write_text('executed')\n"
            "print('OK: sampleproject-4.0.0-py3-none-any.whl')\n")
        result = module._verify_official_offline(evidence, TOOLS, VERIFIER_PYTHON,
            repository="https://github.com/malicious/claim")
        self.assertFalse(result["accepted"])
        self.assertFalse(marker.exists())

    def test_windows_forged_sdk_with_genuine_version_metadata_is_rejected(self):
        if os.name != "nt":
            self.assertEqual(module._tool_preflight(TOOLS), TOOLS.absolute())
            return
        temporary = tempfile.TemporaryDirectory(prefix="rph-fake-verifier-")
        self.addCleanup(temporary.cleanup)
        fake = Path(temporary.name)
        for rel in ("pypi_attestations-0.0.30.dist-info/METADATA",
                    "sigstore-4.5.1.dist-info/METADATA",
                    "sigstore/_store/https%3A%2F%2Ftuf-repo-cdn.sigstore.dev/trusted_root.json",
                    module.WINDOWS_VERIFIER_MANIFEST):
            destination = fake / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((TOOLS / rel).read_bytes())
        marker = fake / "forged-verifier-ran"
        (fake / "pypi_attestations.py").write_text(
            "from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n"
            "print('OK: sampleproject-4.0.0-py3-none-any.whl')\n")
        module._tool_preflight(fake)  # Version-only checks are deliberately insufficient.
        with self.assertRaises((ValueError, OSError)):
            module._verify_official_offline(EVIDENCE, fake, VERIFIER_PYTHON)
        self.assertFalse(marker.exists())

    def test_windows_actual_sdk_cache_root_tamper_is_rejected(self):
        evidence = self._clone_evidence()
        if os.name != "nt":
            self.assertEqual(module._check_evidence(evidence)["osv_advisory_count"], 22)
            return
        cache = evidence / "cache/windows-local/sigstore/sigstore-python/Cache/tuf/https%3A%2F%2Ftuf-repo-cdn.sigstore.dev"
        cache.mkdir(parents=True)
        target = cache / "trusted_root.json"
        target.write_text('{"forged":true}')
        with self.assertRaisesRegex(ValueError, "official_verifier_component_sha256_mismatch"):
            module._verify_official_offline(evidence, TOOLS, VERIFIER_PYTHON)
        self.assertEqual(target.read_text(), '{"forged":true}')

    def test_real_wheel_and_pypi_integrity_provenance_content_addressed(self):
        self.assertEqual(len(module._hashed(EVIDENCE / module.WHEEL_FILE,
                                            module.PINNED["wheel"])), 4661)
        self.assertGreater(len(module._hashed(EVIDENCE / module.PROVENANCE_FILE,
                                            module.PINNED["provenance"])), 200)

    def test_production_tuf_root_is_official_and_pinned(self):
        data = module._hashed(EVIDENCE / module.TRUSTED_ROOT_RELATIVE,
                              module.PINNED["tuf_root"])
        root = json.loads(data)
        self.assertIn("certificateAuthorities", root)
        self.assertIn("tlogs", root)

    def test_original_dsse_certificate_and_rekor_inclusion_proof_present(self):
        doc = json.loads((EVIDENCE / module.PROVENANCE_FILE).read_text())
        attestation = doc["attestation_bundles"][0]["attestations"][0]
        self.assertIn("signature", attestation["envelope"])
        material = attestation["verification_material"]
        self.assertTrue(material["certificate"])
        self.assertTrue(material["transparency_entries"][0]["inclusionProof"]["rootHash"])

    def test_real_official_osv_api_advisories_for_vulnerable_fixture(self):
        self.assertEqual(self.evidence["osv_advisory_count"], 22)
        ids = self.evidence["osv_advisory_ids"]
        self.assertTrue(any(id_.startswith("GHSA-") for id_ in ids))
        self.assertTrue(any(id_.startswith("PYSEC-") for id_ in ids))

    def test_bounded_sbom_inventories_real_cargo_and_python_dependencies(self):
        report = self._report()
        components = report["sbom_components"]
        self.assertEqual(len(components), report["sbom_count"])
        self.assertGreater(len(components), 50)
        self.assertTrue(any(c["ecosystem"] == "crates.io" for c in components))
        self.assertTrue(any(c["ecosystem"] == "PyPI" for c in components))
        self.assertTrue(any(c["name"] == "sigstore" and c["version"] == "4.5.1"
                            for c in components))
        self.assertFalse(report["sbom_covers_all_rust_python_dependencies"])
        self.assertFalse(report["full_independent_cve_audit_proven"])

    def test_official_verifier_rejects_wrong_publisher_identity(self):
        check = module._verify_official_offline(
            EVIDENCE, TOOLS, VERIFIER_PYTHON,
            repository="https://github.com/malicious/claim")
        self.assertFalse(check["accepted"])
        self.assertNotEqual(check["exit_code"], 0)

    def test_official_verifier_rejects_one_byte_modified_wheel(self):
        cloned = self._clone_evidence()
        wheel = cloned / module.WHEEL_FILE
        content = bytearray(wheel.read_bytes())
        content[-9] ^= 1
        wheel.write_bytes(content)
        check = module._verify_official_offline(EVIDENCE, TOOLS, VERIFIER_PYTHON,
                                                wheel=wheel)
        self.assertFalse(check["accepted"])
        self.assertNotEqual(check["exit_code"], 0)

    def test_official_verifier_rejects_changed_dsse_signature(self):
        def tamper(att):
            signature = att["envelope"]["signature"]
            att["envelope"]["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
        path = self._mutated_attestation(tamper)
        check = module._verify_official_offline(EVIDENCE, TOOLS, VERIFIER_PYTHON,
                                                provenance=path)
        self.assertFalse(check["accepted"])
        self.assertNotEqual(check["exit_code"], 0)

    def test_official_verifier_rejects_rekor_inclusion_proof_tampering(self):
        def tamper(att):
            proof = att["verification_material"]["transparency_entries"][0]["inclusionProof"]
            root_hash = proof["rootHash"]
            proof["rootHash"] = ("A" if root_hash[0] != "A" else "B") + root_hash[1:]
        path = self._mutated_attestation(tamper)
        check = module._verify_official_offline(EVIDENCE, TOOLS, VERIFIER_PYTHON,
                                                provenance=path)
        self.assertFalse(check["accepted"])
        self.assertNotEqual(check["exit_code"], 0)

    def test_official_verifier_rejects_mutated_fulcio_certificate(self):
        def tamper(att):
            cert = att["verification_material"]["certificate"]
            att["verification_material"]["certificate"] = ("A" if cert[0] != "A" else "B") + cert[1:]
        path = self._mutated_attestation(tamper)
        check = module._verify_official_offline(EVIDENCE, TOOLS, VERIFIER_PYTHON,
                                                provenance=path)
        self.assertFalse(check["accepted"])
        self.assertNotEqual(check["exit_code"], 0)

    def test_pinned_path_rejects_tampered_official_osv_snapshot(self):
        clone = self._clone_evidence()
        osv = clone / module.active_osv_file(EVIDENCE)
        text = osv.read_text()
        osv.write_text(text.replace("urllib3", "fake-lib", 1))
        with self.assertRaisesRegex(ValueError, "official_evidence_sha256_mismatch"):
            module._check_evidence(clone)

    def test_pinned_path_rejects_tampered_tuf_trust_root(self):
        clone = self._clone_evidence()
        root = clone / module.TRUSTED_ROOT_RELATIVE
        data = bytearray(root.read_bytes())
        data[-1] ^= 1
        root.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "official_evidence_sha256_mismatch"):
            module._check_evidence(clone)

    def test_pinned_path_rejects_tampered_pypi_provenance_before_verifier(self):
        clone = self._clone_evidence()
        provenance = clone / module.PROVENANCE_FILE
        provenance.write_bytes(provenance.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "official_evidence_sha256_mismatch"):
            module._check_evidence(clone)

    def test_public_evidence_directory_is_refused(self):
        clone = self._clone_evidence()
        if os.name == "nt":set_public_read_acl(clone)
        else:clone.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private_evidence_or_tool_root_required"):
            module._check_evidence(clone)

    def test_evidence_symlink_is_refused(self):
        clone = self._clone_evidence()
        path = clone / module.WHEEL_FILE
        path.unlink()
        path.symlink_to(EVIDENCE / module.WHEEL_FILE)
        with self.assertRaisesRegex(ValueError, "unsafe_or_oversize_evidence_file"):
            module._check_evidence(clone)

    def test_cli_no_network_capabilities_does_not_execute_verifier(self):
        proc = self._cli([])
        self.assertEqual(proc.returncode, 0)
        report = json.loads(proc.stdout)
        self.assertEqual(report["status"], "OFFICIAL_SUPPLY_CHAIN_VERIFIER_ADAPTER_AVAILABLE")
        self.assertFalse(report["network_performed"])

    def test_cli_actual_official_offline_verification(self):
        proc = self._cli(["--mode", "verify", "--project", str(ROOT),
                          "--evidence", str(EVIDENCE), "--tool-root", str(TOOLS),
                          "--verifier-python", VERIFIER_PYTHON])
        self.assertEqual(proc.returncode, 0, proc.stderr[:300])
        report = json.loads(proc.stdout)
        self.assertEqual(report["status"], "OFFICIAL_PYPI_SIGSTORE_AND_BOUNDED_OSV_SBOM_VERIFIED")
        self.assertEqual(report["osv_fixture_advisory_count"], 22)


if __name__ == "__main__":
    unittest.main()
