"""All 100 real local Cargo/PyPI packages separately checked via official OSV."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "python" / "full_sbom_osv_v23.py"
EVIDENCE = ROOT / ".v23-official-evidence"
TOOLS = ROOT / ".v23-pypi-verify"
AUDITED_ROOT = ROOT if os.name == "nt" else ROOT / "dist" / "prior-v0.23"
spec = importlib.util.spec_from_file_location("full_sbom_osv_v23", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FullLiveOsvQueryBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not EVIDENCE.is_dir() or not TOOLS.is_dir():
            raise RuntimeError("mandatory_real_live_osv_all100_evidence_missing")
        cls.offline = module.verify_offline_snapshot(AUDITED_ROOT, TOOLS, EVIDENCE)
        cls.profile = module.supply.windows_r6_profile(EVIDENCE) if os.name == "nt" else None
        cls.snapshot_file = module.active_snapshot_file(EVIDENCE)
        cls.snapshot_pin = cls.profile["osv_all100_sha256"] if cls.profile else module.PINNED_SNAPSHOT_SHA256
        cls.captured = json.loads((EVIDENCE / cls.snapshot_file).read_bytes())

    def _verified(self):
        return module.verify_offline_snapshot(AUDITED_ROOT, TOOLS, EVIDENCE)

    def _copy_snapshot(self):
        temporary = tempfile.TemporaryDirectory(prefix="rph-osv-forged-response-")
        self.addCleanup(temporary.cleanup)
        evidence = Path(temporary.name)
        (evidence / self.snapshot_file).write_bytes(
            (EVIDENCE / self.snapshot_file).read_bytes())
        if self.profile:
            for name in (module.supply.WINDOWS_R6_PROFILE_FILE, self.profile["osv_all100_wire_file"]):
                (evidence / name).write_bytes((EVIDENCE / name).read_bytes())
        (evidence / module.supply.WHEEL_FILE).write_bytes(
            (EVIDENCE / module.supply.WHEEL_FILE).read_bytes())
        return evidence

    def _forged(self, mutate):
        evidence = self._copy_snapshot()
        payload = json.loads((evidence / self.snapshot_file).read_bytes())
        mutate(payload)
        encoded = module._json_bytes(payload)
        (evidence / self.snapshot_file).write_bytes(encoded)
        if self.profile:
            profile = dict(self.profile)
            profile["osv_all100_sha256"] = hashlib.sha256(encoded).hexdigest()
            with mock.patch.object(module.supply, "windows_r6_profile", return_value=profile):
                return module.verify_offline_snapshot(AUDITED_ROOT, TOOLS, evidence)
        with mock.patch.object(module, "PINNED_SNAPSHOT_SHA256", hashlib.sha256(encoded).hexdigest()):
            return module.verify_offline_snapshot(AUDITED_ROOT, TOOLS, evidence)

    def test_real_official_querybatch_100_of_100_corresponding_results(self):
        self.assertEqual(self.offline["component_count"], 100)
        self.assertEqual(len(self.offline["packages"]), 100)
        self.assertEqual(self.offline["querybatch_source"],
                         "https://api.osv.dev/v1/querybatch")
        self.assertEqual(len(self.captured["response"]["results"]), 100)
        self.assertEqual(len(self.captured["request"]["queries"]), 100)

    def test_exact_package_name_version_and_ecosystem_from_real_sbom(self):
        inventory = module._components(AUDITED_ROOT, TOOLS)
        query = self.captured["request"]["queries"]
        for component, item in zip(inventory, query):
            self.assertEqual(item, {"package": {
                "name": component["name"], "ecosystem": component["ecosystem"]},
                "version": component["version"]})

    def test_all_seven_minor_versions_consume_same_immutable_official_snapshot(self):
        self.assertEqual(module._sha(module._json_bytes(self.captured)),
                         self.snapshot_pin)
        self.assertEqual(self.offline["content_addressed_snapshot_sha256"],
                         self.snapshot_pin)

    def test_official_response_wire_and_parsed_content_both_pinned(self):
        self.assertEqual(self.captured["response_wire_sha256" if self.profile else "response_sha256"],
                         self.profile["osv_all100_wire_sha256"] if self.profile else module.PINNED_WIRE_RESPONSE_SHA256)
        self.assertEqual(module._sha(module._json_bytes(self.captured["response"])),
                         self.profile["osv_all100_canonical_response_sha256"] if self.profile else module.PINNED_WIRE_RESPONSE_SHA256)
        self.assertEqual(self.captured["request_sha256"],
                         self.profile["osv_all100_request_sha256"] if self.profile else module.PINNED_OFFICIAL_REQUEST_SHA256)

    def test_original_official_https_endpoint_and_tls_receipt(self):
        self.assertEqual(self.captured["source"], "https://api.osv.dev/v1/querybatch")
        self.assertIn("HTTPS/TLS", self.captured["transport"])
        self.assertEqual(self.captured["response_http_status"], 200)
        self.assertIsNone(self.captured["response_etag"])

    def test_zero_found_advisories_is_a_recorded_official_result_not_a_safety_claim(self):
        self.assertEqual(self.offline["advisory_findings"], 0)
        self.assertTrue(all(item["advisory_count"] == 0 for item in self.offline["packages"]))
        self.assertTrue(self.offline["osv_snapshot_does_not_prove_absence_of_unknown_vulnerabilities"])

    def test_exact_67_crates_and_33_pypi_components(self):
        packages = self.offline["packages"]
        self.assertEqual(sum(p["ecosystem"] == "crates.io" for p in packages), 67)
        self.assertEqual(sum(p["ecosystem"] == "PyPI" for p in packages), 33)

    def test_no_unjustified_signed_publisher_provenance_claim_for_any_package(self):
        self.assertTrue(all(p["publisher_provenance_status"] == "UNKNOWN"
                            for p in self.offline["packages"]))
        self.assertFalse(self.offline["signed_publisher_provenance_of_all_packages_proven"])
        self.assertFalse(self.offline["project_package_code_executed"])

    def test_platform_artifact_scope_never_claims_unproved_release_authentication(self):
        if self.profile:
            self.assertFalse(self.offline["current_R6_release_binary_attested"])
            self.assertFalse(self.offline["full_product_safety_proven"])
            self.assertFalse(self.offline["legacy_v23_snapshot_replayed"])
            self.assertEqual(self.offline["legacy_snapshot_replay_status"],
                             "HOLD_ORIGINAL_OSV_BYTES_UNAVAILABLE")
            return
        elf = self.offline["rust_elf"]
        self.assertEqual(len(elf["sha256"]), 64)
        self.assertTrue(elf["is_elf"])
        with (AUDITED_ROOT / elf["path"]).open("rb") as binary:
            self.assertEqual(binary.read(4), b"\x7fELF")
        if module.PINNED_FINAL_RELEASE_ELF_SHA256 is None:
            self.assertTrue(self.offline["same_rust_elf_as_capture"])
        else:
            self.assertTrue(self.offline["matches_pinned_final_release_elf"])

    def test_pinned_real_wheel_is_sha_verified_without_import(self):
        self.assertEqual(self.offline["pypi_wheel_sha256"], module.supply.PINNED["wheel"])
        self.assertEqual(module._sha((EVIDENCE / module.supply.WHEEL_FILE).read_bytes()),
                         module.supply.PINNED["wheel"])

    def test_forged_http_body_rejected_even_if_snapshot_hash_recomputed(self):
        def mutate(body):
            body["response"]["results"][0] = {"vulns": [{
                "id": "GHSA-fake-fake-fake", "modified": "2026-01-01T00:00:00Z"}]}
        with self.assertRaisesRegex(ValueError, "forged_official_osv_response_content"):
            self._forged(mutate)

    def test_forged_host_rejected_even_if_snapshot_hash_recomputed(self):
        with self.assertRaisesRegex(ValueError, "forged_osv_source_or_sbom_binding"):
            self._forged(lambda body: body.update({"source": "https://fake.osv.invalid/v1/querybatch"}))

    def test_reordered_query_mapping_rejected_even_if_snapshot_hash_recomputed(self):
        def mutate(body):
            body["request"]["queries"][0], body["request"]["queries"][1] = (
                body["request"]["queries"][1], body["request"]["queries"][0])
        with self.assertRaisesRegex(ValueError, "forged_osv_source_or_sbom_binding"):
            self._forged(mutate)

    def test_missing_osv_result_rejected_before_forged_body_digest(self):
        with self.assertRaisesRegex(ValueError, "osv_response_missing_or_extra_component"):
            self._forged(lambda body: body["response"]["results"].pop())

    def test_tampered_wheel_rejected_even_with_valid_osv_snapshot(self):
        clone = self._copy_snapshot()
        wheel = clone / module.supply.WHEEL_FILE
        raw = bytearray(wheel.read_bytes())
        raw[0] ^= 1
        wheel.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "official_evidence_sha256_mismatch"):
            module.verify_offline_snapshot(AUDITED_ROOT, TOOLS, clone)

    def test_snapshot_overwrite_and_second_live_query_refused(self):
        with mock.patch.object(module, "urlopen", side_effect=AssertionError("network not allowed")):
            with self.assertRaisesRegex(ValueError, "snapshot_already_exists_no_overwrite"):
                module.capture_live(AUDITED_ROOT, TOOLS, EVIDENCE)

    def test_current_artifact_cannot_inherit_unproved_release_claim(self):
        if self.profile:
            with self.assertRaisesRegex(ValueError, "unsupported_current_release_binary_claim"):
                self._forged(lambda body: body.update({"current_R6_release_binary_attested":True}))
            return
        forged_elf = dict(self.offline["rust_elf"])
        forged_elf["sha256"] = "0" * 64
        with mock.patch.object(module, "_rust_elf_metadata", return_value=forged_elf):
            report = self._verified()
            self.assertFalse(report["same_rust_elf_as_capture"])
            self.assertEqual(report["status"], "OFFICIAL_OSV_100_QUERIES_STALE_RUST_ELF_PARTIAL")

    def test_cli_capabilities_is_local_and_no_network(self):
        proc = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE)],
                              capture_output=True, check=False, timeout=10)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["status"],
                         "OFFICIAL_OSV_FULL_SBOM_ADAPTER_AVAILABLE")

    def test_cli_verify_100_real_offline_components(self):
        proc = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE),
                               "--mode", "verify", "--project", str(AUDITED_ROOT),
                               "--tool-root", str(TOOLS), "--evidence", str(EVIDENCE)],
                              capture_output=True, check=False, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr[:200])
        report = json.loads(proc.stdout)
        self.assertEqual(report["component_count"], 100)
        self.assertEqual(report["status"],
                         "OFFICIAL_OSV_100_WINDOWS_R6_COHORT_VERIFIED_RELEASE_HOLD" if self.profile else
                         "OFFICIAL_OSV_100_OF_100_COMPONENTS_QUERIED_OFFLINE_AUDITED")

    def test_caller_modified_profile_cannot_supply_another_trust_key(self):
        if self.profile:
            clone = self._copy_snapshot()
            profile = json.loads((clone / module.supply.WINDOWS_R6_PROFILE_FILE).read_bytes())
            profile["artifact_pins"]["wheel"] = "0" * 64
            (clone / module.supply.WINDOWS_R6_PROFILE_FILE).write_bytes(module._json_bytes(profile))
            with self.assertRaisesRegex(ValueError, "official_evidence_sha256_mismatch"):
                module.verify_offline_snapshot(AUDITED_ROOT, TOOLS, clone)
        else:
            self.assertEqual(module.PINNED_SNAPSHOT_SHA256,
                             "c6888e21999c85b707c1220ce8cd1429629b72135fca461e567df6fae10ba360")


if __name__ == "__main__":
    unittest.main()
