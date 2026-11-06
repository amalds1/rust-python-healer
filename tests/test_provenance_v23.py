"""Cryptographic PEP 740, PEP API FTS and supply-chain negative tests."""

import base64
from contextlib import closing
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "python" / "provenance_v23.py"
spec = importlib.util.spec_from_file_location("provenance_v23", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def run_openssl(*args):
    completed = subprocess.run([mod._openssl_executable()] + list(args), capture_output=True,
                               check=False, timeout=8)
    if completed.returncode:
        raise RuntimeError("openssl_fixture_failure:" + repr(completed.stderr[:100]))
    return completed.stdout


class WindowsCryptoBackendTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows installed backend contract")
    def test_cwd_path_and_programfiles_environment_cannot_select_backend(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / "openssl.exe"
            fake.write_bytes(b"fixture; never execute")
            with patch.dict(os.environ, {"PATH": temporary, "ProgramFiles": temporary}):
                actual = Path(mod._openssl_executable())
                self.assertTrue(actual.is_absolute())
                self.assertNotEqual(actual, fake)
                self.assertIn(b"OpenSSL", mod._openssl(["version"]))


def pep_fixture():
    numbers = (703, 740, 751)
    records = {}
    for number in numbers:
        records[str(number)] = {
            "number": number, "title": "Trusted PEP {} offline fixture".format(number),
            "authors": "Fixture", "status": "Final", "type": "Standards Track",
            "topic": "packaging", "created": "01-Jan-2025",
            "python_version": "3.13" if number == 703 else None,
            "superseded_by": None, "replaces": None,
            "url": "https://peps.python.org/pep-{:04d}/".format(number)}
    records["703"]["status"] = "Superseded"
    records["703"]["superseded_by"] = "740"
    records["740"]["replaces"] = "703"
    return json.dumps(records, sort_keys=True, separators=(",", ":")).encode()


def trusted_wheel():
    """Pure PEP 427 three-file wheel with real RECORD SHA/size entries."""
    records = {
        "demo/__init__.py": b"VALUE = 3\n",
        "demo-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nTag: py3-none-any\n",
        "demo-1.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
    }
    rows = []
    for name, content in sorted(records.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        rows.append("{},sha256={},{}\n".format(name, digest, len(content)))
    rows.append("demo-1.0.dist-info/RECORD,,\n")
    records["demo-1.0.dist-info/RECORD"] = "".join(rows).encode()
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, content in sorted(records.items()):
            archive.writestr(name, content)
    return stream.getvalue()


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rph-prov-v23-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def _pep(self, payload=None):
        payload = pep_fixture() if payload is None else payload
        return mod.pep_api_snapshot(payload, hashlib.sha256(payload).hexdigest())

    def _material(self):
        cargo = self.base / "Cargo.lock"
        cargo.write_text("""version = 3
[[package]]
name = "demo-crate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
""")
        wheel = self.base / "demo-1.0-py3-none-any.whl"
        wheel.write_bytes(trusted_wheel())
        binary = self.base / "rust-app"
        binary.write_bytes(b"\x7fELF" + b"\x02\x01" + b"\x00" * 60)
        advisory = json.dumps({"advisories": [
            {"ecosystem": "cargo", "name": "demo-crate", "version": "1.0.0", "id": "CVE-2026-12345"},
            {"ecosystem": "pypi", "name": "demo", "version": "0.9", "id": "CVE-2026-54321"},
        ]}).encode()
        pins = {"cargo_lock_sha256": hashlib.sha256(cargo.read_bytes()).hexdigest(),
                "python_wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                "rust_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "advisory_feed_sha256": hashlib.sha256(advisory).hexdigest()}
        return cargo, wheel, binary, pins, advisory

    # F067 / F211: source-bound complete offline API snapshots.
    def test_official_api_schema_all_fixture_peps_and_edges_index(self):
        report = self._pep()
        self.assertEqual(report["status"], "COMPLETE_CONSISTENT_PEP_API_SNAPSHOT")
        self.assertEqual(len(report["records"]), 3)
        self.assertEqual(report["records"][0]["superseded_by"], [740])
        self.assertFalse(report["official_publisher_authenticated_by_live_https"])

    def test_persist_real_sqlite_fts_source_hash_and_metadata(self):
        parsed = self._pep()
        db_path = self.base / "peps.sqlite"
        report = mod.persist_pep_snapshot(db_path, parsed)
        self.assertEqual(report["count"], 3)
        with closing(sqlite3.connect(str(db_path))) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM pep_fts WHERE pep_fts MATCH 'trusted'").fetchone()[0], 3)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT sha256 FROM provenance").fetchone()[0], parsed["source_sha256"])

    def test_pep_live_source_not_inferred_from_caller_digest(self):
        parsed = self._pep()
        self.assertFalse(parsed["official_publisher_authenticated_by_live_https"])

    def test_pep_changelog_detects_changed_status_and_supersedes(self):
        older = self._pep()
        source = json.loads(pep_fixture())
        source["751"]["status"] = "Active"
        source["751"]["replaces"] = "740"
        raw = json.dumps(source).encode()
        newer = self._pep(raw)
        changes = mod.pep_snapshot_change(older, newer)
        self.assertEqual(changes["changes"], [{"pep": 751, "change": "UPDATED",
                                              "old_status": "Final", "new_status": "Active"}])

    def test_pep_bad_sha_wrong_source_and_untrusted_url_rejected(self):
        with self.assertRaisesRegex(ValueError, "pep_api_sha_mismatch"):
            mod.pep_api_snapshot(pep_fixture(), "f" * 64)
        with self.assertRaisesRegex(ValueError, "untrusted_pep_source"):
            mod.pep_api_snapshot(pep_fixture(), hashlib.sha256(pep_fixture()).hexdigest(),
                                 "https://evil.example/peps.json")

    def test_pep_missing_or_ambiguous_status_fails_closed(self):
        source = json.loads(pep_fixture())
        source["740"]["status"] = "Unknown"
        with self.assertRaisesRegex(ValueError, "invalid_official_pep_record"):
            self._pep(json.dumps(source).encode())

    def test_pep_unknown_superseded_reference_fails_closed(self):
        source = json.loads(pep_fixture())
        source["740"]["replaces"] = "900000"
        with self.assertRaisesRegex(ValueError, "dangling_or_self"):
            self._pep(json.dumps(source).encode())

    def test_pep_duplicate_json_keys_rejected(self):
        raw = b'{"703":{"number":703},"703":{"number":703}}'
        with self.assertRaisesRegex(ValueError, "invalid_json_structure"):
            self._pep(raw)

    def test_pep_existing_database_never_clobbered(self):
        report = self._pep()
        dest = self.base / "existing.sqlite"
        dest.write_bytes(b"private user database")
        with self.assertRaisesRegex(ValueError, "destination_already_exists"):
            mod.persist_pep_snapshot(dest, report)
        self.assertEqual(dest.read_bytes(), b"private user database")

    def test_pep_fetch_rejects_inappropriate_timeout_without_network(self):
        with self.assertRaisesRegex(ValueError, "invalid_network_timeout"):
            mod.fetch_official_peps(0)

    def test_pep_index_cli_capabilities_offline(self):
        completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE)],
                                   capture_output=True, check=False, timeout=8)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"],
                         "READ_ONLY_PROVENANCE_CAPABILITIES")

    def test_pep_index_cli_real_fixture(self):
        source = self.base / "peps.json"
        source.write_bytes(pep_fixture())
        completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE),
                                    "--mode", "pep-index", "--source", str(source),
                                    "--sha256", hashlib.sha256(source.read_bytes()).hexdigest()],
                                   capture_output=True, check=False, timeout=8)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["count"], 3)

    def _fake_pep_reply(self, raw=None, etag='"v1"'):
        return {"status": "COMPLETE_CONSISTENT_PEP_API_SNAPSHOT",
                "raw_bytes": pep_fixture() if raw is None else raw,
                "etag": etag}

    def _private_cache(self):
        folder = self.base / "private-peps"
        folder.mkdir(mode=0o700)
        if os.name == "nt":
            from windows_privacy_fixtures import set_private_acl
            set_private_acl(folder)
        return folder

    def test_pep_sync_real_sqlite_content_addressed_commit(self):
        folder = self._private_cache()
        report = mod.sync_pep_index(folder, lambda etag: self._fake_pep_reply())
        self.assertEqual(report["status"], "PEP_MOCKED_SOURCE_SYNCHRONIZED_NOT_OFFICIAL")
        self.assertEqual(report["pep_count"], 3)
        self.assertFalse(report["live_https_authenticated"])
        snapshot = json.loads((folder / "current.json").read_bytes())
        self.assertEqual(snapshot["sha256"], report["sha256"])
        self.assertEqual(hashlib.sha256((folder / snapshot["source_file"]).read_bytes()).hexdigest(),
                         report["sha256"])
        with closing(sqlite3.connect(str(folder / snapshot["index_file"]))) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM peps").fetchone()[0], 3)

    def test_pep_sync_304_rehashes_locally_before_acceptance(self):
        folder = self._private_cache()
        mod.sync_pep_index(folder, lambda etag: self._fake_pep_reply())
        report = mod.sync_pep_index(folder, lambda etag: {
            "status": "OFFICIAL_PEP_NOT_MODIFIED_TLS", "etag": etag})
        self.assertEqual(report["status"], "PEP_CACHE_SHA_VERIFIED_UNCHANGED")
        self.assertFalse(report["live_https_authenticated"])
        self.assertTrue(report["304_not_used_as_hash_replacement"])

    def test_pep_sync_rejects_tampered_legacy_cache_before_network(self):
        folder = self._private_cache()
        mod.sync_pep_index(folder, lambda etag: self._fake_pep_reply())
        manifest = json.loads((folder / "current.json").read_text())
        (folder / manifest["source_file"]).write_bytes(b"tampered cached peps")
        called = []
        with self.assertRaisesRegex(ValueError, "stale_or_tampered"):
            mod.sync_pep_index(folder, lambda etag: called.append(True))
        self.assertEqual(called, [])

    def test_pep_sync_new_status_keeps_prior_evidence_and_changes(self):
        folder = self._private_cache()
        old = mod.sync_pep_index(folder, lambda etag: self._fake_pep_reply())
        updated = json.loads(pep_fixture())
        updated["751"]["status"] = "Active"
        raw = json.dumps(updated, sort_keys=True).encode()
        report = mod.sync_pep_index(folder, lambda etag: self._fake_pep_reply(raw, '"v2"'))
        self.assertEqual(report["changes"][0]["pep"], 751)
        self.assertNotEqual(report["sha256"], old["sha256"])
        self.assertTrue((folder / ("peps-" + old["sha256"] + ".json")).is_file())

    def test_pep_sync_public_directory_and_symlink_denied(self):
        bad = self.base / "public-peps"
        bad.mkdir(mode=0o755)
        if os.name == "nt":
            from windows_privacy_fixtures import set_public_read_acl
            set_public_read_acl(bad)
        with self.assertRaisesRegex(ValueError, "private_pep_cache_required"):
            mod.sync_pep_index(bad, lambda etag: self._fake_pep_reply())
        link = self.base / "link-peps"
        link.symlink_to(bad)
        with self.assertRaisesRegex(ValueError, "private_pep_cache_required"):
            mod.sync_pep_index(link, lambda etag: self._fake_pep_reply())

    def test_pep_sync_304_without_earlier_state_denied(self):
        folder = self._private_cache()
        with self.assertRaisesRegex(ValueError, "unverifiable_http_304"):
            mod.sync_pep_index(folder, lambda etag: {
                "status": "OFFICIAL_PEP_NOT_MODIFIED_TLS", "etag": '"v1"'})

    def test_pep_watcher_bound_twice_and_never_invents_tls(self):
        folder = self._private_cache()
        runs = [self._fake_pep_reply(), {"status": "OFFICIAL_PEP_NOT_MODIFIED_TLS", "etag": '"v1"'}]
        report = mod.watch_pep_index(folder, cycles=2, interval_ms=1,
                                     fetcher=lambda etag: runs.pop(0))
        self.assertEqual(report["status"], "BOUNDED_PEP_WATCH_COMPLETED")
        self.assertEqual(len(report["cycles"]), 2)
        self.assertFalse(report["all_live_https_authenticated"])

    def test_pep_watcher_rejects_unbounded_cycles(self):
        with self.assertRaisesRegex(ValueError, "unsafe_pep_watch_schedule"):
            mod.watch_pep_index(self.base, cycles=999)

    # F209 local SBOM against actual wheel RECORD, cargo lock, pinned ELF.
    def test_supply_chain_real_record_crates_bin_and_advisories(self):
        args = self._material()
        report = mod.audit_supply_chain(*args)
        self.assertEqual(report["status"], "LOCAL_SUPPLY_CHAIN_AUDIT_MATCHED_UNOFFICIAL_FEED")
        self.assertEqual(report["cargo_packages_inventoried"], 1)
        self.assertEqual(report["wheel_record_entries_verified"], 4)
        self.assertEqual(report["local_advisories_matching"], [{"id": "CVE-2026-12345", "ecosystem": "cargo"}])
        self.assertFalse(report["external_advisory_publisher_authenticated"])
        self.assertFalse(report["unknown_package_code_executed"])

    def test_supply_chain_tampered_rust_binary_denied(self):
        cargo, wheel, binary, pins, advisory = self._material()
        binary.write_bytes(binary.read_bytes() + b"tampered")
        with self.assertRaisesRegex(ValueError, "release_material_hash_mismatch"):
            mod.audit_supply_chain(cargo, wheel, binary, pins, advisory)

    def test_supply_chain_tampered_advisory_denied(self):
        cargo, wheel, binary, pins, advisory = self._material()
        with self.assertRaisesRegex(ValueError, "advisory_source_pin_mismatch"):
            mod.audit_supply_chain(cargo, wheel, binary, pins, advisory + b"tamper")

    def test_supply_chain_bad_operator_pin_fails_closed(self):
        cargo, wheel, binary, pins, advisory = self._material()
        pins["cargo_lock_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "release_material_hash_mismatch"):
            mod.audit_supply_chain(cargo, wheel, binary, pins, advisory)

    def test_supply_chain_corrupt_wheel_record_denied(self):
        cargo, wheel, binary, pins, advisory = self._material()
        with zipfile.ZipFile(str(wheel), "a") as archive:
            archive.writestr("unexpected.txt", "untracked")
        pins["python_wheel_sha256"] = hashlib.sha256(wheel.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "wheel_record_incomplete"):
            mod.audit_supply_chain(cargo, wheel, binary, pins, advisory)

    def test_supply_chain_hardlinked_binary_denied(self):
        cargo, wheel, binary, pins, advisory = self._material()
        import os
        os.link(binary, self.base / "same-binary")
        with self.assertRaisesRegex(ValueError, "unsafe_file"):
            mod.audit_supply_chain(cargo, wheel, binary, pins, advisory)

    def test_supply_chain_invalid_cve_data_denied(self):
        cargo, wheel, binary, pins, advisory = self._material()
        bad = json.dumps({"advisories": [{"ecosystem": "cargo", "name": "demo-crate", "version": "1.0.0", "id": "fake"}]}).encode()
        pins["advisory_feed_sha256"] = hashlib.sha256(bad).hexdigest()
        with self.assertRaisesRegex(ValueError, "invalid_advisory_entry"):
            mod.audit_supply_chain(cargo, wheel, binary, pins, bad)

    def test_supply_chain_missing_wheel_digest_denied(self):
        cargo, wheel, binary, pins, advisory = self._material()
        bad = io.BytesIO()
        with zipfile.ZipFile(bad, "w") as archive:
            archive.writestr("demo-1.0.dist-info/METADATA", "Name: demo\nVersion: 1.0")
            archive.writestr("demo-1.0.dist-info/RECORD", "demo-1.0.dist-info/METADATA,,\n"
                             "demo-1.0.dist-info/RECORD,,\n")
        wheel.write_bytes(bad.getvalue())
        pins["python_wheel_sha256"] = hashlib.sha256(wheel.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "wheel_record_hash_required"):
            mod.audit_supply_chain(cargo, wheel, binary, pins, advisory)

    # F188 cryptography: genuine v1 DSSE ECDSA P-256 chain against pinned CA.
    def _signing_fixture(self):
        artifact = self.base / "demo-1.0-py3-none-any.whl"
        artifact.write_bytes(trusted_wheel())
        root_key = self.base / "root.key"
        leaf_key = self.base / "leaf.key"
        root_pem = self.base / "root.pem"
        leaf_csr = self.base / "leaf.csr"
        leaf_pem = self.base / "leaf.pem"
        leaf_der = self.base / "leaf.der"
        identity = "https://github.com/example/rust-python-healer/.github/workflows/release.yml@refs/heads/main"
        run_openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(root_key))
        run_openssl("req", "-new", "-x509", "-key", str(root_key), "-days", "2", "-sha256",
                    "-subj", "/CN=Trusted Local Fixture Root", "-addext", "basicConstraints=critical,CA:TRUE",
                    "-out", str(root_pem))
        run_openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(leaf_key))
        run_openssl("req", "-new", "-key", str(leaf_key), "-subj", "/CN=Fixture Publisher",
                    "-out", str(leaf_csr))
        ext = self.base / "leaf.ext"
        ext.write_text("subjectAltName=URI:" + identity + "\nbasicConstraints=critical,CA:FALSE\n"
                       "keyUsage=digitalSignature\n")
        run_openssl("x509", "-req", "-in", str(leaf_csr), "-CA", str(root_pem),
                    "-CAkey", str(root_key), "-CAcreateserial", "-days", "2", "-sha256",
                    "-extfile", str(ext), "-out", str(leaf_pem))
        leaf_der.write_bytes(run_openssl("x509", "-in", str(leaf_pem), "-outform", "DER"))
        root_digest = hashlib.sha256(run_openssl("x509", "-in", str(root_pem), "-outform", "DER")).hexdigest()
        statement = json.dumps({"_type": "https://in-toto.io/Statement/v1",
                                "subject": [{"name": artifact.name,
                                             "digest": {"sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}}],
                                "predicateType": "https://docs.pypi.org/attestations/publish/v1",
                                "predicate": None}, sort_keys=True).encode()
        pae = self.base / "pae.bin"
        pae.write_bytes(mod.dsse_pae(statement))
        sig = self.base / "sig.der"
        run_openssl("dgst", "-sha256", "-sign", str(leaf_key), "-out", str(sig), str(pae))
        att = {"version": 1,
               "envelope": {"statement": base64.b64encode(statement).decode(),
                            "signature": base64.b64encode(sig.read_bytes()).decode()},
               "verification_material": {"certificate": base64.b64encode(leaf_der.read_bytes()).decode(),
                                          "transparency_entries": []}}
        bundle = {"attestation_bundles": [{"publisher": {"kind": "github", "claims": {}},
                                           "attestations": [att]}]}
        return artifact, root_pem.read_bytes(), root_digest, identity, bundle

    def _verify(self, artifact, root_pem, root_digest, identity, bundle, **options):
        return mod.verify_pep740(json.dumps(bundle).encode(), artifact, "demo", "1.0",
                                 root_pem, root_digest, identity, **options)

    def test_pep740_actual_p256_dsse_and_pinned_ca_valid_but_log_unproven(self):
        inputs = self._signing_fixture()
        result = self._verify(*inputs)
        self.assertEqual(result["status"], "NOT_QUALIFIED_NO_AUTHENTICATED_LOG")
        self.assertTrue(result["p256_dsse_signature_valid"])
        self.assertFalse(result["production_install_authorized"])

    def test_pep740_local_crypto_pass_does_not_claim_pypi_publisher(self):
        result = self._verify(*self._signing_fixture(), allow_unverified_log=True)
        self.assertEqual(result["status"], "LOCAL_PINNED_PEP740_CRYPTO_PASS_LOG_UNATTESTED")
        self.assertFalse(result["official_sigstore_trust_root_attested"])
        self.assertFalse(result["rekor_transparency_entry_authenticated"])

    def test_pep740_wrong_root_pin_never_passes(self):
        artifact, root_pem, root_digest, identity, bundle = self._signing_fixture()
        with self.assertRaisesRegex(ValueError, "trusted_root_hash_mismatch"):
            self._verify(artifact, root_pem, "0" * 64, identity, bundle)

    def test_pep740_identity_mismatch_never_passes(self):
        artifact, root_pem, root_digest, identity, bundle = self._signing_fixture()
        with self.assertRaisesRegex(ValueError, "publisher_identity_mismatch"):
            self._verify(artifact, root_pem, root_digest,
                         "https://github.com/another/publisher/release", bundle)

    def test_pep740_signed_artifact_modified_is_not_accepted(self):
        artifact, root_pem, root_digest, identity, bundle = self._signing_fixture()
        artifact.write_bytes(artifact.read_bytes() + b"tampered")
        with self.assertRaisesRegex(ValueError, "intoto_artifact_sha_mismatch"):
            self._verify(artifact, root_pem, root_digest, identity, bundle)

    def test_pep740_wrong_dsse_signature_fails_crypto_check(self):
        artifact, root_pem, root_digest, identity, bundle = self._signing_fixture()
        bundle["attestation_bundles"][0]["attestations"][0]["envelope"]["signature"] = base64.b64encode(b"invalid").decode()
        with self.assertRaisesRegex(ValueError, "cryptographic_verification_failed"):
            self._verify(artifact, root_pem, root_digest, identity, bundle)

    def test_pep740_bad_statement_and_wrong_version_denied(self):
        artifact, root_pem, root_digest, identity, bundle = self._signing_fixture()
        bundle["attestation_bundles"][0]["attestations"][0]["version"] = 2
        with self.assertRaisesRegex(ValueError, "unsupported_attestation_version"):
            self._verify(artifact, root_pem, root_digest, identity, bundle)

    def test_pep740_undocumented_missing_attestations_denied(self):
        artifact, root_pem, root_digest, identity, bundle = self._signing_fixture()
        bundle["attestation_bundles"][0]["attestations"] = []
        with self.assertRaisesRegex(ValueError, "invalid_attestation_count"):
            self._verify(artifact, root_pem, root_digest, identity, bundle)

    def test_pep740_integrity_url_cannot_target_arbitrary_host(self):
        self.assertEqual(mod.integrity_endpoint("demo", "1.0", "demo-1.0-py3-none-any.whl"),
                         "https://pypi.org/integrity/demo/1.0/demo-1.0-py3-none-any.whl/provenance")
        for malicious in ("../", "//evil.example", "demo.whl?token=x", ""):
            with self.assertRaisesRegex(ValueError, "invalid_integrity_route"):
                mod.integrity_endpoint("demo", "1.0", malicious)


if __name__ == "__main__":
    unittest.main()
