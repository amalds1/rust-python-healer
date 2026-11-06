"""Package offline evidence/AST inspection matrix, no target package imports."""

import copy
from contextlib import closing
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("package_intelligence", ROOT / "python" / "package_intelligence.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)
PYVER = "{}.{}.0".format(*sys.version_info[:2])
AS_OF = "2026-11-01"


def fixture():
    policy = {"schema_version": 1, "policy_id": "offline-registry-p1", "sources": {
        "registry": {"hostname": "packages.example.org", "ingest_allowed": True,
                     "licenses": ["MIT"]}}}
    trust = {"schema_version": 1, "authorities": {
        "registry": {"key_hex": "ed" * 32}}}
    base = {"authority": "registry", "source_uri": "https://packages.example.org/docs/acme",
            "license_id": "MIT", "document_text": "Local offline package evidence fixture.",
            "observed_date": "2026-10-12", "package": "acme",
            "package_version": "1.2.3", "python_version": PYVER}
    api = dict(base, kind="api", record_id="api-old-acme-v1", symbol="acme.old_api",
               signature_text="old_api(value, *, strict=True)",
               deprecated_since="1.2.0", removed_in="2.0.0",
               changelog="old_api deprecated; use new_api", replacement="acme.new_api")
    advisory = dict(base, kind="advisory", record_id="cve-acme-v1",
                    advisory_id="CVE-2026-12345", severity="high",
                    fixed_version="1.2.4", withdrawn=False)
    distribution = dict(base, kind="distribution", record_id="wheel-acme-v1",
                        artifact_sha256="12" * 32, yanked=True, removed=False,
                        prerelease=False, repository_trust="trusted")
    manifest = {"schema_version": 1, "api": [api], "advisory": [advisory],
                "distribution": [distribution]}
    for entries in (manifest["api"], manifest["advisory"], manifest["distribution"]):
        for record in entries:
            sign(policy, trust, record)
    return policy, trust, manifest


def sign(policy, trust, record):
    record["document_sha256"] = hashlib.sha256(
        record["document_text"].encode("utf-8")).hexdigest()
    record["signature"] = module.sign_for_test(
        policy, record, trust["authorities"][record["authority"]]["key_hex"])
    return record


class PackageIntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "pkg.sqlite"
        self.policy, self.trust, self.manifest = fixture()

    def ingest(self):
        return module.ingest(self.db, self.policy, self.trust, self.manifest)

    def api(self, version="1.2.3", pyver=PYVER):
        return module.lookup_api(self.db, "acme", version, pyver,
                                 self.policy, self.trust, AS_OF)

    def advisories(self, deps=None):
        return module.check_advisories(self.db, {"acme": "1.2.3"} if deps is None else deps,
                                       PYVER, self.policy, self.trust, AS_OF)

    def distribution(self, version="1.2.3"):
        return module.check_distribution(self.db, "acme", version, PYVER,
                                         self.policy, self.trust, AS_OF)

    def scan(self, source):
        return module.locate_obsolete_calls(self.db, source, {"acme": "1.2.3"},
                                            PYVER, self.policy, self.trust, AS_OF)

    def test_index_signature_deprecation_changelog_and_replacement(self):
        self.assertEqual(self.ingest()["records_inserted"], 3)
        result = self.api()
        self.assertEqual(result["status"], "UNVERIFIED_EXTERNAL")
        self.assertEqual(result["apis"][0]["symbol"], "acme.old_api")
        self.assertEqual(result["apis"][0]["signature_text"],
                         "old_api(value, *, strict=True)")
        self.assertEqual(result["apis"][0]["deprecated_since"], "1.2.0")
        self.assertEqual(result["apis"][0]["changelog"],
                         "old_api deprecated; use new_api")

    def test_conflicting_api_deprecation_claims_never_silently_override(self):
        first = self.manifest["api"][0]
        second = copy.deepcopy(first)
        second["record_id"] = "api-old-acme-conflicting"
        second["removed_in"] = "1.3.0"
        sign(self.policy, self.trust, second)
        self.manifest["api"].append(second)
        self.ingest()
        result = self.api()
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["needs_review"][0]["reason"],
                         "conflicting_api_metadata")
        scan = self.scan("import acme\nacme.old_api(1)\n")
        self.assertEqual(scan["findings"], [])
        self.assertEqual(scan["needs_review"][0]["reason"],
                         "conflicting_api_metadata")

    def test_api_exact_python_version_and_package_version(self):
        self.ingest()
        self.assertEqual(self.api(version="1.2.4")["status"], "NO_EVIDENCE")
        self.assertEqual(self.api(pyver="3.16.0")["status"], "NO_EVIDENCE")
        self.assertEqual(len(self.api()["apis"]), 1)

    def test_api_ast_matches_import_and_alias_without_running_code(self):
        self.ingest()
        source = "import acme as lib\nlib.old_api(1)\nfrom acme import old_api as old\nold(2)\n"
        output = self.scan(source)
        self.assertEqual(output["status"], "REVIEW_REQUIRED")
        self.assertEqual([r["line"] for r in output["findings"]], [2, 4])
        self.assertEqual({r["symbol"] for r in output["findings"]}, {"acme.old_api"})
        self.assertFalse(output["target_modules_imported"])
        self.assertFalse(output["source_executed"])
        self.assertFalse(output["automatic_rewrite"])

    def test_ast_ignores_comments_strings_and_other_package(self):
        self.ingest()
        output = self.scan("# acme.old_api()\ns = 'acme.old_api()'\n"
                           "from another_package import old_api\nold_api(2)\n")
        self.assertEqual(output["findings"], [])
        self.assertEqual(output["status"], "NO_MATCH_IN_INDEX")

    def test_ast_skips_shadowed_parameters_and_assigned_aliases(self):
        self.ingest()
        local = self.scan("import acme as lib\ndef handler(lib):\n    return lib.old_api()\n")
        self.assertEqual(local["findings"], [])
        rebound = self.scan("import acme as lib\nlib = object()\nlib.old_api()\n")
        self.assertEqual(rebound["findings"], [])

    def test_ast_statically_rejects_syntax_error_no_execution(self):
        self.ingest()
        with self.assertRaises(SyntaxError):
            self.scan("import acme\nacme.old_api(\n")

    def test_cve_advisory_matches_exact_installed_version_only(self):
        self.ingest()
        result = self.advisories()
        self.assertEqual(result["status"], "UNVERIFIED_EXTERNAL")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["advisory_id"], "CVE-2026-12345")
        self.assertEqual(result["findings"][0]["fixed_version"], "1.2.4")
        self.assertEqual(self.advisories({"acme": "1.2.4"})["findings"], [])
        self.assertFalse(result["advisory_coverage_complete"])

    def test_withdrawn_advisory_not_counted_as_active_vulnerability(self):
        record = self.manifest["advisory"][0]
        record["withdrawn"] = True
        sign(self.policy, self.trust, record)
        self.ingest()
        result = self.advisories()
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["withdrawn_advisory_records"][0]["advisory_id"],
                         "CVE-2026-12345")

    def test_yanked_distribution_requires_review(self):
        self.ingest()
        result = self.distribution()
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertIn("yanked", result["risks"][0]["indicators"])
        self.assertFalse(result["automatic_install"])

    def test_removed_and_untrusted_distribution_indicators(self):
        record = self.manifest["distribution"][0]
        record.update(yanked=False, removed=True, repository_trust="untrusted")
        sign(self.policy, self.trust, record)
        self.ingest()
        indicators = self.distribution()["risks"][0]["indicators"]
        self.assertIn("removed", indicators)
        self.assertIn("repository_not_confirmed_trusted", indicators)

    def test_prerelease_lexical_indicator_even_if_metadata_wrong(self):
        record = self.manifest["distribution"][0]
        record.update(package_version="1.2.3rc1", yanked=False, prerelease=False)
        sign(self.policy, self.trust, record)
        self.ingest()
        result = self.distribution(version="1.2.3rc1")
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertIn("prerelease", result["risks"][0]["indicators"])
        self.assertIn("prerelease_metadata_inconsistent", result["risks"][0]["indicators"])

    def test_dev_prerelease_dotted_version_recognized(self):
        record = self.manifest["distribution"][0]
        record.update(package_version="1.2.3.dev2", yanked=False, prerelease=False)
        sign(self.policy, self.trust, record)
        self.ingest()
        result = self.distribution(version="1.2.3.dev2")
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertIn("prerelease", result["risks"][0]["indicators"])

    def test_stale_evidence_stays_visible_for_review_not_fresh(self):
        record = self.manifest["api"][0]
        record["observed_date"] = "2025-01-01"
        sign(self.policy, self.trust, record)
        self.ingest()
        result = self.api()
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["needs_review"][0]["reason"], "stale_evidence")
        self.assertEqual(result["apis"], [])

    def test_future_dated_advisory_never_treated_as_fresh(self):
        record = self.manifest["advisory"][0]
        record["observed_date"] = "2027-01-01"
        sign(self.policy, self.trust, record)
        self.ingest()
        result = self.advisories()
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["needs_review"][0]["reason"], "future_dated")

    def test_document_sha256_tamper_rejected_before_sqlite(self):
        self.manifest["api"][0]["document_text"] += " poisoned"
        with self.assertRaisesRegex(ValueError, "document_sha256_mismatch"):
            self.ingest()
        self.assertFalse(self.db.exists())

    def test_operator_signature_tamper_rejected_before_sqlite(self):
        self.manifest["api"][0]["changelog"] = "totally safe"
        with self.assertRaisesRegex(ValueError, "operator_attestation_invalid"):
            self.ingest()
        self.assertFalse(self.db.exists())

    def test_license_and_hostname_with_token_rejected(self):
        record = self.manifest["api"][0]
        for uri in ("https://attacker.example.org/", "https://user:pw@packages.example.org/a",
                    "https://packages.example.org/a?token=secret"):
            record["source_uri"] = uri
            sign(self.policy, self.trust, record)
            with self.assertRaisesRegex(ValueError, "unlicensed_or_untrusted_source"):
                self.ingest()
            self.assertFalse(self.db.exists())
        record["source_uri"] = "https://packages.example.org/a"
        record["license_id"] = "UNKNOWN"
        sign(self.policy, self.trust, record)
        with self.assertRaisesRegex(ValueError, "unlicensed_or_untrusted_source"):
            self.ingest()

    def test_duplicate_operator_authority_and_replay_rejected(self):
        self.trust["authorities"]["second"] = {"key_hex": "ed" * 32}
        with self.assertRaisesRegex(ValueError, "duplicate_authority_key"):
            self.ingest()
        self.trust["authorities"].pop("second")
        self.ingest()
        with self.assertRaisesRegex(ValueError, "immutable_evidence_collision"):
            self.ingest()

    def test_db_row_tamper_detected_on_lookup(self):
        self.ingest()
        with closing(sqlite3.connect(str(self.db))) as conn:
            with conn:
                conn.execute("UPDATE package_evidence SET policy_id='forged' WHERE kind='api'")
        result = self.api()
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["apis"], [])
        self.assertEqual(result["needs_review"][0]["reason"], "invalid_provenance")

    def test_policy_revocation_makes_existing_source_untrusted(self):
        self.ingest()
        self.policy["sources"]["registry"]["ingest_allowed"] = False
        self.assertEqual(self.api()["status"], "REVIEW_REQUIRED")
        self.assertEqual(self.advisories()["status"], "REVIEW_REQUIRED")

    def test_invalid_versions_and_bounded_source_rejected(self):
        self.ingest()
        for bad in ("1.2.*", "1.2.3; import os", "latest", ""):
            with self.assertRaisesRegex(ValueError, "exact_package_or_python_version_required"):
                self.api(version=bad)
        with self.assertRaisesRegex(ValueError, "invalid_source_size"):
            self.scan("x" * 200001)

    def test_no_automatic_full_cve_coverage_or_publisher_authenticity(self):
        result = self.ingest()
        self.assertEqual(result["status"], "UNVERIFIED_EXTERNAL")
        self.assertFalse(result["publisher_authenticated"])
        self.assertFalse(result["network_used"])
        self.assertFalse(result["source_executed"])
        self.assertFalse(result["document_text_stored"])
        self.assertFalse(self.advisories()["live_advisory_feed_checked"])


if __name__ == "__main__":
    unittest.main()
