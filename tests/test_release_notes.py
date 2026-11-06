"""Offline release/deprecation records: SHA, operator provenance, review policy."""

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
spec = spec_from_file_location("release_notes", ROOT / "python" / "release_notes.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)
PYTHON_VERSION = "{}.{}.0".format(*sys.version_info[:2])
TODAY = "2026-11-01"


def fixture():
    policy = {"schema_version": 1, "policy_id": "release-v1", "sources": {
        "first": {"hostname": "docs.example.org", "licenses": ["CC-BY-4.0"],
                  "allow_ingest": True},
        "second": {"hostname": "docs2.example.org", "licenses": ["MIT"],
                   "allow_ingest": True}}}
    trust = {"schema_version": 1, "authorities": {
        "first": {"key_hex": "ab" * 32}, "second": {"key_hex": "cd" * 32}}}
    record = {
        "record_id": "numpy-old-api-v1", "authority": "first",
        "source_uri": "https://docs.example.org/numpy/1.26.4/release",
        "license_id": "CC-BY-4.0",
        "release_document": "Fixture: old_api is deprecated in 1.25.0. This is not a real source.",
        "package": "numpy", "package_version": "1.26.4",
        "python_version": PYTHON_VERSION,
        "topic": "deprecation:old_api", "claim": "old_api is deprecated",
        "deprecated_since": "1.25.0", "removal_not_before": "2.0.0",
        "observed_date": "2026-10-12", "signature": "",
    }
    sign(policy, trust, record)
    return policy, trust, {"schema_version": 1, "entries": [record]}


def sign(policy, trust, record):
    record["document_sha256"] = hashlib.sha256(
        record["release_document"].encode("utf-8")).hexdigest()
    record["signature"] = module.sign_for_test(
        policy, record, trust["authorities"][record["authority"]]["key_hex"])
    return record


def another(policy, trust, record, *, different_claim=False):
    new = copy.deepcopy(record)
    new["record_id"] = "alternate-v1"
    new["authority"] = "second"
    new["source_uri"] = "https://docs2.example.org/numpy/1.26.4/release"
    new["license_id"] = "MIT"
    if different_claim:
        new["claim"] = "old_api is not deprecated"
    return sign(policy, trust, new)


class ReleaseNotesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db = Path(self.temporary.name) / "notes.sqlite"
        self.policy, self.trust, self.manifest = fixture()

    def ingest(self):
        return module.ingest(self.db, self.policy, self.trust, self.manifest)

    def review(self, python_version=PYTHON_VERSION, package="numpy",
               package_version="1.26.4", topic="deprecation:old_api", **extra):
        return module.review(self.db, python_version, package, package_version,
                             topic, TODAY, policy=self.policy, trust=self.trust, **extra)

    def test_exact_version_ingestion_and_deprecation_window(self):
        ingested = self.ingest()
        result = self.review()
        self.assertEqual(ingested["entries_inserted"], 1)
        self.assertEqual(result["status"], "OPERATOR_ATTESTED_NOT_PUBLISHER_VERIFIED")
        self.assertFalse(result["review_required"])
        self.assertEqual(result["records"][0]["deprecated_since"], "1.25.0")
        self.assertEqual(result["records"][0]["removal_not_before"], "2.0.0")
        self.assertEqual(result["records"][0]["document_sha256"],
                         self.manifest["entries"][0]["document_sha256"])

    def test_current_actual_minor_attested_and_other_versions_never_inherit_it(self):
        self.ingest()
        self.assertEqual(len(self.review()["records"]), 1)
        other = "3.16.0" if PYTHON_VERSION != "3.16.0" else "3.9.0"
        result = self.review(python_version=other)
        self.assertEqual(result["status"], "NO_EVIDENCE")
        self.assertFalse(result["review_required"])

    def test_incorrect_package_version_or_topic_returns_no_evidence(self):
        self.ingest()
        self.assertEqual(self.review(package_version="1.26.5")["status"], "NO_EVIDENCE")
        self.assertEqual(self.review(package="pandas")["status"], "NO_EVIDENCE")
        self.assertEqual(self.review(topic="deprecation:other_api")["status"], "NO_EVIDENCE")

    def test_two_independent_agreeing_sources_preserved(self):
        first = self.manifest["entries"][0]
        self.manifest["entries"].append(another(self.policy, self.trust, first))
        self.ingest()
        result = self.review()
        self.assertEqual(len(result["records"]), 2)
        self.assertFalse(result["conflicting_claims"])
        self.assertFalse(result["review_required"])
        self.assertEqual({r["authority"] for r in result["records"]},
                         {"first", "second"})

    def test_conflicting_sources_require_review_without_auto_override(self):
        first = self.manifest["entries"][0]
        self.manifest["entries"].append(another(
            self.policy, self.trust, first, different_claim=True))
        self.ingest()
        result = self.review()
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertTrue(result["conflicting_claims"])
        self.assertTrue(result["review_required"])
        self.assertEqual(len(result["records"]), 2)
        self.assertFalse(result["automatic_override"])

    def test_stale_source_review_required_and_not_silently_dropped(self):
        record = self.manifest["entries"][0]
        record["observed_date"] = "2025-01-01"
        sign(self.policy, self.trust, record)
        self.ingest()
        result = self.review(stale_after_days=30)
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["stale_record_ids"], [record["record_id"]])
        self.assertEqual(len(result["records"]), 1)

    def test_future_dated_evidence_requires_review(self):
        record = self.manifest["entries"][0]
        record["observed_date"] = "2026-11-09"
        sign(self.policy, self.trust, record)
        self.ingest()
        result = self.review()
        self.assertEqual(result["future_dated_record_ids"], [record["record_id"]])
        self.assertEqual(result["status"], "REVIEW_REQUIRED")

    def test_sha256_content_tamper_is_rejected_before_database_creation(self):
        self.manifest["entries"][0]["release_document"] += " malicious change"
        with self.assertRaisesRegex(ValueError, "release_document_sha256_mismatch"):
            self.ingest()
        self.assertFalse(self.db.exists())

    def test_signature_tamper_is_rejected_before_database_creation(self):
        self.manifest["entries"][0]["claim"] = "pretend it has been removed"
        with self.assertRaisesRegex(ValueError, "operator_signature_invalid"):
            self.ingest()
        self.assertFalse(self.db.exists())

    def test_unlicensed_sources_are_denied_before_database_creation(self):
        item = self.manifest["entries"][0]
        for new_license in ("NOASSERTION", "Private", "Unknown"):
            item["license_id"] = new_license
            sign(self.policy, self.trust, item)
            with self.assertRaisesRegex(ValueError, "release_document_ingestion_denied"):
                self.ingest()
            self.assertFalse(self.db.exists())
        item["license_id"] = "CC-BY-4.0"
        self.policy["sources"]["first"]["allow_ingest"] = False
        sign(self.policy, self.trust, item)
        with self.assertRaisesRegex(ValueError, "release_document_ingestion_denied"):
            self.ingest()

    def test_hostname_credentials_and_query_tokens_are_denied(self):
        item = self.manifest["entries"][0]
        for uri in ("https://evil.example.org/numpy/1.26.4/",
                    "https://user:password@docs.example.org/numpy/1.26.4/",
                    "https://docs.example.org/numpy/?access_token=secret",
                    "http://docs.example.org/numpy/1.26.4/",
                    "https://docs.example.org/numpy/#access_token"):
            item["source_uri"] = uri
            sign(self.policy, self.trust, item)
            with self.assertRaisesRegex(ValueError, "source_uri_not_authorized"):
                self.ingest()
            self.assertFalse(self.db.exists())

    def test_duplicate_authority_key_is_not_independent_provenance(self):
        self.trust["authorities"]["second"]["key_hex"] = "ab" * 32
        with self.assertRaisesRegex(ValueError, "duplicate_operator_authority_key"):
            self.ingest()
        self.assertFalse(self.db.exists())

    def test_duplicate_entry_ids_and_replay_never_overwrite(self):
        first = self.manifest["entries"][0]
        self.manifest["entries"].append(copy.deepcopy(first))
        with self.assertRaisesRegex(ValueError, "duplicate_release_record_id"):
            self.ingest()
        self.assertFalse(self.db.exists())
        self.manifest["entries"].pop()
        self.ingest()
        with self.assertRaisesRegex(ValueError, "immutable_release_record_collision"):
            self.ingest()
        self.assertEqual(len(self.review()["records"]), 1)

    def test_inverted_or_ambiguous_deprecation_windows_rejected(self):
        item = self.manifest["entries"][0]
        item["removal_not_before"] = "1.24.0"
        sign(self.policy, self.trust, item)
        with self.assertRaisesRegex(ValueError, "inverted_deprecation_window"):
            self.ingest()
        item["removal_not_before"] = "2.0.0rc1"
        sign(self.policy, self.trust, item)
        with self.assertRaisesRegex(ValueError, "prerelease_window_needs_manual_review"):
            self.ingest()

    def test_unbounded_and_fuzzy_query_versions_denied(self):
        self.ingest()
        for invalid in ("3.11.*", "3.11.0; DROP TABLE release_notes", "last", ""):
            with self.assertRaisesRegex(ValueError, "exact_version_required"):
                self.review(python_version=invalid)
        for invalid in (0, -1, True, 3651):
            with self.assertRaisesRegex(ValueError, "invalid_stale_window"):
                self.review(stale_after_days=invalid)

    def test_license_digest_not_publisher_or_external_verification(self):
        ingested = self.ingest()
        result = self.review()
        self.assertFalse(ingested["publisher_verified"])
        self.assertFalse(ingested["source_executed"])
        self.assertFalse(ingested["network_used"])
        self.assertFalse(ingested["source_document_text_stored"])
        self.assertFalse(result["publisher_verified"])
        self.assertFalse(result["automatic_override"])
        self.assertNotIn("Fixture:", repr(result))

    def test_database_claim_tamper_after_ingestion_detected_before_trust(self):
        self.ingest()
        with closing(sqlite3.connect(str(self.db))) as connection:
            with connection:
                connection.execute("UPDATE release_notes SET claim=? WHERE record_id=?",
                                   ("removed from all versions", "numpy-old-api-v1"))
        result = self.review()
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertTrue(result["provenance_rechecked"])
        self.assertEqual(result["invalid_provenance_record_ids"], ["numpy-old-api-v1"])
        self.assertFalse(result["automatic_override"])

    def test_missing_trust_never_returns_attested_provenance(self):
        self.ingest()
        result = module.review(self.db, PYTHON_VERSION, "numpy", "1.26.4",
                               "deprecation:old_api", TODAY)
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertFalse(result["provenance_rechecked"])
        with self.assertRaisesRegex(ValueError, "policy_and_trust_required_together"):
            module.review(self.db, PYTHON_VERSION, "numpy", "1.26.4",
                          "deprecation:old_api", TODAY, policy=self.policy)

    def test_replayed_release_policy_and_revoked_authority_require_review(self):
        self.ingest()
        self.policy["policy_id"] = "another-policy-id"
        self.assertEqual(self.review()["status"], "REVIEW_REQUIRED")
        self.policy["policy_id"] = "release-v1"
        self.policy["sources"]["first"]["allow_ingest"] = False
        result = self.review()
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["invalid_provenance_record_ids"], ["numpy-old-api-v1"])

    def test_database_date_corruption_never_raises_or_autoverifies(self):
        self.ingest()
        with closing(sqlite3.connect(str(self.db))) as connection:
            with connection:
                connection.execute("UPDATE release_notes SET observed_date=?",
                                   ("not-a-valid-date",))
        result = self.review()
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["invalid_provenance_record_ids"], ["numpy-old-api-v1"])


if __name__ == "__main__":
    unittest.main()
