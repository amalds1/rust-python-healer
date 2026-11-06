"""Offline, non-official PEP snapshots/changes/supersedes integrity matrix."""

from contextlib import closing
import copy
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sqlite3
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("pep_history", ROOT / "python" / "pep_history.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)
TODAY = "2026-11-01"


def fixture():
    policy = {"schema_version": 1, "policy_id": "local-pep-review-v1", "sources": {
        "pep-operator": {"hostname": "peps.python.org", "ingest_allowed": True,
                         "licenses": ["CC0-1.0"]}}}
    trust = {"schema_version": 1, "authorities": {
        "pep-operator": {"key_hex": "a9" * 32}}}
    item = {"snapshot_id": "pep703-draft-2026-10-12", "number": 703,
            "title": "Synthetic PEP 703 status fixture", "status": "Draft",
            "supersedes": [], "source_uri": "https://peps.python.org/pep-0703/",
            "license_id": "CC0-1.0", "document_text": "Synthetic offline PEP snapshot; not official.",
            "observed_date": "2026-10-12", "authority": "pep-operator",
            "change_summary": "Synthetic status observation"}
    sign(policy, trust, item)
    return policy, trust, {"schema_version": 1, "snapshots": [item]}


def sign(policy, trust, item):
    item["document_sha256"] = hashlib.sha256(
        item["document_text"].encode("utf-8")).hexdigest()
    item["signature"] = module.sign_for_test(
        policy, item, trust["authorities"][item["authority"]]["key_hex"])
    return item


def changed(policy, trust, source, status="Final"):
    item = copy.deepcopy(source)
    item["snapshot_id"] = "pep703-final-2026-10-24"
    item["status"] = status
    item["change_summary"] = "Synthetic PEP status transition"
    item["observed_date"] = "2026-10-24"
    return sign(policy, trust, item)


class PepHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "pep.sqlite"
        self.policy, self.trust, self.manifest = fixture()

    def ingest(self):
        return module.ingest(self.db, self.policy, self.trust, self.manifest)

    def review(self, number=703, days=90):
        return module.review(self.db, number, TODAY, self.policy, self.trust,
                             stale_days=days)

    def test_single_signed_status_snapshot_and_no_live_claim(self):
        report = self.ingest()
        self.assertEqual(report["snapshots_inserted"], 1)
        self.assertEqual(report["status"], "UNVERIFIED_EXTERNAL")
        result = self.review()
        self.assertEqual(result["status"], "UNVERIFIED_EXTERNAL")
        self.assertEqual(result["snapshots"][0]["status"], "Draft")
        self.assertFalse(result["publisher_authenticated"])
        self.assertFalse(result["network_synchronized"])
        self.assertFalse(result["automatic_override"])

    def test_pep_status_change_keeps_both_snapshots_and_requires_review(self):
        first = self.manifest["snapshots"][0]
        self.manifest["snapshots"].append(changed(self.policy, self.trust, first))
        self.ingest()
        result = self.review()
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertTrue(result["status_changed"])
        self.assertEqual([s["status"] for s in result["snapshots"]], ["Draft", "Final"])
        self.assertFalse(result["automatic_override"])

    def test_supersession_unknown_target_requires_review(self):
        first = self.manifest["snapshots"][0]
        first["supersedes"] = [684]
        sign(self.policy, self.trust, first)
        self.ingest()
        result = self.review()
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["needs_review"][0]["reason"],
                         "unresolved_supersedes_reference")
        self.assertEqual(result["needs_review"][0]["numbers"], [684])

    def test_known_supersession_reference_is_kept(self):
        first = self.manifest["snapshots"][0]
        first["supersedes"] = [684]
        sign(self.policy, self.trust, first)
        other = copy.deepcopy(first)
        other.update(snapshot_id="pep684-2026-10-12", number=684, supersedes=[],
                     source_uri="https://peps.python.org/pep-0684/")
        sign(self.policy, self.trust, other)
        self.manifest["snapshots"].append(other)
        self.ingest()
        self.assertEqual(self.review()["status"], "UNVERIFIED_EXTERNAL")
        self.assertEqual(self.review()["snapshots"][0]["supersedes"], [684])

    def test_supersession_cycle_detected_no_automatic_resolution(self):
        first = self.manifest["snapshots"][0]
        first["supersedes"] = [684]
        sign(self.policy, self.trust, first)
        other = copy.deepcopy(first)
        other.update(snapshot_id="pep684-cycle", number=684, supersedes=[703],
                     source_uri="https://peps.python.org/pep-0684/")
        sign(self.policy, self.trust, other)
        self.manifest["snapshots"].append(other)
        self.ingest()
        result = self.review()
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertIn("supersession_cycle", [r["reason"] for r in result["needs_review"]])

    def test_self_supersedes_and_duplicate_edges_denied(self):
        first = self.manifest["snapshots"][0]
        for edges in ([703], [684, 684], [0], [True], list(range(101, 202))):
            first["supersedes"] = edges
            sign(self.policy, self.trust, first)
            with self.assertRaisesRegex(ValueError, "invalid_pep_supersedes_edges"):
                self.ingest()
        self.assertFalse(self.db.exists())

    def test_old_snapshot_is_not_silently_treated_as_current(self):
        first = self.manifest["snapshots"][0]
        first["observed_date"] = "2025-01-01"
        sign(self.policy, self.trust, first)
        self.ingest()
        result = self.review(days=30)
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["needs_review"][0]["reason"], "stale_snapshot")
        self.assertEqual(len(result["snapshots"]), 1)

    def test_future_dated_snapshot_marked_review(self):
        first = self.manifest["snapshots"][0]
        first["observed_date"] = "2026-11-09"
        sign(self.policy, self.trust, first)
        self.ingest()
        self.assertEqual(self.review()["status"], "REVIEW_REQUIRED")
        self.assertEqual(self.review()["needs_review"][0]["reason"], "future_dated")

    def test_sha_content_tamper_rejected_before_database(self):
        self.manifest["snapshots"][0]["document_text"] += " altered"
        with self.assertRaisesRegex(ValueError, "pep_document_sha256_mismatch"):
            self.ingest()
        self.assertFalse(self.db.exists())

    def test_operator_signature_tamper_rejected_before_database(self):
        self.manifest["snapshots"][0]["status"] = "Final"
        with self.assertRaisesRegex(ValueError, "pep_operator_signature_invalid"):
            self.ingest()
        self.assertFalse(self.db.exists())

    def test_non_pep_domain_auth_path_and_credentials_rejected(self):
        first = self.manifest["snapshots"][0]
        for uri in ("https://evil.example.org/pep-0703/",
                    "https://user:password@peps.python.org/pep-0703/",
                    "https://peps.python.org/pep-0704/",
                    "https://peps.python.org/pep-0703/?token=secret",
                    "http://peps.python.org/pep-0703/"):
            first["source_uri"] = uri
            sign(self.policy, self.trust, first)
            with self.assertRaisesRegex(ValueError, "pep_source_authorization_denied"):
                self.ingest()
            self.assertFalse(self.db.exists())

    def test_licensing_explicit_permission_and_trust_revocation(self):
        first = self.manifest["snapshots"][0]
        first["license_id"] = "All Rights Reserved"
        sign(self.policy, self.trust, first)
        with self.assertRaisesRegex(ValueError, "pep_source_authorization_denied"):
            self.ingest()
        first["license_id"] = "CC0-1.0"
        sign(self.policy, self.trust, first)
        self.ingest()
        self.policy["sources"]["pep-operator"]["ingest_allowed"] = False
        self.assertEqual(self.review()["status"], "REVIEW_REQUIRED")

    def test_invalid_status_and_number_fail_closed(self):
        first = self.manifest["snapshots"][0]
        first["status"] = "OfficialVerifiedByUs"
        sign(self.policy, self.trust, first)
        with self.assertRaisesRegex(ValueError, "invalid_pep_status"):
            self.ingest()
        first["status"] = "Draft"
        first["number"] = 0
        sign(self.policy, self.trust, first)
        with self.assertRaisesRegex(ValueError, "invalid_pep_number"):
            self.ingest()

    def test_snapshot_id_duplicate_or_replay_does_not_overwrite(self):
        first = self.manifest["snapshots"][0]
        self.manifest["snapshots"].append(copy.deepcopy(first))
        with self.assertRaisesRegex(ValueError, "duplicate_pep_snapshot"):
            self.ingest()
        self.manifest["snapshots"].pop()
        self.ingest()
        with self.assertRaisesRegex(ValueError, "immutable_pep_snapshot_collision"):
            self.ingest()

    def test_db_policy_replay_tamper_detected(self):
        self.ingest()
        with closing(sqlite3.connect(str(self.db))) as conn:
            with conn:
                conn.execute("UPDATE pep_snapshots SET policy_id='tampered'")
        result = self.review()
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["needs_review"][0]["reason"], "invalid_provenance")
        self.assertEqual(result["snapshots"], [])

    def test_unknown_pep_does_not_imply_missing_or_invalid_pep(self):
        self.ingest()
        result = self.review(number=9998)
        self.assertEqual(result["status"], "NO_EVIDENCE")
        self.assertEqual(result["snapshots"], [])
        self.assertFalse(result["external_pep_feed_verified"])

    def test_operator_key_collision_not_independent_provenance(self):
        self.trust["authorities"]["second"] = {"key_hex": "a9" * 32}
        with self.assertRaisesRegex(ValueError, "duplicate_pep_authority_key"):
            self.ingest()


if __name__ == "__main__":
    unittest.main()
