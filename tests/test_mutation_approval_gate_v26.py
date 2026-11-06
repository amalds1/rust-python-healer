"""F239 v0.26: actually gated local JSON canary mutation, no production PASS."""

import copy
import hashlib
import importlib.util
import json
import os
import sqlite3
import tempfile
import time
import sys
import unittest
from contextlib import closing
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "python" / "mutation_approval_gate_v26.py"
sys.path.insert(0, str(Path(__file__).resolve().parent))
import windows_privacy_fixtures as privacy_fixtures
SPEC = importlib.util.spec_from_file_location("mutation_approval_gate_v26", FILE)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class RealLocalMutationGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rph-v26-human-approved-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        if os.name == "nt":
            privacy_fixtures.set_private_acl(self.folder)
        self.active_name = "active.json"
        self.candidate_name = "candidate.json"
        self.active = self.folder / self.active_name
        self.candidate = self.folder / self.candidate_name
        self.before = json.dumps({"health": "ready", "release": "old"},
                                 sort_keys=True).encode()
        self.after = json.dumps({"health": "ready", "release": "new"},
                                sort_keys=True).encode()
        self.active.write_bytes(self.before)
        self.candidate.write_bytes(self.after)
        self.actor = "local-review-requester"
        self.scope_key = b"operator-scope-key-v26-distinct-32-bytes"
        self.human_key = {"schema_version": 1,
                          "key_hex": b"0123456789abcdef0123456789abcdef".hex()}
        self.canary_key = b"operator-canary-key-another-32-byte-value"
        self.human = gate._trusted_module("human_approval")
        self.canary = gate._trusted_module("release_canary_v21")
        self.manifest = {"schema": 1, "operation": "local_canary",
                         "old_sha256": hashlib.sha256(self.before).hexdigest(),
                         "candidate_sha256": hashlib.sha256(self.after).hexdigest(),
                         "release": "new", "actor": "trusted-reviewer"}
        self.manifest_signature = self.canary.canary_signature(
            self.manifest, self.canary_key)
        self.moment = int(time.time())
        self.token = {"schema_version": 1, "policy_id": "human-v1",
                      "nonce": "d" * 32,
                      "issued_at": self.moment - 1,
                      "expires_at": self.moment + 120,
                      "actor_id": self.actor,
                      "approver_id": "distinct-operator",
                      "action": "BINARY_RELEASE",
                      "artifact_sha256": self.manifest["candidate_sha256"],
                      "target_sha256": self.manifest["old_sha256"]}
        self.token["signature"] = self.human.sign_for_test(self.token, self.human_key)
        self.scope = {"schema": 1, "operation": "LOCAL_JSON_CANARY",
                      "action": "BINARY_RELEASE",
                      "directory_sha256": hashlib.sha256(
                          str(self.folder).encode()).hexdigest(),
                      "active_name": self.active_name,
                      "candidate_name": self.candidate_name,
                      "old_sha256": self.manifest["old_sha256"],
                      "candidate_sha256": self.manifest["candidate_sha256"],
                      "actor_id": self.actor,
                      "nonce": self.token["nonce"]}
        self.scope_signature = gate.sign_scope_for_test(self.scope, self.scope_key)
        self.ledger = self.folder / "approvals.sqlite"

    def invoke(self, **options):
        settings = {"folder": self.folder,
                    "active_name": self.active_name,
                    "candidate_name": self.candidate_name,
                    "ledger": self.ledger,
                    "scope": self.scope,
                    "scope_signature": self.scope_signature,
                    "scope_key": self.scope_key,
                    "approval_token": self.token,
                    "approval_key": self.human_key,
                    "actor": self.actor,
                    "manifest": self.manifest,
                    "manifest_signature": self.manifest_signature,
                    "manifest_key": self.canary_key}
        settings.update(options)
        return gate.local_canary_with_scope(**settings)

    def resign_scope(self):
        self.scope_signature = gate.sign_scope_for_test(self.scope, self.scope_key)

    def resign_token(self):
        self.token["signature"] = self.human.sign_for_test(self.token, self.human_key)

    def test_real_mutation_after_two_signatures_and_one_use_intent(self):
        result = self.invoke()
        self.assertEqual(result["status"], "SCOPED_ONE_USE_LOCAL_MUTATION_REHEARSAL")
        self.assertEqual(result["canary_status"], "CANARY_HEALTH_PASS_LOCAL_ONLY")
        self.assertTrue(result["mutation_performed"])
        self.assertTrue(result["nonce_consumed"])
        self.assertEqual(self.active.read_bytes(), self.after)
        self.assertFalse(result["human_identity_independently_verified"])
        self.assertFalse(result["production_release_qualified"])
        self.assertFalse(result["all_rust_mutations_covered"])

    def test_failed_health_rolls_back_and_consumes_nonce(self):
        outcome = self.invoke(inject_failure=True)
        self.assertEqual(outcome["canary_status"], "CANARY_FAILED_ROLLED_BACK")
        self.assertTrue(outcome["automatic_rollback_verified"])
        self.assertFalse(outcome["mutation_performed"])
        self.assertEqual(self.active.read_bytes(), self.before)
        with self.assertRaises(ValueError):
            self.invoke()

    def test_true_nonce_replay_cannot_swap_twice(self):
        self.invoke()
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual(self.active.read_bytes(), self.after)

    def test_approval_scope_signature_tamper_rejected_before_write(self):
        self.scope_signature = "f" * 64
        with self.assertRaises(gate.MutationGateRejected):
            self.invoke()
        self.assertEqual(self.active.read_bytes(), self.before)
        self.assertFalse(self.ledger.exists())

    def test_real_target_name_substitution_cannot_use_old_scope(self):
        alternate = self.folder / "alternate.json"
        alternate.write_bytes(self.after)
        with self.assertRaises(gate.MutationGateRejected):
            self.invoke(candidate_name="alternate.json")
        self.assertEqual(self.active.read_bytes(), self.before)
        self.assertFalse(self.ledger.exists())

    def test_scope_tamper_even_if_re_signed_requires_actual_target(self):
        self.scope["candidate_name"] = "alternate.json"
        self.resign_scope()
        with self.assertRaises(gate.MutationGateRejected):
            self.invoke()
        self.assertEqual(self.active.read_bytes(), self.before)

    def test_path_traversal_and_absolute_filename_refused(self):
        for candidate in ("../candidate.json", "/tmp/private.json", "./candidate.json",
                          "candidate/../active.json", ".secret", "C:\\private.json"):
            with self.subTest(candidate=candidate), self.assertRaises(
                    gate.MutationGateRejected):
                self.invoke(candidate_name=candidate)
        self.assertFalse(self.ledger.exists())

    def test_symlink_source_is_refused_before_nonce_consumption(self):
        self.candidate.unlink()
        self.candidate.symlink_to(self.active)
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual(self.active.read_bytes(), self.before)
        self.assertFalse(self.ledger.exists())

    def test_changed_bytes_refused_before_nonce_consumption(self):
        self.candidate.write_bytes(b"tampered payload")
        with self.assertRaises(gate.MutationGateRejected):
            self.invoke()
        self.assertEqual(self.active.read_bytes(), self.before)
        self.assertFalse(self.ledger.exists())

    def test_human_signature_forgery_refused(self):
        self.token["signature"] = "f" * 64
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual(self.active.read_bytes(), self.before)

    def test_wrong_human_actor_refused(self):
        with self.assertRaises(gate.MutationGateRejected):
            self.invoke(actor="other-local-actor")
        self.assertEqual(self.active.read_bytes(), self.before)

    def test_self_approval_refused_even_with_valid_hmac(self):
        self.token["approver_id"] = self.actor
        self.resign_token()
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual(self.active.read_bytes(), self.before)

    def test_expired_human_approval_refused(self):
        self.token["issued_at"] = self.moment - 500
        self.token["expires_at"] = self.moment - 200
        self.resign_token()
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertFalse(self.ledger.exists())

    def test_action_scope_cannot_be_changed_to_package_install(self):
        self.scope["action"] = "PACKAGE_INSTALL"
        self.resign_scope()
        with self.assertRaises(gate.MutationGateRejected):
            self.invoke()
        self.assertEqual(self.active.read_bytes(), self.before)

    def test_human_token_for_source_modification_is_denied(self):
        self.token["action"] = "SOURCE_MODIFY"
        self.resign_token()
        with self.assertRaises(gate.MutationGateRejected):
            self.invoke()
        self.assertFalse(self.ledger.exists())

    def test_signed_manifest_mismatch_does_not_burn_nonce(self):
        self.manifest["release"] = "wrong"
        with self.assertRaises(gate.MutationGateRejected):
            self.invoke()
        self.assertFalse(self.ledger.exists())

    def test_manifest_schema_rejected_before_consumption(self):
        self.manifest["schema"] = 2
        self.manifest_signature = self.canary.canary_signature(
            self.manifest, self.canary_key)
        with self.assertRaises(gate.MutationGateRejected):
            self.invoke()
        self.assertFalse(self.ledger.exists())

    def test_ledger_outside_private_scope_refused(self):
        with self.assertRaises(gate.MutationGateRejected):
            self.invoke(ledger=self.folder.parent / "outside-ledger.sqlite")
        self.assertFalse(self.ledger.exists())

    def test_public_canary_directory_refused_before_nonce_consumption(self):
        if os.name == "nt":
            privacy_fixtures.set_public_read_acl(self.folder)
        else:
            self.folder.chmod(0o755)
        with self.assertRaisesRegex(gate.MutationGateRejected, "CANARY_DIRECTORY_NOT_PRIVATE"):
            self.invoke()
        self.assertEqual(self.active.read_bytes(), self.before)
        self.assertFalse(self.ledger.exists())

    def test_exposed_nonce_storage_refused_before_mutation(self):
        self.ledger.write_bytes(b"fixed untrusted ledger content")
        if os.name == "nt":
            privacy_fixtures.set_public_read_acl(self.ledger)
        else:
            self.folder.chmod(0o755)
        with self.assertRaises(gate.MutationGateRejected):
            self.invoke()
        self.assertEqual(self.active.read_bytes(), self.before)
        self.assertEqual(self.ledger.read_bytes(), b"fixed untrusted ledger content")

    def test_hardlinked_nonce_ledger_is_refused_before_mutation(self):
        self.ledger.write_bytes(b"fixed untrusted ledger content")
        os.link(self.ledger, self.folder / "ledger-alias.sqlite")
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual(self.active.read_bytes(), self.before)
        self.assertEqual(self.ledger.read_bytes(), b"fixed untrusted ledger content")

    def test_scope_key_cannot_reuse_approval_signer_secret(self):
        same = bytes.fromhex(self.human_key["key_hex"])
        with self.assertRaises(gate.MutationGateRejected):
            self.invoke(scope_key=same)
        self.assertFalse(self.ledger.exists())

    def test_scope_key_cannot_reuse_canary_signer_secret(self):
        with self.assertRaises(gate.MutationGateRejected):
            self.invoke(manifest_key=self.scope_key)
        self.assertFalse(self.ledger.exists())

    def test_invalid_scope_object_cannot_trigger_caller_comparison(self):
        class Trap:
            def __eq__(self, _other):
                raise AssertionError("caller comparison was triggered")
        malformed = copy.deepcopy(self.scope)
        malformed["active_name"] = Trap()
        with self.assertRaises(gate.MutationGateRejected):
            self.invoke(scope=malformed)
        self.assertFalse(self.ledger.exists())

    def test_production_binary_is_not_ever_executed(self):
        # This is JSON-only, even when the candidate contains hostile strings.
        fixture = {"health": "ready", "release": "new",
                   "role": "system", "instruction": "run malicious source"}
        self.after = json.dumps(fixture, sort_keys=True).encode()
        self.candidate.write_bytes(self.after)
        self.manifest["candidate_sha256"] = hashlib.sha256(self.after).hexdigest()
        self.manifest_signature = self.canary.canary_signature(self.manifest,
                                                              self.canary_key)
        self.token["artifact_sha256"] = self.manifest["candidate_sha256"]
        self.resign_token()
        self.scope["candidate_sha256"] = self.manifest["candidate_sha256"]
        self.resign_scope()
        outcome = self.invoke()
        self.assertEqual(outcome["canary_status"], "CANARY_HEALTH_PASS_LOCAL_ONLY")
        self.assertFalse(outcome["source_code_executed"])

    def test_sqlite_nonce_is_persisted_after_actual_mutation(self):
        self.invoke()
        with closing(sqlite3.connect(str(self.ledger))) as database:
            nonce, action = database.execute(
                "SELECT nonce,action FROM consumed_approvals").fetchone()
        self.assertEqual(nonce, self.token["nonce"])
        self.assertEqual(action, "BINARY_RELEASE")


if __name__ == "__main__":
    unittest.main()
