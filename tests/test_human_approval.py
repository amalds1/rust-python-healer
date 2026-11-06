"""Human HMAC intent gate: deny-by-default and one-use SQLite nonce ledger."""

import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("human_approval", ROOT / "python" / "human_approval.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)
KEY = {"schema_version": 1, "key_hex": "ab" * 32}
SOURCE = hashlib.sha256(b"known-source").hexdigest()
TARGET = hashlib.sha256(b"known-target").hexdigest()
CLOCK = 2_000_000_000


def approved_token(clock=CLOCK, **overrides):
    result = {"schema_version": 1, "policy_id": "human-v1", "nonce": "a" * 32,
              "issued_at": clock, "expires_at": clock + 120,
              "actor_id": "developer-001", "approver_id": "reviewer-002",
              "action": "SOURCE_MODIFY", "artifact_sha256": SOURCE,
              "target_sha256": TARGET}
    result.update(overrides)
    result["signature"] = module.sign_for_test(result, KEY)
    return result


class HumanApprovalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ledger = self.root / "approval-nonces.sqlite"

    def tearDown(self):
        self.tmp.cleanup()

    def allow(self, token=None, **kwargs):
        return module.consume(self.ledger, token if token is not None else approved_token(), KEY,
                              "developer-001", "SOURCE_MODIFY", SOURCE, TARGET,
                              now=CLOCK + 10, **kwargs)

    def count(self):
        if not self.ledger.exists():
            return 0
        con = sqlite3.connect(str(self.ledger))
        try:
            return con.execute("SELECT COUNT(*) FROM consumed_approvals").fetchone()[0]
        finally:
            con.close()

    def test_valid_signed_intent_is_consumed_once_without_performing_mutation(self):
        result = self.allow()
        self.assertEqual(result["status"], "APPROVAL_CONSUMED_ACTION_NOT_PERFORMED")
        self.assertEqual(result["approved_action"], "SOURCE_MODIFY")
        self.assertEqual(result["target_sha256"], TARGET)
        self.assertEqual(self.count(), 1)
        self.assertFalse(result["mutation_performed"])
        self.assertFalse(result["human_identity_independently_verified"])
        self.assertFalse(result["release_authorized_by_this_tool"])

    def test_replaying_same_nonce_is_rejected_after_first_consumption(self):
        self.allow()
        with self.assertRaisesRegex(ValueError, "approval_nonce_replay_refused"):
            self.allow()
        self.assertEqual(self.count(), 1)

    def test_one_nonce_cannot_authorize_second_action_even_with_valid_signature(self):
        self.allow()
        another = approved_token(action="BINARY_RELEASE")
        with self.assertRaisesRegex(ValueError, "approval_nonce_replay_refused"):
            module.consume(self.ledger, another, KEY, "developer-001",
                           "BINARY_RELEASE", SOURCE, TARGET, now=CLOCK + 10)
        self.assertEqual(self.count(), 1)

    def test_actor_substitution_is_refused_before_nonce_consumption(self):
        with self.assertRaisesRegex(ValueError, "approval_context_mismatch"):
            module.consume(self.ledger, approved_token(), KEY, "intruder-003",
                           "SOURCE_MODIFY", SOURCE, TARGET, now=CLOCK + 10)
        self.assertFalse(self.ledger.exists())

    def test_action_substitution_is_refused_for_installs_and_releases(self):
        for action in ("PACKAGE_INSTALL", "BINARY_RELEASE"):
            with self.subTest(action=action):
                with self.assertRaisesRegex(ValueError, "approval_context_mismatch"):
                    module.consume(self.ledger, approved_token(), KEY, "developer-001",
                                   action, SOURCE, TARGET, now=CLOCK + 10)
        self.assertFalse(self.ledger.exists())

    def test_source_or_target_hash_substitution_cannot_use_old_approval(self):
        for source, target in (("0" * 64, TARGET), (SOURCE, "f" * 64)):
            with self.subTest(source=source, target=target):
                with self.assertRaisesRegex(ValueError, "approval_context_mismatch"):
                    module.consume(self.ledger, approved_token(), KEY, "developer-001",
                                   "SOURCE_MODIFY", source, target, now=CLOCK + 10)
        self.assertFalse(self.ledger.exists())

    def test_a_valid_but_expired_token_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "approval_expired"):
            self.allow(token=approved_token(issued_at=CLOCK - 200,
                                            expires_at=CLOCK - 1))
        self.assertFalse(self.ledger.exists())

    def test_future_token_beyond_clock_skew_is_not_yet_valid(self):
        with self.assertRaisesRegex(ValueError, "approval_not_yet_valid"):
            self.allow(token=approved_token(issued_at=CLOCK + 50,
                                            expires_at=CLOCK + 170))

    def test_long_lived_approval_does_not_bypass_300_second_limit(self):
        with self.assertRaisesRegex(ValueError, "approval_window_too_long"):
            self.allow(token=approved_token(expires_at=CLOCK + 301))

    def test_same_requester_and_approver_refused_even_when_signed(self):
        with self.assertRaisesRegex(ValueError, "self_approval_refused"):
            self.allow(token=approved_token(approver_id="developer-001"))

    def test_edited_signature_or_claimed_source_hash_is_rejected(self):
        changed = copy.deepcopy(approved_token())
        changed["artifact_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "approval_context_mismatch"):
            self.allow(token=changed)
        changed = copy.deepcopy(approved_token())
        changed["signature"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "approval_signature_invalid"):
            self.allow(token=changed)

    def test_wrong_operator_key_cannot_consume_legitimate_token(self):
        with self.assertRaisesRegex(ValueError, "approval_signature_invalid"):
            module.consume(self.ledger, approved_token(),
                           {"schema_version": 1, "key_hex": "cd" * 32},
                           "developer-001", "SOURCE_MODIFY", SOURCE, TARGET,
                           now=CLOCK + 10)

    def test_unsigned_approval_json_denied_by_default(self):
        token = approved_token()
        token.pop("signature")
        with self.assertRaisesRegex(ValueError, "invalid_approval_token_structure"):
            self.allow(token=token)

    def test_two_concurrent_identical_approvals_admit_at_most_one(self):
        token = approved_token()
        def attempt():
            try:
                return module.consume(self.ledger, token, KEY, "developer-001",
                                      "SOURCE_MODIFY", SOURCE, TARGET, now=CLOCK + 10)["status"]
            except (ValueError, sqlite3.Error) as exc:
                return "REJECTED:" + str(exc)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(results.count("APPROVAL_CONSUMED_ACTION_NOT_PERFORMED"), 1)
        self.assertEqual(len([x for x in results if x.startswith("REJECTED:")]), 1)
        self.assertEqual(self.count(), 1)

    def test_nonce_table_blocks_deletion_and_mutation(self):
        self.allow()
        con = sqlite3.connect(str(self.ledger))
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                con.execute("DELETE FROM consumed_approvals")
            with self.assertRaises(sqlite3.IntegrityError):
                con.execute("UPDATE consumed_approvals SET nonce='b'")
        finally:
            con.close()
        self.assertEqual(self.count(), 1)

    def test_invalid_numbers_boolean_and_unsafe_identifiers_rejected(self):
        for payload in (
            approved_token(expires_at=True),
            approved_token(nonce="../unsafe"),
            approved_token(actor_id="../../outside"),
            approved_token(action="DELETE_DATABASE"),
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    self.allow(token=payload)

    def test_symlinked_key_file_or_nonce_database_is_refused(self):
        key_file = self.root / "key.json"
        key_file.write_text(json.dumps(KEY))
        link = self.root / "key-link.json"
        link.symlink_to(key_file)
        with self.assertRaisesRegex(ValueError, "approval_input_symlink_refused"):
            module.read_json(link)
        self.allow()
        db_link = self.root / "db-link.sqlite"
        db_link.symlink_to(self.ledger)
        with self.assertRaisesRegex(ValueError, "approval_ledger_symlink_refused"):
            module.consume(db_link, approved_token(nonce="b" * 32), KEY,
                           "developer-001", "SOURCE_MODIFY", SOURCE, TARGET,
                           now=CLOCK + 10)

    def test_oversized_and_ambiguous_json_refused(self):
        file = self.root / "token.json"
        file.write_bytes(b" " * (module.MAX_INPUT_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "approval_input_not_unique_bounded_file"):
            module.read_json(file)
        file.write_text('{"schema_version":1,"schema_version":2}')
        with self.assertRaisesRegex(ValueError, "duplicate_approval_json_key"):
            module.read_json(file)

    def test_cli_embedded_helper_consumes_token_and_does_not_execute_code(self):
        current = int(time.time())
        token = approved_token(current)
        token_file = self.root / "token.json"
        key_file = self.root / "key.json"
        token_file.write_text(json.dumps(token))
        key_file.write_text(json.dumps(KEY))
        marker = self.root / "user_code_was_run.txt"
        proc = subprocess.run([
            sys.executable, "-I", "-S", "-B", "-c",
            (ROOT / "python" / "human_approval.py").read_text(),
            "--ledger", str(self.ledger), "--token", str(token_file),
            "--key-file", str(key_file), "--actor", "developer-001",
            "--action", "SOURCE_MODIFY", "--artifact-sha256", SOURCE,
            "--target-sha256", TARGET], capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        response = json.loads(proc.stdout)
        self.assertEqual(response["status"], "APPROVAL_CONSUMED_ACTION_NOT_PERFORMED")
        self.assertNotIn(KEY["key_hex"], proc.stdout)
        self.assertFalse(response["mutation_performed"])
        self.assertFalse(marker.exists())
        same = subprocess.run([
            sys.executable, "-I", "-S", "-B", "-c",
            (ROOT / "python" / "human_approval.py").read_text(),
            "--ledger", str(self.ledger), "--token", str(token_file),
            "--key-file", str(key_file), "--actor", "developer-001",
            "--action", "SOURCE_MODIFY", "--artifact-sha256", SOURCE,
            "--target-sha256", TARGET], capture_output=True, text=True, check=False)
        self.assertEqual(same.returncode, 2)
        self.assertEqual(json.loads(same.stdout)["status"], "DENIED")


if __name__ == "__main__":
    unittest.main()
