"""Independent snapshot integrity tests, designed for CPython 3.9–3.15."""

from importlib.util import module_from_spec, spec_from_file_location
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

if os.name == "nt":
    from windows_privacy_fixtures import set_private_acl, set_public_read_acl


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("evidence_snapshot", ROOT / "python" / "evidence_snapshot.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)

KEY = "ab" * 32
BAD_KEY = "cd" * 32
CONFIG = hashlib.sha256(b"configuration-v1").hexdigest()
POLICY = hashlib.sha256(b"recorded-at-retention-policy-v1").hexdigest()
SOURCE = b"# Not executed\nprint('would execute')\n"


class EvidenceSnapshotTests(unittest.TestCase):
    def test_key_crlf_and_hardlinked_key_do_not_relax_exact_key_bytes(self):
        self.keyfile.write_bytes((KEY + "\r\n").encode("ascii"))
        with self.assertRaisesRegex(ValueError, "auditor_key_not_protected_regular_file"):
            module.auditor_key_from_file(self.keyfile)
        self.keyfile.write_bytes((KEY + "\n").encode("ascii"))
        os.link(self.keyfile, self.folder / "hardlinked.key")
        with self.assertRaisesRegex(ValueError, "auditor_key_not_protected_regular_file"):
            module.auditor_key_from_file(self.keyfile)

    def test_key_descriptor_closed_if_fdopen_fails(self):
        descriptors = []
        def fail(descriptor, mode):
            descriptors.append(descriptor)
            raise OSError("fixed fdopen failure")
        with mock.patch.object(module.os, "fdopen", side_effect=fail):
            with self.assertRaisesRegex(OSError, "fixed fdopen failure"):
                module.auditor_key_from_file(self.keyfile)
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError):os.fstat(descriptors[0])
        self.keyfile.rename(self.folder / "closed-and-movable.key")

    def test_key_privacy_rechecked_after_read_and_descriptor_closed_on_rejection(self):
        actual_fdopen = module.os.fdopen
        descriptors = []
        path = self.keyfile
        class Stream:
            def __init__(inner, descriptor, mode):
                descriptors.append(descriptor); inner.actual = actual_fdopen(descriptor, mode)
            def __enter__(inner):return inner
            def __exit__(inner, *args):inner.actual.close()
            def fileno(inner):return inner.actual.fileno()
            def read(inner, limit):
                data = inner.actual.read(limit)
                if os.name == "nt":set_public_read_acl(path)
                else:path.chmod(0o644)
                return data
        try:
            with mock.patch.object(module.os, "fdopen", side_effect=Stream):
                with self.assertRaises(ValueError):module.auditor_key_from_file(path)
            self.assertEqual(len(descriptors), 1)
            with self.assertRaises(OSError):os.fstat(descriptors[0])
        finally:
            if os.name == "nt":set_private_acl(path)
            else:path.chmod(0o600)

    def test_source_same_inode_leaf_alias_race_rejected_before_snapshot_record(self):
        path = self.source; backing = self.folder / "backing.py"
        if os.name == "nt":
            boundary = module._windows_helper("source"); actual_open = boundary._open
            def swapped_windows(*args, **kwargs):
                path.rename(backing); path.symlink_to(backing)
                return actual_open(*args, **kwargs)
            with mock.patch.object(boundary, "_open", side_effect=swapped_windows):
                with self.assertRaises(ValueError):self.record()
        else:
            actual_open = module.os.open
            def swapped_posix(*args, **kwargs):
                path.rename(backing); path.symlink_to(backing)
                return actual_open(*args, **kwargs)
            with mock.patch.object(module.os, "open", side_effect=swapped_posix):
                with self.assertRaises(OSError):self.record()
        self.assertEqual(module.inspect(self.conn)["snapshots"], 0)
        self.assertEqual(module.inspect(self.conn)["events"], 0)

    def test_key_same_inode_leaf_alias_race_rejected(self):
        path = self.keyfile; backing = self.folder / "backing.key"
        if os.name == "nt":
            boundary = module._windows_helper("privacy"); actual_open = boundary.open_private_readonly
            def swapped_windows(*args, **kwargs):
                path.rename(backing); path.symlink_to(backing)
                return actual_open(*args, **kwargs)
            with mock.patch.object(boundary, "open_private_readonly", side_effect=swapped_windows):
                with self.assertRaises(ValueError):module.auditor_key_from_file(path)
        else:
            actual_open = module.os.open
            def swapped_posix(*args, **kwargs):
                path.rename(backing); path.symlink_to(backing)
                return actual_open(*args, **kwargs)
            with mock.patch.object(module.os, "open", side_effect=swapped_posix):
                with self.assertRaises(OSError):module.auditor_key_from_file(path)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.db = self.folder / "evidence.sqlite"
        self.source = self.folder / "variant.py"
        self.source.write_bytes(SOURCE)
        self.keyfile = self.folder / "hmac.key"
        self.keyfile.write_bytes((KEY + "\n").encode("ascii"))
        if os.name == "nt":set_private_acl(self.keyfile)
        else:self.keyfile.chmod(0o600)
        self.conn = module.database(self.db)
        self.addCleanup(self.conn.close)
        module.register_experiment(self.conn, "experiment-39-315", 30, 2, POLICY)

    def record(self, variant="v1", created_at=None, key=KEY):
        if created_at is None:
            created_at = int(time.time()) - 10
        signature = module.sign_for_test("experiment-39-315", variant,
                                         hashlib.sha256(self.source.read_bytes()).hexdigest(),
                                         CONFIG, created_at, key)
        return module.record_snapshot(self.conn, "experiment-39-315", variant,
                                      self.source, CONFIG, created_at, signature, key)

    def test_immutable_full_content_recording_hmac_and_read_only_restore_check(self):
        result = self.record()
        self.assertEqual(result["status"], "IMMUTABLE_SNAPSHOT_RECORDED")
        self.assertEqual(result["source_sha256"], hashlib.sha256(SOURCE).hexdigest())
        self.assertFalse(result["source_executed"])
        event_count = module.inspect(self.conn)["events"]
        verified = module.verify_snapshot(self.conn, result["snapshot_id"], KEY)
        self.assertEqual(verified["status"],
                         "LOCAL_INTEGRITY_MATCH_NOT_EXTERNAL_ATTESTATION")
        self.assertTrue(verified["operator_hmac_match"])
        self.assertTrue(verified["source_hash_match"])
        self.assertTrue(verified["retention_window_active"])
        self.assertFalse(verified["source_publisher_authenticated"])
        self.assertEqual(module.inspect(self.conn)["events"], event_count)
        self.assertEqual(self.conn.execute("SELECT source_blob FROM snapshots").fetchone()[0],
                         SOURCE)

    def test_reopen_database_and_per_experiment_policies(self):
        result = self.record()
        with closing(module.database(self.db)) as second:
            self.assertEqual(module.verify_snapshot(second, result["snapshot_id"], KEY)
                             ["status"], "LOCAL_INTEGRITY_MATCH_NOT_EXTERNAL_ATTESTATION")
            self.assertEqual(module.inspect(second)["snapshots"], 1)
            self.assertEqual(module.inspect(second)["chain_breaks"], 0)
            self.assertEqual(module.register_experiment(second, "different", 2, 0, POLICY)
                             ["status"], "POLICY_REGISTERED")
            self.assertEqual(module.inspect(second)["experiments"], 2)

    def test_idempotent_duplicate_never_claims_a_new_test_and_does_not_append_event(self):
        fixed_created_at = int(time.time()) - 10
        result = self.record(created_at=fixed_created_at)
        replay = self.record(created_at=fixed_created_at)
        self.assertEqual(replay["status"], "ALREADY_RECORDED_NO_RETEST")
        self.assertEqual(replay["snapshot_id"], result["snapshot_id"])
        self.assertEqual(module.inspect(self.conn)["snapshots"], 1)
        self.assertEqual(module.inspect(self.conn)["events"], 1)

    def test_replay_of_tampered_signature_is_rejected(self):
        fixed_created_at = int(time.time()) - 10
        result = self.record(created_at=fixed_created_at)
        self.conn.execute("DROP TRIGGER immutable_snapshots_update")
        self.conn.execute("UPDATE snapshots SET source_signature=? WHERE snapshot_id=?",
                          ("ff" * 32, result["snapshot_id"]))
        with self.assertRaisesRegex(ValueError, "conflicting_immutable_snapshot"):
            self.record(created_at=fixed_created_at)
        self.assertEqual(module.verify_snapshot(self.conn, result["snapshot_id"], KEY)
                         ["status"], "INVALID")

    def test_refuses_invalid_signatures_wrong_key_and_wrong_source_hash(self):
        now = int(time.time())
        bad_sig = module.sign_for_test("experiment-39-315", "wrong", "0" * 64,
                                       CONFIG, now, KEY)
        with self.assertRaisesRegex(ValueError, "source_signature_invalid"):
            module.record_snapshot(self.conn, "experiment-39-315", "wrong",
                                   self.source, CONFIG, now, bad_sig, KEY)
        recorded = self.record()
        self.assertFalse(module.verify_snapshot(self.conn, recorded["snapshot_id"],
                                                BAD_KEY)["operator_hmac_match"])
        self.assertEqual(module.inspect(self.conn)["snapshots"], 1)

    def test_append_only_triggers_refuse_update_and_delete_for_all_four_tables(self):
        result = self.record()
        with mock.patch.object(module.time, "time", return_value=time.time() + 86400 * 3):
            module.archive_snapshot(self.conn, result["snapshot_id"])
        for table in ("experiments", "snapshots", "archive_copies", "audit_events"):
            with self.subTest(table=table):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.conn.execute("UPDATE {} SET rowid = rowid+1".format(table))
                with self.assertRaises(sqlite3.IntegrityError):
                    self.conn.execute("DELETE FROM {}".format(table))
        self.assertEqual(module.inspect(self.conn)["status"],
                         "LOCAL_LEDGER_INTACT_NOT_EXTERNAL_ATTESTATION")

    def test_minimum_retention_and_archive_after_stored_ingest_time(self):
        result = self.record(created_at=1_600_000_000)
        before = module.archive_snapshot(self.conn, result["snapshot_id"])
        self.assertEqual(before["status"], "RETENTION_WINDOW_ACTIVE")
        self.assertEqual(module.inspect(self.conn)["archives"], 0)
        # Controlled clock used only within this test, not by the production API.
        simulated_now = int(time.time()) + 3 * 86400
        with mock.patch.object(module.time, "time", return_value=simulated_now):
            archived = module.archive_snapshot(self.conn, result["snapshot_id"])
        self.assertEqual(archived["status"], "ARCHIVED_COPY_RECORDED")
        self.assertFalse(archived["deletion_performed"])
        self.assertTrue(archived["minimum_retention_enforced"])
        self.assertEqual(module.inspect(self.conn)["archives"], 1)
        self.assertEqual(module.inspect(self.conn)["snapshots"], 1)
        self.assertEqual(module.inspect(self.conn)["events"], 2)
        verified = module.verify_snapshot(self.conn, result["snapshot_id"], KEY)
        self.assertTrue(verified["archived"])
        self.assertTrue(verified["archive_bytes_match"])
        self.assertTrue(verified["retention_window_active"])
        self.assertEqual(module.archive_snapshot(self.conn, result["snapshot_id"])
                         ["status"], "ALREADY_ARCHIVED")
        with mock.patch.object(module.time, "time", return_value=simulated_now):
            self.assertEqual(module.archive_snapshot(self.conn, result["snapshot_id"])
                             ["status"], "ALREADY_ARCHIVED")

    def test_archive_clock_cannot_be_fast_forwarded_by_callers(self):
        result = self.record()
        now = int(time.time())
        with self.assertRaisesRegex(ValueError, "untrusted_archive_clock_skew"):
            module.archive_snapshot(self.conn, result["snapshot_id"], now + 1000000)
        with self.assertRaisesRegex(ValueError, "untrusted_archive_clock_skew"):
            module.archive_snapshot(self.conn, result["snapshot_id"], now - 1000000)
        self.assertEqual(module.inspect(self.conn)["archives"], 0)

    def test_backdated_source_metadata_cannot_bypass_ingest_retention(self):
        result = self.record(created_at=42)
        self.assertEqual(module.archive_snapshot(self.conn, result["snapshot_id"])
                         ["status"], "RETENTION_WINDOW_ACTIVE")
        check = module.verify_snapshot(self.conn, result["snapshot_id"], KEY)
        self.assertGreater(check["retention_expires_at"], int(time.time()))
        self.assertEqual(check["retention_basis"],
                         "local_ingest_clock_not_external_timestamp_attestation")

    def test_future_source_timestamp_is_refused_even_with_valid_signature(self):
        with self.assertRaisesRegex(ValueError, "future_snapshot_creation_time_refused"):
            self.record(created_at=int(time.time()) + 86400)
        self.assertEqual(module.inspect(self.conn)["snapshots"], 0)

    def test_audit_chain_tamper_detected_even_if_update_trigger_is_removed(self):
        self.record()
        self.record(variant="v2")
        self.assertEqual(module.inspect(self.conn)["events"], 2)
        self.conn.execute("DROP TRIGGER immutable_events_update")
        self.conn.execute("UPDATE audit_events SET action='ALTERED' WHERE seq=1")
        result = module.inspect(self.conn)
        self.assertEqual(result["status"], "INVALID")
        self.assertGreater(result["chain_breaks"], 0)

    def test_source_blob_tamper_and_archive_copy_tamper_detected(self):
        result = self.record()
        self.conn.execute("DROP TRIGGER immutable_snapshots_update")
        self.conn.execute("UPDATE snapshots SET source_blob=? WHERE snapshot_id=?",
                          (b"malicious", result["snapshot_id"]))
        self.assertEqual(module.verify_snapshot(self.conn, result["snapshot_id"], KEY)
                         ["status"], "INVALID")
        self.assertEqual(module.inspect(self.conn)["blob_mismatches"], 1)

    def test_archived_blob_tamper_detected_after_archive(self):
        result = self.record()
        with mock.patch.object(module.time, "time", return_value=time.time() + 3 * 86400):
            module.archive_snapshot(self.conn, result["snapshot_id"])
        self.conn.execute("DROP TRIGGER immutable_archive_update")
        self.conn.execute("UPDATE archive_copies SET source_blob=?", (b"tampered",))
        self.assertEqual(module.verify_snapshot(self.conn, result["snapshot_id"], KEY)
                         ["status"], "INVALID")
        self.assertEqual(module.inspect(self.conn)["status"], "INVALID")

    def test_sql_injection_and_immutable_retention_policy_conflicts(self):
        with self.assertRaisesRegex(ValueError, "invalid_snapshot_identity"):
            module.register_experiment(self.conn, "x'); DROP TABLE snapshots; --",
                                       30, 2, POLICY)
        with self.assertRaisesRegex(ValueError, "immutable_retention_policy_conflict"):
            module.register_experiment(self.conn, "experiment-39-315", 14, 2, POLICY)
        with self.assertRaisesRegex(ValueError, "invalid_experiment_retention_policy"):
            module.register_experiment(self.conn, "next", 0, 3, POLICY)
        self.assertEqual(module.inspect(self.conn)["experiments"], 1)

    def test_rejects_symlink_hardlink_directory_and_oversized_source(self):
        link = self.folder / "link.py"
        link.symlink_to(self.source)
        with self.assertRaisesRegex(ValueError, "source_symlink_refused"):
            module.source_bytes(link)
        hardlink = self.folder / "hardlink.py"
        os.link(self.source, hardlink)
        with self.assertRaisesRegex(ValueError, "source_not_unique_regular_bounded_file"):
            module.source_bytes(hardlink)
        self.assertEqual(module.inspect(self.conn)["snapshots"], 0)
        with self.assertRaisesRegex(ValueError, "source_not_unique_regular_bounded_file"):
            module.source_bytes(self.folder)
        oversized = self.folder / "large.py"
        oversized.write_bytes(b"z" * (module.MAX_SOURCE_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "source_not_unique_regular_bounded_file"):
            module.source_bytes(oversized)

    def test_python_code_is_never_executed_even_from_signed_snapshot(self):
        marker = self.folder / "executed.marker"
        self.source.write_text("from pathlib import Path\nPath({!r}).write_text('ran')\n".format(
            str(marker)), encoding="utf-8")
        result = self.record()
        self.assertFalse(marker.exists())
        self.assertFalse(module.verify_snapshot(self.conn, result["snapshot_id"], KEY)
                         ["source_executed"])
        self.assertFalse(marker.exists())

    def test_foreign_keys_and_future_or_partial_schema_rejected(self):
        with closing(sqlite3.connect(str(self.folder / "future.sqlite"))) as future:
            future.execute("PRAGMA user_version=42")
        with self.assertRaisesRegex(ValueError, "future_snapshot_schema_refused"):
            module.database(self.folder / "future.sqlite")
        with closing(sqlite3.connect(str(self.folder / "partial.sqlite"))) as partial:
            partial.execute("CREATE TABLE snapshots(fake TEXT)")
            partial.execute("PRAGMA user_version=1")
        with self.assertRaisesRegex(ValueError, "snapshot_schema_not_authoritative"):
            module.database(self.folder / "partial.sqlite")
        self.assertEqual(self.conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)

    def test_rejects_missing_triggers_or_modified_immutable_trigger(self):
        self.conn.close()
        with closing(sqlite3.connect(str(self.db))) as conn:
            conn.execute("DROP TRIGGER immutable_snapshots_update")
            conn.execute("CREATE TRIGGER immutable_snapshots_update BEFORE UPDATE ON snapshots "
                         "BEGIN SELECT 1; END")
        with self.assertRaisesRegex(ValueError, "snapshot_immutability_triggers_corrupted"):
            module.database(self.db)

    def test_symlink_database_and_insecure_secret_files_refused(self):
        alias = self.folder / "alias.sqlite"
        alias.symlink_to(self.db)
        with self.assertRaisesRegex(ValueError, "unsafe_snapshot_database_path"):
            module.database(alias)
        self.assertEqual(module.auditor_key_from_file(self.keyfile), KEY)
        if os.name == "nt":set_public_read_acl(self.keyfile)
        else:self.keyfile.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "auditor_key_not_protected_regular_file"):
            module.auditor_key_from_file(self.keyfile)
        if os.name == "nt":set_private_acl(self.keyfile)
        else:self.keyfile.chmod(0o600)
        key_alias = self.folder / "alias.key"
        key_alias.symlink_to(self.keyfile)
        with self.assertRaisesRegex(ValueError, "auditor_key_symlink_refused"):
            module.auditor_key_from_file(key_alias)

    def test_cli_round_trip_isolated_stdlib_and_does_not_print_secret_key(self):
        script = ROOT / "python" / "evidence_snapshot.py"
        def invoke(*args):
            completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(script),
                                         "--db", str(self.db), *args],
                                       check=True, capture_output=True, text=True)
            self.assertNotIn(KEY, completed.stdout)
            return json.loads(completed.stdout)
        policy = invoke("experiment", "--id", "experiment-39-315",
                        "--retention-days", "30", "--archive-after-days", "2",
                        "--policy-sha256", POLICY)
        self.assertEqual(policy["status"], "EXISTING_POLICY_NOT_MUTATED")
        created_at = int(time.time())
        signature = module.sign_for_test("experiment-39-315", "cli",
                                         hashlib.sha256(SOURCE).hexdigest(),
                                         CONFIG, created_at, KEY)
        recorded = invoke("record", "--experiment", "experiment-39-315",
                          "--variant", "cli", "--code", str(self.source),
                          "--config-sha256", CONFIG, "--created-at", str(created_at),
                          "--signature", signature, "--auditor-key-file", str(self.keyfile))
        self.assertEqual(recorded["status"], "IMMUTABLE_SNAPSHOT_RECORDED")
        verified = invoke("verify", "--snapshot", recorded["snapshot_id"],
                          "--auditor-key-file", str(self.keyfile))
        self.assertEqual(verified["status"],
                         "LOCAL_INTEGRITY_MATCH_NOT_EXTERNAL_ATTESTATION")
        self.assertEqual(invoke("check")["snapshots"], 1)

    def test_two_connection_wal_transaction_and_replay_atomicity(self):
        first = self.record()
        with closing(module.database(self.db)) as separate:
            replay = module.register_experiment(separate, "experiment-39-315", 30, 2,
                                                POLICY)
            self.assertEqual(replay["status"], "EXISTING_POLICY_NOT_MUTATED")
            source = self.source
            created_at = int(time.time())
            signed = module.sign_for_test("experiment-39-315", "second",
                                           hashlib.sha256(SOURCE).hexdigest(), CONFIG,
                                           created_at, KEY)
            second = module.record_snapshot(separate, "experiment-39-315", "second",
                                            source, CONFIG, created_at, signed, KEY)
            self.assertNotEqual(second["snapshot_id"], first["snapshot_id"])
            self.assertEqual(module.inspect(self.conn)["snapshots"], 2)
        with self.assertRaisesRegex(ValueError, "immutable_retention_policy_conflict"):
            module.register_experiment(self.conn, "experiment-39-315", 11, 0, POLICY)
        self.assertEqual(module.inspect(self.conn)["events"], 2)


if __name__ == "__main__":
    unittest.main()
