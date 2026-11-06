"""Actual subprocess crash/WAL, fail-closed restore and local DR gate tests."""

import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import windows_privacy_fixtures as privacy_fixtures
MOD = ROOT / "python" / "dr_recovery_v26.py"
MATRIX_SCRIPT = ROOT / "tools" / "run_dr_recovery_matrix_v26.py"
sys.path.insert(0, str(ROOT / "python"))
SPEC = importlib.util.spec_from_file_location("dr_recovery_v26", MOD)
DR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DR)
MATRIX_SPEC = importlib.util.spec_from_file_location("run_dr_recovery_matrix_v26", MATRIX_SCRIPT)
MATRIX = importlib.util.module_from_spec(MATRIX_SPEC)
MATRIX_SPEC.loader.exec_module(MATRIX)


class DRRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rph-test-dr-v26-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        if os.name == "nt":
            privacy_fixtures.set_private_acl(self.root)
        self.archive_dir = self.root / "archives"
        self.output_dir = self.root / "outputs"
        self.archive_dir.mkdir(mode=0o700)
        self.output_dir.mkdir(mode=0o700)
        self.db = self.root / "source.sqlite"

    def prepare(self):
        DR.create_database(self.db)
        DR.append_committed_event(self.db, 1, "before_snapshot")
        shot = DR.backup_drill.drill_once(self.db, self.archive_dir, "scenario")
        return shot

    def restore(self, shot, target=None):
        return DR.restore_verified(self.archive_dir, shot["archive"],
                                   target or self.output_dir / "restored.sqlite",
                                   shot["sha256"], shot["logical_sha256"])

    def test_full_real_disposable_drill_passes_all_local_gates(self):
        report = DR.selftest()
        self.assertEqual(report["status"], "LOCAL_WAL_CRASH_RESTORE_RTO_RPO_GATES_PASS")
        self.assertEqual(report["rpo_lost_commits_observed"], 1)
        self.assertGreater(report["rto_observed_ms"], 0)
        self.assertLessEqual(report["rto_observed_ms"], report["rto_gate_ms"])
        self.assertTrue(report["wal_committed_snapshot_verified"])
        self.assertTrue(report["snapshot_ledger_chain_verified"])
        self.assertTrue(report["negative_existing_output_never_overwritten"])
        self.assertTrue(report["trusted_fixture_code_executed"])
        self.assertFalse(report["production_disaster_recovery_qualified"])
        self.assertFalse(report["independent_off_host_audit"])

    def test_fault_crashes_are_actual_child_exit_codes(self):
        report = DR.selftest()
        self.assertEqual([item["actual_exit_code"] for item in report["real_child_crashes"]],
                         [74, 75])
        self.assertEqual([item["commit_was_explicitly_completed"]
                          for item in report["real_child_crashes"]], [False, True])

    def test_stricter_rpo_gate_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "rto_or_rpo_gate_failed"):
            DR.selftest(max_lost_commits=0)

    def test_invalid_predeclared_gates_refused(self):
        for settings in ({"max_rto_ms": 0}, {"max_rto_ms": 60001},
                         {"max_lost_commits": -1}, {"max_lost_commits": 101},
                         {"max_rto_ms": 2.5}, {"max_lost_commits": True}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                DR.selftest(**settings)

    def test_new_database_created_without_overwrite(self):
        DR.create_database(self.db)
        with self.assertRaises(FileExistsError):
            DR.create_database(self.db)
        self.assertEqual(DR.event_rows(self.db), [])

    def test_wal_commit_survives_real_immediate_exit(self):
        DR.create_database(self.db)
        DR.append_committed_event(self.db, 1, "before_snapshot")
        before = DR.run_real_crash(self.db, False)
        self.assertEqual(before["actual_exit_code"], 74)
        self.assertEqual([v[0] for v in DR.event_rows(self.db)], [1])
        after = DR.run_real_crash(self.db, True)
        self.assertEqual(after["actual_exit_code"], 75)
        self.assertEqual([v[0] for v in DR.event_rows(self.db)], [1, 3])

    def test_restore_into_new_path_has_matching_logical_contents(self):
        shot = self.prepare()
        result = self.restore(shot)
        self.assertEqual(result["status"], "LOCAL_RECOVERY_VERIFIED_NO_OVERWRITE")
        self.assertEqual([row[0] for row in DR.event_rows(self.output_dir / "restored.sqlite")],
                         [1])
        self.assertTrue(result["no_existing_destination_overwritten"])
        self.assertFalse(result["off_host_recovery_verified"])

    def test_fast_restore_uses_measured_high_resolution_clock_when_monotonic_ticks_are_coarse(self):
        shot = self.prepare()
        with mock.patch.object(DR.time, "monotonic_ns", return_value=0):
            result = self.restore(shot)
        self.assertGreater(result["rto_observed_ms"], 0)
        self.assertEqual(result["rto_clock"], "perf_counter_ns")
        self.assertGreater(result["rto_clock_resolution_seconds"], 0)

    def test_existing_output_never_overwritten(self):
        shot = self.prepare()
        target = self.output_dir / "restored.sqlite"
        target.write_bytes(b"precious-existing-bytes")
        prior = target.read_bytes()
        with self.assertRaises(FileExistsError):
            self.restore(shot, target)
        self.assertEqual(target.read_bytes(), prior)

    def test_symlink_output_never_followed(self):
        shot = self.prepare()
        original = self.output_dir / "original.txt"
        original.write_bytes(b"must-stay-unchanged")
        link = self.output_dir / "restored.sqlite"
        link.symlink_to(original)
        with self.assertRaises(FileExistsError):
            self.restore(shot, link)
        self.assertEqual(original.read_bytes(), b"must-stay-unchanged")

    def test_incorrect_sha_provenance_refused_before_output(self):
        shot = self.prepare()
        target = self.output_dir / "never.sqlite"
        with self.assertRaisesRegex(ValueError, "provenance_sha256_mismatch"):
            DR.restore_verified(self.archive_dir, shot["archive"], target,
                                "f" * 64, shot["logical_sha256"])
        self.assertFalse(target.exists())

    def test_incorrect_logical_provenance_refused_before_output(self):
        shot = self.prepare()
        target = self.output_dir / "never.sqlite"
        with self.assertRaisesRegex(ValueError, "logical_snapshot_mismatch"):
            DR.restore_verified(self.archive_dir, shot["archive"], target,
                                shot["sha256"], "f" * 64)
        self.assertFalse(target.exists())

    def test_archive_tampering_detected_by_existing_chain(self):
        shot = self.prepare()
        archive = self.archive_dir / shot["archive"]
        with archive.open("r+b") as stream:
            stream.seek(0)
            stream.write(b"INVALID_SQLITE_FILE")
        with self.assertRaisesRegex(ValueError, "archive_checksum_mismatch"):
            self.restore(shot)
        self.assertFalse((self.output_dir / "restored.sqlite").exists())

    def test_missing_archive_refused(self):
        shot = self.prepare()
        with self.assertRaises((FileNotFoundError, ValueError)):
            DR.restore_verified(self.archive_dir, "backup-not-present.sqlite",
                                self.output_dir / "missing.sqlite",
                                shot["sha256"], shot["logical_sha256"])

    def test_invalid_path_traversal_refused(self):
        shot = self.prepare()
        with self.assertRaisesRegex(ValueError, "invalid_snapshot_archive_name"):
            DR.restore_verified(self.archive_dir, "../backup-escape.sqlite",
                                self.output_dir / "escape.sqlite",
                                shot["sha256"], shot["logical_sha256"])

    def test_nonprivate_destination_refused(self):
        shot = self.prepare()
        public = self.root / "public"
        public.mkdir(mode=0o777)
        if os.name == "nt":
            privacy_fixtures.set_public_read_acl(public)
        else:
            public.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "directory_must_be_private"):
            self.restore(shot, public / "output.sqlite")
        self.assertFalse((public / "output.sqlite").exists())

    def test_source_event_data_is_bounded(self):
        DR.create_database(self.db)
        for identity, label in ((0, "before_snapshot"),
                                (True, "before_snapshot"),
                                (5, "unknown-label")):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                DR.append_committed_event(self.db, identity, label)

    def test_actual_locally_signed_upgrade_rolls_back(self):
        canary = self.root / "canary"
        canary.mkdir(mode=0o700)
        result = DR.locally_signed_canary_failure(canary)
        self.assertTrue(result["rollback_verified"])
        self.assertTrue(result["locally_signed_test_approval_verified"])
        self.assertFalse(result["production_release_authorized"])

    def test_cli_selftest_passes_without_untrusted_inputs(self):
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(MOD),
                                 "--mode", "selftest"], capture_output=True,
                                text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["status"], "LOCAL_WAL_CRASH_RESTORE_RTO_RPO_GATES_PASS")

    def test_cli_mandatory_restore_fields_fail_closed(self):
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(MOD),
                                 "--mode", "restore"], capture_output=True,
                                text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "NO_PASS")

    def test_cli_forbids_selftest_filenames(self):
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(MOD),
                                 "--mode", "selftest", "--archive-dir", "/tmp"],
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "NO_PASS")

    def test_collector_measures_real_exact_local_cpython_minor(self):
        minor = f"3.{sys.version_info.minor}"
        detail = MATRIX.measure_minor(minor, Path(sys.executable), 5000)
        self.assertEqual(detail["status"], "PASS_BOUND_LOCAL_DR_DRILL_ONLY")
        self.assertEqual(detail["actual_patch"], ".".join(map(str, sys.version_info[:3])))
        self.assertFalse(detail["production_rto_rpo_qualified"])

    def test_collector_rejects_falsely_labeled_minor(self):
        with self.assertRaises(ValueError):
            MATRIX.measure_minor("3.99", Path(sys.executable), 5000)

    def test_collector_rejects_relative_runtime(self):
        minor = f"3.{sys.version_info.minor}"
        with self.assertRaises(ValueError):
            MATRIX.measure_minor(minor, Path("python3"), 5000)


if __name__ == "__main__":
    unittest.main()
