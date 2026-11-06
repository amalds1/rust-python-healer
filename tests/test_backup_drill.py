"""Actual offline periodical WAL/restore exercises on every CPython minor."""

from contextlib import closing
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import windows_privacy_fixtures as privacy_fixtures
SPEC = spec_from_file_location("backup_drill_module", ROOT / "python" / "backup_drill.py")
module = module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class BackupDrillTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rph-backup-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        if os.name == "nt":
            privacy_fixtures.set_private_acl(self.root)
        self.archive = self.root / "archives"
        self.archive.mkdir(mode=0o700)
        self.db = self.root / "knowledge.sqlite"
        self.conn = sqlite3.connect(str(self.db))
        self.addCleanup(self.conn.close)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("CREATE TABLE data (id INTEGER PRIMARY KEY, content TEXT)")
        self.conn.execute("INSERT INTO data(content) VALUES ('committed-1')")
        self.conn.commit()

    def test_wal_backup_restores_committed_record_without_sidelining_writer(self):
        self.conn.execute("INSERT INTO data(content) VALUES ('committed-in-wal')")
        self.conn.commit()
        report = module.drill_once(self.db, self.archive, "wal")
        self.assertEqual(report["status"], "DRILL_RESTORED_AND_SHA_VERIFIED")
        self.assertTrue(report["restoration_verified"])
        with closing(sqlite3.connect(str(self.archive / "backup-wal.sqlite"))) as snapshot:
            self.assertEqual(snapshot.execute("SELECT COUNT(*) FROM data").fetchone()[0], 2)
        self.assertEqual(module.verify_archives(self.archive)["checked"], 1)

    def test_uncommitted_wal_rows_are_not_backed_up(self):
        self.conn.execute("INSERT INTO data(content) VALUES ('never-committed')")
        module.drill_once(self.db, self.archive, "uncommitted")
        with closing(sqlite3.connect(str(self.archive / "backup-uncommitted.sqlite"))) as snapshot:
            self.assertEqual(snapshot.execute("SELECT COUNT(*) FROM data").fetchone()[0], 1)
        self.conn.rollback()

    def test_real_periodic_watch_runs_three_distinct_backup_restore_drills(self):
        result = module.scheduled_drills(self.db, self.archive, cycles=3,
                                         interval_ms=10, identifier_prefix="safe")
        self.assertEqual(result["status"], "PERIODIC_LOCAL_DRILLS_VERIFIED")
        self.assertEqual(len(result["measurements"]), 3)
        self.assertEqual(module.verify_archives(self.archive)["checked"], 3)
        self.assertFalse(result["external_scheduler_installed"])

    def test_corrupt_archive_rejected_by_sha_and_integrity(self):
        module.drill_once(self.db, self.archive, "tamper")
        (self.archive / "backup-tamper.sqlite").write_bytes(b"not SQLite")
        with self.assertRaises(ValueError):
            module.verify_archives(self.archive)

    def test_orphan_archive_after_simulated_crash_fails_closed(self):
        module.drill_once(self.db, self.archive, "committed")
        (self.archive / "backup-orphan.sqlite").write_bytes(b"incomplete-crash-snapshot")
        with self.assertRaisesRegex(ValueError, "untracked_or_missing_archive"):
            module.verify_archives(self.archive)

    def test_corrupt_ledger_event_hash_rejected(self):
        module.drill_once(self.db, self.archive, "valid")
        ledger = self.archive / "drill-ledger.jsonl"
        item = json.loads(ledger.read_text())
        item["backup_sha256"] = "0" * 64
        ledger.write_text(json.dumps(item) + "\n")
        with self.assertRaisesRegex(ValueError, "invalid_drill_chain"):
            module.verify_archives(self.archive)

    def test_archive_name_is_nonoverwriting_and_unique(self):
        module.drill_once(self.db, self.archive, "once")
        with self.assertRaisesRegex(ValueError, "archive_already_exists"):
            module.drill_once(self.db, self.archive, "once")
        self.assertEqual(module.verify_archives(self.archive)["checked"], 1)

    def test_external_symlink_and_hardlink_source_rejected(self):
        external = self.root / "external-link.sqlite"
        external.symlink_to(self.db)
        with self.assertRaises(ValueError):
            module.drill_once(external, self.archive, "escaped")
        link = self.root / "hardlink.sqlite"
        os.link(str(self.db), str(link))
        with self.assertRaises(ValueError):
            module.drill_once(self.db, self.archive, "linked")

    def test_archive_directory_requires_private_permissions(self):
        if os.name == "nt":
            privacy_fixtures.set_public_read_acl(self.archive)
        else:
            self.archive.chmod(0o755)
        with self.assertRaises(ValueError):
            module.drill_once(self.db, self.archive, "unsafe-dir")

    def test_malformed_identifiers_cannot_plant_arbitrary_files(self):
        for unsafe in ("../outside", "/tmp", "bad.name", "", "a" * 100):
            with self.subTest(name=unsafe):
                with self.assertRaises(ValueError):
                    module.drill_once(self.db, self.archive, unsafe)
        self.assertFalse((self.root / "outside").exists())

    def test_repeated_watcher_invalid_bounds_fail_closed(self):
        for cycles, interval in ((0, 10), (11, 10), (2, 0), (1, 60001)):
            with self.assertRaises(ValueError):
                module.scheduled_drills(self.db, self.archive, cycles=cycles,
                                        interval_ms=interval)

    def test_cli_offline_watch_multiple_real_time_cycles(self):
        result = subprocess.run([
            sys.executable, "-I", "-S", "-B", str(ROOT / "python" / "backup_drill.py"),
            "--database", str(self.db), "--archive-dir", str(self.archive),
            "--action", "watch", "--id", "cli", "--cycles", "2", "--interval-ms", "7",
        ], capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[-300:])
        report = json.loads(result.stdout)
        self.assertEqual(report["cycles"], 2)
        self.assertTrue(report["all_restores_verified"])

    def test_no_source_code_execution_or_release_authority_claim(self):
        result = module.drill_once(self.db, self.archive, "read")
        self.assertFalse(result["source_executed"])
        self.assertFalse(result["external_attestation"])
        self.assertEqual(result["sequence"], 1)


if __name__ == "__main__":
    unittest.main()
