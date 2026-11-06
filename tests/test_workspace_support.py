"""F234/F249 agent source snapshots and consent-gated redacted support bundles."""

from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("workspace_support", ROOT / "python" / "workspace_support.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


def source(folder, name="main.py", text="def safe():\n    return 2\n"):
    path = Path(folder) / name
    path.write_text(text, encoding="utf-8")
    return path


class WorkspaceTests(unittest.TestCase):
    def test_snapshot_preserves_full_two_megabyte_source_budget(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "bounded.py"
            raw = b"#" * module.MAX_SOURCE_FILE
            path.write_bytes(raw)
            session = module.create_agent_workspaces([path], ["agent"], root)
            self.assertEqual(session.snapshot_path("agent", "bounded.py").read_bytes(), raw)
            self.assertEqual(session.verify()["status"], "SNAPSHOTS_MATCH_BASELINE")

    def test_source_leaf_alias_race_is_refused_before_copy(self):
        with tempfile.TemporaryDirectory() as root:
            path = source(root); backing = Path(root) / "backing.py"
            if os.name == "nt":
                boundary = module._windows_security(); original_open = boundary._open
                def swapped_windows(*args, **kwargs):
                    path.rename(backing); path.symlink_to(backing)
                    return original_open(*args, **kwargs)
                with mock.patch.object(boundary, "_open", side_effect=swapped_windows):
                    with self.assertRaises(module.SnapshotError):
                        module.create_agent_workspaces([path], ["agent"], root)
            else:
                original_open = module.os.open
                def swapped_posix(*args, **kwargs):
                    path.rename(backing); path.symlink_to(backing)
                    return original_open(*args, **kwargs)
                with mock.patch.object(module.os, "open", side_effect=swapped_posix):
                    with self.assertRaises(module.SnapshotError):
                        module.create_agent_workspaces([path], ["agent"], root)
            self.assertFalse(any(Path(root).glob("rph-agent-work-*")))

    def test_agent_workspaces_have_distinct_readonly_copies(self):
        with tempfile.TemporaryDirectory() as root:
            path = source(root)
            session = module.create_agent_workspaces([path], ["agent_a", "agent_b"], root)
            one = session.snapshot_path("agent_a", "main.py")
            two = session.snapshot_path("agent_b", "main.py")
            self.assertEqual(one.read_bytes(), two.read_bytes())
            self.assertNotEqual((one.stat().st_dev, one.stat().st_ino),
                                (two.stat().st_dev, two.stat().st_ino))
            self.assertFalse(one.stat().st_mode & 0o222)
            self.assertNotEqual(session.work_path("agent_a"), session.work_path("agent_b"))
            result = session.verify()
            self.assertEqual(result["status"], "SNAPSHOTS_MATCH_BASELINE")
            self.assertFalse(result["user_code_executed"])
            self.assertFalse(result["os_sandbox_enforced"])

    def test_snapshot_is_independent_of_original_source_changes(self):
        with tempfile.TemporaryDirectory() as root:
            path = source(root)
            session = module.create_agent_workspaces([path], ["agent"], root)
            previous = session.snapshot_path("agent", "main.py").read_bytes()
            path.write_text("print('modified')\n")
            self.assertEqual(session.snapshot_path("agent", "main.py").read_bytes(), previous)
            self.assertEqual(session.verify()["status"], "SNAPSHOTS_MATCH_BASELINE")

    def test_tampered_snapshot_detected_even_after_restoring_readonly_mode(self):
        with tempfile.TemporaryDirectory() as root:
            path = source(root)
            session = module.create_agent_workspaces([path], ["agent"], root)
            snapshot = session.snapshot_path("agent", "main.py")
            snapshot.chmod(0o600)
            snapshot.write_text("SECRET_TAMPER_4721")
            snapshot.chmod(0o400)
            result = session.verify()
            self.assertEqual(result["reason"], "snapshot_sha256_mismatch")
            self.assertNotIn("SECRET", json.dumps(result))

    def test_snapshot_file_permission_tamper_detected(self):
        with tempfile.TemporaryDirectory() as root:
            session = module.create_agent_workspaces([source(root)], ["agent"], root)
            session.snapshot_path("agent", "main.py").chmod(0o600)
            self.assertEqual(session.verify()["reason"], "snapshot_not_readonly")

    def test_extra_snapshot_file_and_missing_agent_refused(self):
        with tempfile.TemporaryDirectory() as root:
            session = module.create_agent_workspaces([source(root)], ["alice"], root)
            with self.assertRaises(module.SnapshotError):
                session.snapshot_path("bob", "main.py")
            snapshot_directory = session.root / "alice" / "snapshot"
            snapshot_directory.chmod(0o700)
            (snapshot_directory / "injected.py").write_text("return secret\n")
            self.assertEqual(session.verify()["reason"], "snapshot_file_inventory_changed")

    def test_symlink_snapshot_rejected_without_following(self):
        with tempfile.TemporaryDirectory() as root:
            session = module.create_agent_workspaces([source(root)], ["alice"], root)
            snapshot_directory = session.root / "alice" / "snapshot"
            snapshot_directory.chmod(0o700)
            original = snapshot_directory / "main.py"
            original.chmod(0o600)  # Remove own fixture's Windows readonly flag.
            original.unlink()
            original.symlink_to(Path(root) / "main.py")
            self.assertEqual(session.verify()["reason"], "snapshot_not_readonly")

    def test_input_symlink_and_hardlink_refused(self):
        with tempfile.TemporaryDirectory() as root:
            original = source(root)
            symlink = Path(root) / "sym.py"
            symlink.symlink_to(original)
            with self.assertRaisesRegex(module.SnapshotError, "source_not_private_regular_file"):
                module.create_agent_workspaces([symlink], ["agent"], root)
            hardlink = Path(root) / "hard.py"
            os.link(original, hardlink)
            with self.assertRaisesRegex(module.SnapshotError, "source_not_private_regular_file"):
                module.create_agent_workspaces([original], ["agent"], root)

    def test_input_duplicate_basename_and_agent_id_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = source(root)
            with self.assertRaisesRegex(module.SnapshotError, "invalid_or_duplicate_source_basename"):
                module.create_agent_workspaces([path, path], ["agent"], root)
            with self.assertRaisesRegex(module.SnapshotError, "invalid_agent_list"):
                module.create_agent_workspaces([path], ["agent", "agent"], root)
            with self.assertRaisesRegex(module.SnapshotError, "invalid_agent_list"):
                module.create_agent_workspaces([path], ["../../bad"], root)

    def test_bounded_agent_and_source_count(self):
        with tempfile.TemporaryDirectory() as root:
            path = source(root)
            bad_names = ["agent{}".format(index) for index in range(module.MAX_AGENTS + 1)]
            with self.assertRaisesRegex(module.SnapshotError, "invalid_agent_list"):
                module.create_agent_workspaces([path], bad_names, root)
            bad_files = [path] * (module.MAX_SOURCE_FILES + 1)
            with self.assertRaisesRegex(module.SnapshotError, "invalid_source_list"):
                module.create_agent_workspaces(bad_files, ["agent"], root)

    def test_oversized_source_refused_before_copies(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "large.py"
            with path.open("wb") as output:
                output.truncate(module.MAX_SOURCE_FILE + 1)
            with self.assertRaisesRegex(module.SnapshotError, "source_limit_exceeded"):
                module.create_agent_workspaces([path], ["agent"], root)


class SupportBundleTests(unittest.TestCase):
    def example(self):
        return [{"code": "F202", "level": "WARN", "count": 2,
                 "python_version": "3.15", "token": "PRIVATE_TOKEN_987654",
                 "absolute_path": "/private/user/secrets.py",
                 "raw_source": "API_KEY=SUPER_PRIVATE"}]

    def test_no_opt_in_means_no_file(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "support.zip"
            result = module.build_support_bundle(self.example(), target)
            self.assertEqual(result["status"], "CONSENT_REQUIRED_NO_FILE_WRITTEN")
            self.assertFalse(target.exists())
            self.assertFalse(result["network_used"])
            self.assertFalse(result["telemetry_uploaded"])

    def test_opt_in_local_bundle_contains_only_allowlisted_metrics(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "support.zip"
            result = module.build_support_bundle(self.example(), target, opt_in=True)
            self.assertEqual(result["status"], "OFFLINE_SUPPORT_BUNDLE_CREATED")
            self.assertEqual(result["discarded_fields"], 3)
            raw = target.read_bytes()
            for private in (b"PRIVATE_TOKEN", b"/private/user", b"API_KEY", b"SUPER_PRIVATE"):
                self.assertNotIn(private, raw)
            with zipfile.ZipFile(target) as archive:
                self.assertEqual(set(archive.namelist()), {"summary.json", "NOTICE.txt"})
                document = json.loads(archive.read("summary.json"))
                self.assertEqual(document["events"], [{"code": "F202", "level": "WARN",
                                                       "count": 2, "python_version": "3.15"}])
                self.assertFalse(document["telemetry_uploaded"])

    def test_identical_input_creates_identical_deterministic_bundle_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            a = Path(root) / "one.zip"
            b = Path(root) / "two.zip"
            first = module.build_support_bundle(self.example(), a, opt_in=True)
            second = module.build_support_bundle(self.example(), b, opt_in=True)
            self.assertEqual(a.read_bytes(), b.read_bytes())
            self.assertEqual(first["sha256"], second["sha256"])

    def test_bad_event_code_level_version_and_count_never_written(self):
        with tempfile.TemporaryDirectory() as root:
            bad_values = (
                {"code": "SECRET_KEY", "level": "INFO", "count": 1},
                {"code": "F202", "level": "PRIVATE", "count": 1},
                {"code": "F202", "level": "INFO", "count": -1},
                {"code": "F202", "level": "INFO", "count": True},
                {"code": "F202", "level": "INFO", "python_version": "3.999"},
            )
            for i, event in enumerate(bad_values):
                target = Path(root) / "bad{}.zip".format(i)
                self.assertEqual(module.build_support_bundle([event], target, True)["status"],
                                 "NOT_WRITTEN_INVALID_INPUT")
                self.assertFalse(target.exists())

    def test_existing_target_and_symlink_never_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "existing.zip"
            target.write_bytes(b"OWNER_PRIVATE_DATA")
            self.assertEqual(module.build_support_bundle(self.example(), target, True)["status"],
                             "NOT_WRITTEN_INVALID_INPUT")
            self.assertEqual(target.read_bytes(), b"OWNER_PRIVATE_DATA")
            link = Path(root) / "linked.zip"
            link.symlink_to(target)
            self.assertEqual(module.build_support_bundle(self.example(), link, True)["status"],
                             "NOT_WRITTEN_INVALID_INPUT")
            self.assertEqual(target.read_bytes(), b"OWNER_PRIVATE_DATA")

    def test_support_bundle_event_quota(self):
        with tempfile.TemporaryDirectory() as root:
            events = [{"code": "TEST_PASS", "level": "INFO"}] * (module.MAX_EVENTS + 1)
            target = Path(root) / "support.zip"
            result = module.build_support_bundle(events, target, True)
            self.assertEqual(result["status"], "NOT_WRITTEN_INVALID_INPUT")
            self.assertFalse(target.exists())

    def test_empty_opted_in_bundle_reports_no_telemetry(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "nothing.zip"
            result = module.build_support_bundle([], target, True)
            self.assertEqual(result["status"], "OFFLINE_SUPPORT_BUNDLE_CREATED")
            self.assertEqual(result["event_count"], 0)
            self.assertFalse(result["credentials_included"])


if __name__ == "__main__":
    unittest.main()
