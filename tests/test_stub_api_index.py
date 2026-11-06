"""Authenticated offline .pyi AST signatures and rename-correlation evidence."""

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from python import example_compile as signer
from python import stub_api_index as module

if os.name == "nt":
    from windows_privacy_fixtures import set_private_acl, set_public_read_acl

BEFORE = b'''from typing import overload
@overload
def old(value: int, /, *, secret: str = "PRIVATE_DEFAULT") -> str: ...
@overload
def old(value: str) -> str: ...
def old(value): ...
class Client:
    @classmethod
    def from_uri(cls, uri: str) -> "Client": ...
    @property
    def enabled(self) -> bool: ...
if sys.version_info >= (3, 11):
    def conditional_feature(): ...
'''
AFTER = b'''from typing import overload
@overload
def new(value: int, /) -> str: ...
@overload
def new(value: str) -> str: ...
def new(value): ...
class Client:
    async def fetch(self, key: str) -> str: ...
'''


class AuthenticatedStubIndexTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        if os.name == "nt":
            set_private_acl(self.folder)
        self.stubs_dir = self.folder / "stubs"
        self.stubs_dir.mkdir()
        self.trust_path = self.folder / "trust.json"
        self.manifest_path = self.folder / "manifest.json"
        self.trust = {
            "schema_version": 1, "source_id": "authorized-stubs",
            "hostname": "example.org", "licenses": ["MIT"],
            "key_hex": "ba" * 32,
        }
        self.manifest = {
            "schema_version": 1, "manifest_id": "authorized-stubs-v1",
            "source_id": "authorized-stubs", "stubs": [], "renames": [],
            "signature": "0" * 64,
        }
        self.trust_path.write_text(json.dumps(self.trust), encoding="utf-8")
        if os.name == "nt":
            set_private_acl(self.trust_path)
        else:
            os.chmod(self.trust_path, 0o600)

    def add_stub(self, identity="before", source=BEFORE, version="3.9",
                 package_version="1.0", module_name="example.api"):
        filename = identity + ".pyi"
        (self.stubs_dir / filename).write_bytes(source)
        row = {
            "id": identity, "blob": filename, "module": module_name,
            "python_version": version, "package_version": package_version,
            "uri": "https://example.org/stubs/" + filename,
            "license": "MIT", "sha256": hashlib.sha256(source).hexdigest(),
            "ingest_authorized": True,
        }
        self.manifest["stubs"].append(row)
        return row

    def add_rename(self):
        rename = {"module": "example.api", "old_name": "old", "new_name": "new",
                  "before_python": "3.9", "after_python": "3.10",
                  "package_version_before": "1.0", "package_version_after": "2.0"}
        self.manifest["renames"].append(rename)
        return rename

    def sign(self):
        self.manifest["signature"] = signer.sign_manifest_for_test(
            self.manifest, self.trust["key_hex"])
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def evaluate(self):
        return module.inspect_manifest(self.manifest_path, self.stubs_dir,
                                       self.trust_path)

    def test_public_trust_file_denied_before_stub_parse_and_in_cli(self):
        self.add_stub(); self.sign()
        if os.name == "nt":
            set_public_read_acl(self.trust_path)
        else:
            self.trust_path.chmod(0o644)
        with mock.patch.object(module, "index_stub", side_effect=AssertionError("must not parse")):
            with self.assertRaisesRegex(ValueError, "invalid_or_unreadable"):
                self.evaluate()
        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(Path(module.__file__)),
             str(self.manifest_path), str(self.stubs_dir), str(self.trust_path)],
            capture_output=True, timeout=10, check=False)
        self.assertEqual(completed.returncode, 1)
        result = json.loads(completed.stdout)
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertFalse(result["source_executed"])
        self.assertFalse(result["network_used"])
        self.assertNotIn(self.trust["key_hex"], completed.stdout.decode())

    def test_hardlinked_private_trust_file_denied_before_stub_parse(self):
        self.add_stub(); self.sign()
        os.link(self.trust_path, self.folder / "trust-alias.json")
        with mock.patch.object(module, "index_stub", side_effect=AssertionError("must not parse")):
            with self.assertRaisesRegex(ValueError, "invalid_or_unreadable"):
                self.evaluate()

    def test_stub_directory_symlink_denied_before_stub_parse(self):
        row = self.add_stub(); row["blob"] = "alias/before.pyi"; self.sign()
        alias = self.stubs_dir / "alias"
        alias.symlink_to(self.stubs_dir, target_is_directory=True)
        try:
            with mock.patch.object(module, "index_stub", side_effect=AssertionError("must not parse")):
                with self.assertRaises(ValueError):
                    self.evaluate()
        finally:
            alias.unlink()

    def test_signed_versioned_snapshots_overloads_and_rename_correlation(self):
        self.add_stub()
        self.add_stub("after", AFTER, "3.10", "2.0")
        self.add_rename()
        self.sign()
        result = self.evaluate()
        self.assertEqual(result["status"], "PARTIAL_STATIC_STUB_EVIDENCE")
        self.assertEqual(result["stub_snapshots_indexed"], 2)
        self.assertEqual(result["rename_candidates_correlated"], 1)
        self.assertEqual(result["snapshots"][0]["overload_sets"], {"old": 2})
        self.assertEqual(result["snapshots"][1]["overload_sets"], {"new": 2})
        self.assertEqual(result["rename_correlations"][0]["status"],
                         "CORRELATED_NAMES_SEMANTICS_UNVERIFIED")
        self.assertFalse(result["rename_semantics_verified"])
        self.assertFalse(result["package_runtime_api_verified"])
        self.assertFalse(result["publisher_authenticated"])
        self.assertFalse(result["source_executed"])
        self.assertFalse(result["network_used"])

    def test_posonly_kwonly_defaults_and_literal_redaction(self):
        self.add_stub()
        self.sign()
        indexed = self.evaluate()["snapshots"][0]
        signatures = [item["signature"] for item in indexed["symbols"]
                      if item["name"] == "old"]
        self.assertIn("(value: int, /, *, secret: str = ...) -> str", signatures)
        self.assertNotIn("PRIVATE_DEFAULT", json.dumps(indexed))
        self.assertIn("Client", {item["name"] for item in indexed["symbols"]})
        methods = {item["name"]: item for item in indexed["symbols"]}
        self.assertTrue(methods["Client.from_uri"]["classmethod"])
        self.assertTrue(methods["Client.enabled"]["property"])
        self.assertEqual(indexed["conditional_blocks_ignored"], 1)
        self.assertNotIn("conditional_feature", methods)

    def test_async_function_and_union_annotations_are_static_only(self):
        raw = (b"async def run(item: int | str, /, **kw: bool) -> None: ...\n"
               b"def other(x: list[str]) -> tuple[int, str]: ...\n")
        self.add_stub(source=raw)
        self.sign()
        indexed = self.evaluate()["snapshots"][0]
        entry = indexed["symbols"][0]
        self.assertEqual(entry["kind"], "async_function")
        self.assertEqual(entry["signature"],
                         "(item: int | str, /, **kw: bool) -> None")
        self.assertEqual(indexed["symbols"][1]["signature"],
                         "(x: list[str]) -> tuple[int, str]")

    def test_untrusted_source_expression_never_executes(self):
        marker = self.folder / "must-not-exist"
        raw = (f"from pathlib import Path\n"
               f"Path({str(marker)!r}).write_text('unsafe')\n"
               "def safe() -> int: ...\n").encode()
        self.add_stub(source=raw)
        self.sign()
        result = self.evaluate()
        self.assertFalse(marker.exists())
        self.assertFalse(result["source_executed"])
        self.assertEqual(result["snapshots"][0]["symbols"][0]["name"], "safe")

    def test_manifest_hmac_tampering_denied(self):
        self.add_stub()
        self.sign()
        self.manifest["stubs"][0]["python_version"] = "3.15"
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "stub_manifest_hmac_invalid"):
            self.evaluate()

    def test_blob_sha256_mismatch_denied(self):
        self.add_stub()
        self.sign()
        (self.stubs_dir / "before.pyi").write_bytes(AFTER)
        with self.assertRaisesRegex(ValueError, "stub_sha256_mismatch"):
            self.evaluate()

    def test_unsafe_paths_symlinks_and_hardlinks_denied(self):
        row = self.add_stub()
        for unsafe in ("../secret.pyi", "./secret.pyi", "/tmp/secret.pyi",
                       "folder\\secret.pyi", "secret.py"):
            with self.subTest(unsafe=unsafe):
                row["blob"] = unsafe
                self.sign()
                with self.assertRaisesRegex(ValueError, "unsafe_blob_path"):
                    self.evaluate()
        row["blob"] = "alias.pyi"
        (self.stubs_dir / "alias.pyi").symlink_to(self.stubs_dir / "before.pyi")
        self.sign()
        with self.assertRaisesRegex(ValueError, "blob_unreadable_or_symlink"):
            self.evaluate()
        (self.stubs_dir / "alias.pyi").unlink()
        os.link(self.stubs_dir / "before.pyi", self.stubs_dir / "alias.pyi")
        self.sign()
        with self.assertRaisesRegex(ValueError, "blob_not_unique_regular_bounded_file"):
            self.evaluate()

    def test_denies_invalid_utf8_nul_and_invalid_syntax(self):
        for raw, reason in ((b"\xff\xfe", "blob_invalid_utf8"),
                            (b"def a():\x00 pass", "blob_contains_nul"),
                            (b"def broken(: pass", "stub_syntax_invalid_or_unsupported")):
            with self.subTest(reason=reason):
                self.manifest["stubs"] = []
                self.add_stub(source=raw)
                self.sign()
                with self.assertRaisesRegex(ValueError, reason):
                    self.evaluate()

    def test_rename_claim_requires_both_older_and_newer_snapshots(self):
        self.add_stub()
        self.add_rename()
        self.sign()
        with self.assertRaisesRegex(ValueError, "rename_missing_versioned_stub_evidence"):
            self.evaluate()
        self.add_stub("after", b"def other(): ...\n", "3.10", "2.0")
        self.sign()
        with self.assertRaisesRegex(ValueError, "rename_presence_or_removal_not_observed"):
            self.evaluate()

    def test_rename_claim_rejected_if_old_still_exists_after(self):
        self.add_stub()
        self.add_stub("after", AFTER + b"def old(): ...\n", "3.10", "2.0")
        self.add_rename()
        self.sign()
        with self.assertRaisesRegex(ValueError, "rename_presence_or_removal_not_observed"):
            self.evaluate()

    def test_rename_version_must_increase_and_names_must_change(self):
        self.add_stub()
        rename = self.add_rename()
        rename["after_python"] = "3.9"
        self.sign()
        with self.assertRaisesRegex(ValueError, "rename_versions_not_monotonic"):
            self.evaluate()
        rename["after_python"] = "3.10"
        rename["new_name"] = rename["old_name"]
        self.sign()
        with self.assertRaisesRegex(ValueError, "rename_must_change_name"):
            self.evaluate()

    def test_duplicate_stub_and_duplicate_manifest_keys_denied(self):
        row = self.add_stub()
        repeat = copy.deepcopy(row)
        repeat["id"] = "repeat"
        self.manifest["stubs"].append(repeat)
        self.sign()
        with self.assertRaisesRegex(ValueError, "duplicate_stub_snapshot"):
            self.evaluate()
        self.manifest["stubs"] = [row]
        self.sign()
        raw = self.manifest_path.read_text(encoding="utf-8")
        self.manifest_path.write_text(raw.replace('"schema_version": 1,',
                                                   '"schema_version": 1, "schema_version": 1,'),
                                      encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalid_or_unreadable"):
            self.evaluate()

    def test_license_authorization_and_uri_rejected(self):
        row = self.add_stub()
        for field, bad, reason in (
                ("license", "private", "stub_license_not_authorized"),
                ("ingest_authorized", False, "stub_ingestion_not_authorized"),
                ("uri", "https://other.org/stub.pyi", "stub_provenance_host_not_authorized"),
                ("uri", "https://example.org/stub.pyi?token=secret",
                 "stub_provenance_host_not_authorized")):
            with self.subTest(field=field):
                original = row[field]
                row[field] = bad
                self.sign()
                with self.assertRaisesRegex(ValueError, reason):
                    self.evaluate()
                row[field] = original

    def test_stub_syntax_is_parsed_by_real_local_version(self):
        self.add_stub(source=b"class Box[T]: ...\n")
        self.sign()
        if sys.version_info < (3, 12):
            with self.assertRaisesRegex(ValueError, "stub_syntax_invalid_or_unsupported"):
                self.evaluate()
        else:
            self.assertEqual(self.evaluate()["snapshots"][0]["symbols"][0]["name"],
                             "Box")

    def test_cli_reports_no_source_execution(self):
        self.add_stub()
        self.sign()
        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(Path(module.__file__)),
             str(self.manifest_path), str(self.stubs_dir), str(self.trust_path)],
            capture_output=True, timeout=10, check=False)
        self.assertEqual(completed.returncode, 0,
                         completed.stderr.decode("utf-8", "replace"))
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "PARTIAL_STATIC_STUB_EVIDENCE")
        self.assertFalse(report["source_executed"])


if __name__ == "__main__":
    unittest.main()
