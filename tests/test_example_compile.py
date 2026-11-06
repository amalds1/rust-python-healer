"""Offline compile-only authorization, integrity, safety and version checks."""

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if os.name == "nt":
    from windows_privacy_fixtures import set_private_acl, set_public_read_acl


def trust_permissions(path, private=True):
    if os.name == "nt":
        (set_private_acl if private else set_public_read_acl)(path)
    else:
        os.chmod(path, 0o600 if private else 0o644)


spec = spec_from_file_location("example_compile", ROOT / "python" / "example_compile.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


class OfflineExampleCompileTests(unittest.TestCase):
    def test_private_reader_rechecks_hardlink_and_acl_changes_on_open_handle(self):
        original_fdopen = module.os.fdopen
        for mutation in ("hardlink", "public_acl"):
            with self.subTest(mutation=mutation):
                self.write_trust()
                alias = self.root / "trust-alias.json"
                class Stream:
                    def __init__(inner, descriptor, mode):
                        inner.actual = original_fdopen(descriptor, mode)
                    def __enter__(inner): return inner
                    def __exit__(inner, *args): inner.actual.close()
                    def fileno(inner): return inner.actual.fileno()
                    def read(inner, maximum):
                        if mutation == "hardlink": os.link(self.trust_path, alias)
                        else: trust_permissions(self.trust_path, private=False)
                        return inner.actual.read(maximum)
                try:
                    with mock.patch.object(module.os, "fdopen", side_effect=Stream):
                        with self.assertRaises(ValueError):
                            module.read_bounded(self.trust_path, 4096, private=True)
                finally:
                    if alias.exists(): alias.unlink()
                    trust_permissions(self.trust_path)

    def test_private_reader_closes_actual_descriptor_if_fdopen_fails(self):
        descriptors = []
        def refuse(descriptor, mode):
            descriptors.append(descriptor)
            raise OSError("fixed fdopen failure")
        with mock.patch.object(module.os, "fdopen", side_effect=refuse):
            with self.assertRaisesRegex(OSError, "fixed fdopen failure"):
                module.read_bounded(self.trust_path, 4096, private=True)
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])
        self.trust_path.unlink()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.blobs = self.root / "blobs"
        self.blobs.mkdir()
        self.trust_path = self.root / "trust.json"
        self.manifest_path = self.root / "manifest.json"
        self.python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
        self.trust = {
            "schema_version": 1, "source_id": "trusted-publisher",
            "hostname": "docs.python.org", "licenses": ["PSF-2.0"],
            "key_hex": "a9" * 32,
        }
        self.manifest = {
            "schema_version": 1, "manifest_id": "trusted-fixture-v1",
            "source_id": "trusted-publisher", "examples": [],
            "signature": "0" * 64,
        }
        self.write_trust()

    def write_trust(self):
        self.trust_path.write_text(json.dumps(self.trust), encoding="utf-8")
        trust_permissions(self.trust_path)

    def add_example(self, example_id="fixture", source=b"x = 7\n",
                    version=None, expected="COMPILES", uri=None):
        name = "item_" + example_id + ".py"
        (self.blobs / name).write_bytes(source)
        record = {
            "id": example_id, "blob": name,
            "sha256": hashlib.sha256(source).hexdigest(),
            "python_version": version or self.python_version,
            "uri": uri or "https://docs.python.org/3/library/ast.html",
            "license": "PSF-2.0", "ingest_authorized": True,
            "expected_compile": expected,
        }
        self.manifest["examples"].append(record)
        return record

    def sign(self):
        self.manifest["signature"] = module.sign_manifest_for_test(
            self.manifest, self.trust["key_hex"])
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def evaluate(self):
        return module.evaluate_manifest(self.manifest_path, self.blobs,
                                        self.trust_path, sys.executable)

    def test_positive_and_negative_compilation_both_are_compile_only_partial(self):
        self.add_example("valid", b"def f(a: int) -> int:\n    return a + 1\n")
        self.add_example("syntax", b"def f(: pass\n", expected="SYNTAX_ERROR")
        self.sign()
        result = self.evaluate()
        self.assertEqual(result["status"], "PARTIAL_COMPILE_ONLY")
        self.assertEqual(result["passed_expectations"], 2)
        self.assertEqual(result["examples_checked"], 2)
        self.assertEqual({item["observed_compile"] for item in result["results"]},
                         {"COMPILES", "SYNTAX_ERROR"})
        self.assertTrue(result["operator_manifest_hmac_verified"])
        for field in ("source_executed", "example_tests_executed", "network_used",
                      "publisher_authenticated", "legal_permission_independently_verified"):
            self.assertFalse(result[field], field)
        self.assertNotIn("return a + 1", json.dumps(result))

    def test_never_executes_unknown_source_or_imports_module(self):
        marker = self.root / "THIS_MUST_NOT_BE_CREATED"
        source = (f"from pathlib import Path\nPath({str(marker)!r}).write_text('unsafe')\n"
                  "raise RuntimeError('THIS_IS_SECRET')\n").encode()
        self.add_example(source=source)
        self.sign()
        result = self.evaluate()
        self.assertEqual(result["results"][0]["observed_compile"], "COMPILES")
        self.assertFalse(marker.exists())
        self.assertNotIn("THIS_IS_SECRET", json.dumps(result))
        self.assertFalse(result["source_executed"])

    def test_except_star_is_version_sensitive_per_selected_interpreter(self):
        expected = "COMPILES" if sys.version_info >= (3, 11) else "SYNTAX_ERROR"
        self.add_example(source=b"try:\n    pass\nexcept* ValueError:\n    pass\n",
                         expected=expected)
        self.sign()
        self.assertEqual(self.evaluate()["passed_expectations"], 1)

    def test_invalid_expected_result_is_failure_not_fabricated_success(self):
        self.add_example(source=b"def bad(:\n", expected="COMPILES")
        self.sign()
        report = self.evaluate()
        self.assertEqual(report["status"], "FAILED")
        self.assertEqual(report["failed_expectations"], 1)

    def test_mismatched_compiler_version_fails_closed(self):
        other = "3.10" if self.python_version != "3.10" else "3.11"
        self.add_example(version=other)
        self.sign()
        with self.assertRaisesRegex(ValueError, "interpreter_python_version_mismatch"):
            self.evaluate()

    def test_tampered_manifest_or_policy_is_rejected_before_compilation(self):
        row = self.add_example()
        self.sign()
        row["expected_compile"] = "SYNTAX_ERROR"
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "example_manifest_hmac_invalid"):
            self.evaluate()
        row["expected_compile"] = "COMPILES"
        self.sign()
        self.trust["key_hex"] = "ee" * 32
        self.write_trust()
        with self.assertRaisesRegex(ValueError, "example_manifest_hmac_invalid"):
            self.evaluate()

    def test_modified_blob_after_authorization_refused_by_sha256(self):
        self.add_example()
        self.sign()
        (self.blobs / "item_fixture.py").write_bytes(b"x = 8\n")
        with self.assertRaisesRegex(ValueError, "example_sha256_mismatch"):
            self.evaluate()

    def test_refuse_invalid_utf8_nul_and_oversized_example(self):
        for raw, reason in ((b"\xff\xfe", "blob_invalid_utf8"),
                            (b"x = 7\x00", "blob_contains_nul"),
                            (b"#" * (module.MAX_BLOB_BYTES + 1),
                             "blob_not_unique_regular_bounded_file")):
            with self.subTest(reason=reason):
                self.manifest["examples"] = []
                self.add_example(source=raw)
                self.sign()
                with self.assertRaisesRegex(ValueError, reason):
                    self.evaluate()

    def test_paths_refuse_traversal_and_symlink_and_hardlink(self):
        row = self.add_example()
        for unsafe in ("../outside.py", "/tmp/outside.py", "sub/../../bad.py",
                       "sub\\bad.py", "./bad.py", "bad.txt"):
            with self.subTest(unsafe=unsafe):
                row["blob"] = unsafe
                self.sign()
                with self.assertRaisesRegex(ValueError, "unsafe_blob_path"):
                    self.evaluate()
        row["blob"] = "linked.py"
        (self.blobs / "linked.py").symlink_to(self.blobs / "item_fixture.py")
        self.sign()
        with self.assertRaisesRegex(ValueError, "blob_unreadable_or_symlink"):
            self.evaluate()
        (self.blobs / "linked.py").unlink()
        os.link(self.blobs / "item_fixture.py", self.blobs / "linked.py")
        self.sign()
        with self.assertRaisesRegex(ValueError, "blob_not_unique_regular_bounded_file"):
            self.evaluate()

    def test_nested_directory_symlink_and_root_symlink_refused(self):
        row = self.add_example()
        row["blob"] = "alias/inner.py"
        (self.blobs / "alias").symlink_to(self.blobs, target_is_directory=True)
        self.sign()
        with self.assertRaisesRegex(ValueError, "blob_unreadable_or_symlink"):
            self.evaluate()
        row["blob"] = "item_fixture.py"
        self.sign()
        alias = self.root / "root_alias"
        alias.symlink_to(self.blobs, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "blob_root_symlink_refused"):
            module.evaluate_manifest(self.manifest_path, alias, self.trust_path)

    def test_trust_file_must_be_owner_only_and_unique(self):
        self.add_example()
        self.sign()
        trust_permissions(self.trust_path, False)
        with self.assertRaisesRegex(ValueError, "invalid_or_unreadable"):
            self.evaluate()
        trust_permissions(self.trust_path)
        alias = self.root / "trust_alias.json"
        os.link(self.trust_path, alias)
        with self.assertRaisesRegex(ValueError, "invalid_or_unreadable"):
            self.evaluate()

    def test_provenance_and_license_require_authorization_even_if_signed(self):
        row = self.add_example()
        for uri in ("http://docs.python.org/a", "https://evil.example.com/a",
                    "https://user:pw@docs.python.org/a",
                    "https://docs.python.org/a?secret=1",
                    "https://docs.python.org/a#frag"):
            with self.subTest(uri=uri):
                row["uri"] = uri
                self.sign()
                with self.assertRaisesRegex(ValueError, "example_provenance_host_not_authorized"):
                    self.evaluate()
        row["uri"] = "https://docs.python.org/a"
        for name, value, reason in (("license", "not-approved", "example_license_not_authorized"),
                                    ("ingest_authorized", False, "example_ingestion_not_authorized")):
            with self.subTest(name=name):
                original = row[name]
                row[name] = value
                self.sign()
                with self.assertRaisesRegex(ValueError, reason):
                    self.evaluate()
                row[name] = original

    def test_duplicate_ids_and_json_duplicate_keys_refused(self):
        row = self.add_example()
        second = copy.deepcopy(row)
        second["blob"] = "second.py"
        (self.blobs / "second.py").write_text("x = 7\n", encoding="utf-8")
        self.manifest["examples"].append(second)
        self.sign()
        with self.assertRaisesRegex(ValueError, "duplicate_example_id_or_blob"):
            self.evaluate()
        self.manifest["examples"] = [row]
        self.sign()
        raw = self.manifest_path.read_text(encoding="utf-8")
        self.manifest_path.write_text(raw.replace('"schema_version": 1,',
                                                   '"schema_version": 1, "schema_version": 1,'),
                                      encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalid_or_unreadable"):
            self.evaluate()

    def test_nonstandard_schema_and_wrong_expectations_are_rejected(self):
        row = self.add_example()
        for field, bad in (("python_version", "3.8"),
                           ("python_version", "3.10.*"),
                           ("expected_compile", "EXECUTE")):
            with self.subTest(field=field, bad=bad):
                original = row[field]
                row[field] = bad
                self.sign()
                with self.assertRaises(ValueError):
                    self.evaluate()
                row[field] = original
        self.manifest["schema_version"] = 2
        self.sign()
        with self.assertRaisesRegex(ValueError, "invalid_example_manifest"):
            self.evaluate()

    def test_cli_outputs_private_safe_structured_evidence(self):
        self.add_example(source=b"token = 'SECRET_NOT_IN_STDOUT'\n")
        self.sign()
        result = subprocess.run(
            [sys.executable, "-I", "-S", str(ROOT / "python" / "example_compile.py"),
             str(self.manifest_path), str(self.blobs), str(self.trust_path)],
            capture_output=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "PARTIAL_COMPILE_ONLY")
        self.assertNotIn(b"SECRET_NOT_IN_STDOUT", result.stdout)

    def test_missing_compiler_is_controlled_error_not_success(self):
        self.add_example()
        self.sign()
        with self.assertRaisesRegex(ValueError, "trusted_compiler_unavailable_or_timed_out"):
            module.evaluate_manifest(self.manifest_path, self.blobs, self.trust_path,
                                     self.root / "nonexistent-cpython")


if __name__ == "__main__":
    unittest.main()
