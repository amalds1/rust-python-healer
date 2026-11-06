"""F098/F202 no-execution static dead-code and nested ZIP security policy."""

from importlib.util import module_from_spec, spec_from_file_location
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("security_quality_v20", ROOT / "python" / "security_quality_v20.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


def source(folder, text):
    target = Path(folder) / "example.py"
    target.write_text(text, encoding="utf-8")
    return target


def archive(folder, members, name="archive.whl", compression=zipfile.ZIP_DEFLATED):
    target = Path(folder) / name
    with zipfile.ZipFile(target, "w", compression=compression) as output:
        for member, data in members:
            output.writestr(member, data)
    return target


def inner_archive(members):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_STORED) as output:
        for name, content in members:
            output.writestr(name, content)
    return data.getvalue()


class StaticQualityTests(unittest.TestCase):
    def test_literal_boolean_dead_branches_proven(self):
        with tempfile.TemporaryDirectory() as root:
            path = source(root, "if False:\n  lost = 1\nif True:\n  keep = 2\nelse:\n  lost2 = 3\n")
            result = module.analyze_dead_code(path)
            findings = [x for x in result["findings"] if x["rule"] == "F098_LITERAL_UNREACHABLE_BRANCH"]
            self.assertEqual(len(findings), 2)
            self.assertTrue(all(x["confidence"] == "PROVEN_LITERAL_BOOL_BRANCH_ONLY" for x in findings))

    def test_unreachable_after_unconditional_return_and_raise(self):
        with tempfile.TemporaryDirectory() as root:
            path = source(root, "def f():\n  return 1\n  unreachable = 5\n"
                                "def g():\n  raise ValueError()\n  dead = 1\n")
            result = module.analyze_dead_code(path)
            findings = [x for x in result["findings"] if x["rule"] == "F098_UNREACHABLE_AFTER_EXIT"]
            self.assertEqual(len(findings), 2)

    def test_unused_local_candidates_are_not_semantic_proof(self):
        with tempfile.TemporaryDirectory() as root:
            path = source(root, "def f():\n  suspect = 1\n  return 8\n")
            result = module.analyze_dead_code(path)
            self.assertIn("F098_UNUSED_LOCAL_CANDIDATE", [f["rule"] for f in result["findings"]])
            self.assertFalse(result["unused_semantics_proven"])

    def test_used_locals_and_dynamic_introspection_suppress_bad_guess(self):
        with tempfile.TemporaryDirectory() as root:
            path = source(root, "def f():\n  x = 7\n  return x\n\ndef g():\n  secret = 1\n  return locals()\n")
            result = module.analyze_dead_code(path)
            self.assertEqual(result["findings_count"], 0)

    def test_no_source_execution_and_no_secret_echo(self):
        with tempfile.TemporaryDirectory() as root:
            path = source(root, "SECRET_TOKEN_362718 = 7\nraise RuntimeError('private-data')\n")
            result = module.analyze_dead_code(path)
            self.assertFalse(result["source_executed"])
            self.assertNotIn("SECRET_TOKEN", json.dumps(result))
            self.assertNotIn("private-data", json.dumps(result))

    def test_invalid_syntax_and_encoding_report_fixed_reasons(self):
        with tempfile.TemporaryDirectory() as root:
            bad = Path(root) / "bad.py"
            bad.write_bytes(b"def incomplete(\n")
            self.assertEqual(module.analyze_dead_code(bad)["reason"], "invalid_source_or_syntax")
            bad.write_bytes(b"hello = '\xff'\n")
            self.assertEqual(module.analyze_dead_code(bad)["reason"], "invalid_source_or_syntax")

    def test_source_symlink_and_hardlink_refused(self):
        with tempfile.TemporaryDirectory() as root:
            original = source(root, "topsecret = 'SECRET_123'\n")
            alias = Path(root) / "alias.py"
            alias.symlink_to(original)
            self.assertEqual(module.analyze_dead_code(alias)["reason"], "input_not_regular")
            hard = Path(root) / "hard.py"
            os.link(original, hard)
            result = module.analyze_dead_code(original)
            self.assertEqual(result["reason"], "input_hardlink_refused")
            self.assertNotIn("SECRET_123", json.dumps(result))

    def test_source_size_limit(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "large.py"
            with path.open("wb") as output:
                output.truncate(module.MAX_SOURCE + 1)
            self.assertEqual(module.analyze_dead_code(path)["reason"], "input_size_limit")

    def test_finding_quota_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            path = source(root, "if False:\n  bad1 = 1\n  bad2 = 2\n")
            previous = module.MAX_FINDINGS
            try:
                module.MAX_FINDINGS = 1
                result = module.analyze_dead_code(path)
            finally:
                module.MAX_FINDINGS = previous
            self.assertEqual(result["status"], "NOT_RUN")
            self.assertEqual(result["reason"], "static_finding_budget_exceeded")


class ZipPolicyTests(unittest.TestCase):
    def test_normal_zip_and_metadata_are_structure_only(self):
        with tempfile.TemporaryDirectory() as root:
            filename = archive(root, [("example-1.0.dist-info/METADATA", "Name: example\nVersion: 1.0\n"),
                                      ("example/__init__.py", "raise RuntimeError('never executed')\n")])
            result = module.inspect_zip(filename)
            self.assertEqual(result["status"], "STATIC_ZIP_STRUCTURE_ACCEPTED_NOT_TRUSTED")
            self.assertEqual(result["entry_count"], 2)
            self.assertFalse(result["user_code_executed"])
            self.assertFalse(result["malware_absence_proven"])

    def test_nested_zip_scanned_and_budgeted(self):
        with tempfile.TemporaryDirectory() as root:
            nested = inner_archive([("payload.py", "x = 1\n")])
            file = archive(root, [("nested.zip", nested), ("README.txt", "ordinary")])
            result = module.inspect_zip(file)
            self.assertEqual(result["status"], "STATIC_ZIP_STRUCTURE_ACCEPTED_NOT_TRUSTED")
            self.assertEqual(result["entry_count"], 3)

    def test_three_times_nested_zip_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            nested = inner_archive([("deep.py", b"x=1\n")])
            for _ in range(2):
                nested = inner_archive([("nest.zip", nested)])
            result = module.inspect_zip(archive(root, [("outer.zip", nested)]))
            self.assertEqual(result["reason"], "archive_nesting_limit")

    def test_zip_slip_and_windows_path_refused(self):
        with tempfile.TemporaryDirectory() as root:
            for bad in ("../secrets.txt", "/etc/passwd", "C:\\temp\\p.py", "a/./b.py", "a/../b.py"):
                with self.subTest(name=bad):
                    file = archive(root, [(bad, b"PRIVATE_2736")])
                    result = module.inspect_zip(file)
                    self.assertEqual(result["reason"], "archive_unsafe_entry_name")
                    self.assertNotIn("PRIVATE", json.dumps(result))

    def test_symlink_member_refused_without_following(self):
        with tempfile.TemporaryDirectory() as root:
            file = Path(root) / "symlink.zip"
            with zipfile.ZipFile(file, "w") as output:
                member = zipfile.ZipInfo("link.py")
                member.create_system = 3
                member.external_attr = (stat.S_IFLNK | 0o777) << 16
                output.writestr(member, "../../secrets")
            self.assertEqual(module.inspect_zip(file)["reason"], "archive_special_entry_refused")

    def test_extreme_compression_ratio_zipbomb_refused(self):
        with tempfile.TemporaryDirectory() as root:
            file = archive(root, [("bomb.txt", b"A" * 800_000)])
            self.assertEqual(module.inspect_zip(file)["reason"], "archive_compression_ratio_limit")

    def test_oversize_document_in_small_stored_archive(self):
        with tempfile.TemporaryDirectory() as root:
            file = archive(root, [("oversize-doc.md", b"z" * (module.MAX_ENTRY + 1))],
                           compression=zipfile.ZIP_STORED)
            self.assertEqual(module.inspect_zip(file)["reason"], "archive_inflated_budget_exceeded")

    def test_duplicate_zip_members_with_casefold_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            file = archive(root, [("src/Code.py", b"a"), ("src/code.py", b"b")])
            self.assertEqual(module.inspect_zip(file)["reason"], "archive_duplicate_entry")

    def test_metadata_duplicate_names_and_illegal_values_refused(self):
        with tempfile.TemporaryDirectory() as root:
            variants = ("Name: safe\nName: evil\n", "Name: ../private\n",
                        "Version: malicious\n", "Name: safe\nX-Test: \x00\n",
                        "Name: safe\rInjected: bad\n", "Name: safe\u202eevil\n")
            for data in variants:
                with self.subTest(metadata=data):
                    file = archive(root, [("pkg.dist-info/METADATA", data)])
                    result = module.inspect_zip(file)
                    self.assertEqual(result["status"], "REJECTED_BY_STATIC_POLICY")

    def test_metadata_utf8_and_long_lines_refused(self):
        with tempfile.TemporaryDirectory() as root:
            for data, expected in ((b"Name: \xff\n", "metadata_invalid_utf8"),
                                   (b"Name: " + b"z" * 5000, "metadata_control_or_line_limit")):
                file = archive(root, [("pkg.dist-info/METADATA", data)],
                               compression=zipfile.ZIP_STORED)
                self.assertEqual(module.inspect_zip(file)["reason"], expected)

    def test_archive_file_symlink_hardlink_and_oversize_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            original = archive(root, [("sample.py", "pass\n")])
            alias = Path(root) / "alias.zip"
            alias.symlink_to(original)
            self.assertEqual(module.inspect_zip(alias)["reason"], "input_not_regular")
            hard = Path(root) / "hard.zip"
            os.link(original, hard)
            self.assertEqual(module.inspect_zip(original)["reason"], "input_hardlink_refused")
            original.unlink()
            hard.unlink()
            with original.open("wb") as output:
                output.truncate(module.MAX_ARCHIVE + 1)
            self.assertEqual(module.inspect_zip(original)["reason"], "input_size_limit")

    def test_invalid_zip_not_called_clean(self):
        with tempfile.TemporaryDirectory() as root:
            file = Path(root) / "bad.zip"
            file.write_bytes(b"NOT_A_ZIP_SENSITIVE_PAYLOAD")
            result = module.inspect_zip(file)
            self.assertEqual(result["reason"], "archive_unreadable_or_invalid")
            self.assertNotIn("SENSITIVE", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
