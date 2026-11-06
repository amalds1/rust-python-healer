"""Offline ExceptionGroup and TaskGroup parser: fixed trusted fixtures only."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("async_trace_parser", ROOT / "python" / "async_trace_parser.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)
SUPPORTS_GROUPS = sys.implementation.name == "cpython" and sys.version_info >= (3, 11)

TRUSTED_NESTED = (
    "raise ExceptionGroup('outer private-message', [\n"
    "    ValueError('hidden-token-123'),\n"
    "    ExceptionGroup('nested secret', [\n"
    "        RuntimeError('hidden-token-456'), TypeError('hidden-token-789')])])\n"
)
TRUSTED_TASKGROUP = (
    "import asyncio\n"
    "async def first():\n    raise ValueError('secret-a')\n"
    "async def second():\n    raise TypeError('secret-b')\n"
    "async def main():\n"
    "    async with asyncio.TaskGroup() as group:\n"
    "        group.create_task(first())\n"
    "        group.create_task(second())\n"
    "asyncio.run(main())\n"
)
TRUSTED_EXCEPT_STAR = (
    "try:\n"
    "    raise ExceptionGroup('outer', [ValueError('captured'), TypeError('remaining')])\n"
    "except* ValueError:\n"
    "    pass\n"
)


def trusted_stderr(source):
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", source],
                            capture_output=True, text=True, timeout=8, check=False)
    if result.returncode == 0 or "Traceback" not in result.stderr:
        raise AssertionError("fixed trusted traceback fixture did not fail")
    return result.stderr


class AsyncTraceParserTests(unittest.TestCase):
    def test_versioned_except_star_and_taskgroup_capabilities(self):
        status = module.parser_capabilities()
        expected = SUPPORTS_GROUPS
        self.assertEqual(status["except_star_syntax"], expected)
        self.assertEqual(status["task_group_runtime_available"], expected)
        self.assertFalse(status["source_executed"])

    def test_trusted_nested_exceptiongroup_has_hierarchy_hints_only(self):
        if not SUPPORTS_GROUPS:
            report = module.analyze_text("ignored under old CPython")
            self.assertEqual(report["status"], "NOT_SUPPORTED")
            return
        report = module.analyze_text(trusted_stderr(TRUSTED_NESTED))
        self.assertEqual(report["status"], "INSPECTED_PARTIAL")
        self.assertEqual(report["exception_groups_seen"], 2)
        self.assertEqual(report["declared_subexception_total"], 4)
        self.assertEqual(report["leaf_exceptions_seen"], 3)
        self.assertEqual(report["leaf_exception_classes"],
                         ["RuntimeError", "TypeError", "ValueError"])
        self.assertEqual(report["exception_group_headers"][1]["parent_group_index_hint"], 0)
        self.assertEqual([item["parent_group_index_hint"] for item in
                          report["leaf_observations"]], [0, 1, 1])
        self.assertFalse(report["exception_hierarchy_verified"])

    def test_real_taskgroup_trace_is_only_an_unverified_text_hint(self):
        if not SUPPORTS_GROUPS:
            self.assertEqual(module.analyze_text("TaskGroup")["status"], "NOT_SUPPORTED")
            return
        report = module.analyze_text(trusted_stderr(TRUSTED_TASKGROUP))
        self.assertEqual(report["status"], "INSPECTED_PARTIAL")
        self.assertEqual(report["taskgroup_hint"], "POSSIBLE_TRACE_TEXT_NOT_VERIFIED")
        self.assertEqual(report["exception_groups_seen"], 1)
        self.assertEqual(report["leaf_exception_classes"], ["TypeError", "ValueError"])
        self.assertFalse(report["task_execution_verified"])

    def test_real_except_star_trace_shows_unhandled_subgroup_only(self):
        if not SUPPORTS_GROUPS:
            self.assertEqual(module.analyze_text("")["status"], "NOT_SUPPORTED")
            return
        report = module.analyze_text(trusted_stderr(TRUSTED_EXCEPT_STAR))
        self.assertEqual(report["status"], "INSPECTED_PARTIAL")
        self.assertEqual(report["leaf_exception_classes"], ["TypeError"])
        self.assertTrue(report["except_star_syntax_supported"])

    def test_sensitive_exception_details_paths_and_messages_never_returned(self):
        if not SUPPORTS_GROUPS:
            self.assertEqual(module.analyze_text("private-data")["status"], "NOT_SUPPORTED")
            return
        raw = trusted_stderr(TRUSTED_NESTED)
        self.assertIn("hidden-token-123", raw)
        report = module.analyze_text(raw)
        output = json.dumps(report)
        for secret in ("hidden-token-123", "hidden-token-456", "hidden-token-789",
                       "outer private-message", "nested secret", "<string>"):
            self.assertNotIn(secret, output)
        self.assertFalse(report["private_exception_messages_exposed"])
        self.assertFalse(report["source_paths_exposed"])

    def test_base_exception_group_supported_without_mislabeling(self):
        if not SUPPORTS_GROUPS:
            return
        source = "raise BaseExceptionGroup('test', [KeyboardInterrupt('private'), SystemExit('private')])"
        report = module.analyze_text(trusted_stderr(source))
        self.assertEqual(report["exception_group_headers"][0]["type"], "BaseExceptionGroup")
        self.assertEqual(report["leaf_exception_classes"], ["KeyboardInterrupt", "SystemExit"])

    def test_custom_exception_identifiers_are_redacted(self):
        if not SUPPORTS_GROUPS:
            self.assertEqual(module.analyze_text("anything")["status"], "NOT_SUPPORTED")
            return
        text = ("  + Exception Group Traceback (most recent call last):\n"
                "  | ExceptionGroup: private-group-secret (1 sub-exception)\n"
                "    | AcmeSECRETcustomException: hidden-password-987\n")
        result = module.analyze_text(text)
        self.assertEqual(result["leaf_exception_classes"], ["[CUSTOM_EXCEPTION_REDACTED]"])
        self.assertNotIn("SECRETcustom", json.dumps(result))
        self.assertNotIn("hidden-password", json.dumps(result))

    def test_truncated_or_missing_group_header_never_gets_full_inspection(self):
        report = module.analyze_text(
            "  | ExceptionGroup: test (3 sub-exceptions)\n  | and 10 more exceptions\n")
        if not SUPPORTS_GROUPS:
            self.assertEqual(report["status"], "NOT_SUPPORTED")
        else:
            self.assertEqual(report["status"], "INCOMPLETE_TRACE_TEXT")
            self.assertTrue(report["truncated_group_output"])
            self.assertFalse(report["header_present"])

    def test_normal_traceback_is_not_exception_group(self):
        report = module.analyze_text("Traceback (most recent call last):\nValueError: secret\n")
        self.assertEqual(report["status"],
                         "NOT_SUPPORTED" if not SUPPORTS_GROUPS else "NOT_RECOGNIZED")

    def test_missing_file_is_never_success(self):
        with tempfile.TemporaryDirectory() as folder:
            report = module.inspect_file(Path(folder) / "absent.txt")
        self.assertEqual(report["status"],
                         "NOT_SUPPORTED" if not SUPPORTS_GROUPS else "NOT_RUN")

    def test_symlink_and_hardlink_are_refused(self):
        if not SUPPORTS_GROUPS:
            return
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            original = root / "trace.txt"
            original.write_text("ordinary trace\n")
            symlink = root / "linked.txt"
            symlink.symlink_to(original)
            self.assertEqual(module.inspect_file(symlink)["reason"], "trace_symlink_refused")
            hardlink = root / "hardlinked.txt"
            os.link(str(original), str(hardlink))
            self.assertEqual(module.inspect_file(original)["reason"],
                             "trace_not_unique_regular_file")

    def test_oversized_invalid_utf8_and_nul_are_rejected(self):
        if not SUPPORTS_GROUPS:
            return
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.txt"
            path.write_bytes(b"x" * (module.MAX_LOG_BYTES + 1))
            self.assertEqual(module.inspect_file(path)["reason"], "trace_size_limit")
            path.write_bytes(b"\xff\xfe")
            self.assertEqual(module.inspect_file(path)["reason"], "trace_invalid_utf8")
            path.write_bytes(b"group\x00secret")
            self.assertEqual(module.inspect_file(path)["reason"], "trace_contains_nul")

    def test_invalid_unicode_and_pathological_long_line_fail_before_regex(self):
        bad_unicode = module.analyze_text("invalid-\ud800-surrogate")
        self.assertEqual(bad_unicode["status"], "NOT_RUN")
        self.assertEqual(bad_unicode["reason"], "trace_invalid_unicode")
        oversized_line = module.analyze_text("x" * (module.MAX_LINE_CHARS + 1))
        self.assertEqual(oversized_line["status"], "NOT_RUN")
        self.assertEqual(oversized_line["reason"], "trace_line_limit")

    def test_group_and_leaf_budgets_fail_closed(self):
        if not SUPPORTS_GROUPS:
            return
        previous_groups, previous_leaves = module.MAX_GROUPS, module.MAX_LEAVES
        try:
            module.MAX_GROUPS = 1
            self.assertEqual(module.analyze_text(trusted_stderr(TRUSTED_NESTED))["reason"],
                             "trace_group_limit")
            module.MAX_GROUPS = previous_groups
            module.MAX_LEAVES = 1
            self.assertEqual(module.analyze_text(trusted_stderr(TRUSTED_NESTED))["reason"],
                             "trace_leaf_limit")
        finally:
            module.MAX_GROUPS = previous_groups
            module.MAX_LEAVES = previous_leaves

    def test_child_helper_cli_reports_same_safe_summary(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "captured.txt"
            if SUPPORTS_GROUPS:
                path.write_text(trusted_stderr(TRUSTED_NESTED))
            else:
                path.write_text("not supported on old CPython")
            child = subprocess.run([sys.executable, "-I", "-S", "-B",
                                    str(ROOT / "python" / "async_trace_parser.py"), str(path)],
                                   capture_output=True, text=True, timeout=8, check=False)
        self.assertEqual(child.returncode, 0, child.stderr)
        report = json.loads(child.stdout)
        self.assertFalse(report["source_executed"])
        self.assertEqual(report["status"],
                         "INSPECTED_PARTIAL" if SUPPORTS_GROUPS else "NOT_SUPPORTED")


if __name__ == "__main__":
    unittest.main()
