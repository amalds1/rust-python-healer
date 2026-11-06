"""Versioned static rule classification: no project execution or risk proof."""

from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("static_quality", ROOT / "python" / "static_quality.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(folder, name, text):
    file = Path(folder) / name
    file.write_text(text, encoding="utf-8")
    return file


class StaticQualityTests(unittest.TestCase):
    def test_complete_declared_rule_taxonomy(self):
        self.assertEqual(len(module.RULES), 9)
        for name, values in module.RULES.items():
            result = module.classify_rule(name)
            self.assertEqual(result["status"], "CLASSIFIED")
            self.assertEqual(result["rule_id"], name)
            self.assertEqual((result["category"], result["severity"],
                              result["reason_code"]), values)

    def test_unknown_and_invalid_taxonomy_cannot_claim_known_rule(self):
        for name in ("SEC999", "sec001", "../SEC001", None, 42, [], {}, ""):
            self.assertEqual(module.classify_rule(name), {
                "status": "UNKNOWN_UNCLASSIFIED", "category": "UNKNOWN",
                "severity": "UNKNOWN", "rule_id": "UNKNOWN",
            })

    def test_security_rules_and_smells_are_all_classified_read_only(self):
        with tempfile.TemporaryDirectory() as folder:
            file = fixture(folder, "hazards.py", """
import pickle, os, subprocess, tempfile
def example():
    untouched = 1
    eval('42')
    os.system('id')
    subprocess.run('echo hi', shell=True)
    pickle.loads(b'garbage')
    tempfile.mktemp()
    try:
        pass
    except:
        pass
    if False:
        expensive_side_effect()
    return 42
    print('unreachable')
async def pending():
    return 10
pending()
def isolated_unused():
    unused_local = 1
    return 7
""")
            findings = module.analyze_file(file)
            self.assertEqual(findings["status"], "INSPECTED_PARTIAL")
            self.assertFalse(findings["source_executed"])
            self.assertFalse(findings["code_behavior_verified"])
            self.assertTrue(findings["all_declared_rules_classified"])
            observed = [row["rule_id"] for row in findings["findings"]]
            self.assertEqual(set(observed), set(module.RULES))
            self.assertGreaterEqual(findings["findings_count"], 9)
            self.assertFalse(findings["security_vulnerabilities_verified"])

    def test_safe_source_has_no_false_positive_for_known_patterns(self):
        with tempfile.TemporaryDirectory() as folder:
            file = fixture(folder, "safe.py", """
from math import sqrt
def square(x):
    y = x * x
    return y
print(square(2))
""")
            data = module.analyze_file(file)
            self.assertEqual(data["status"], "INSPECTED_PARTIAL")
            self.assertEqual(data["findings_count"], 0)

    def test_shadowed_builtin_is_only_a_possible_security_candidate(self):
        with tempfile.TemporaryDirectory() as folder:
            file = fixture(folder, "shadowed.py", "eval = lambda v: v\nvalue = eval('text')\n")
            data = module.analyze_file(file)
            self.assertEqual(data["findings"][0]["rule_id"], "SEC001")
            self.assertEqual(data["findings"][0]["confidence"],
                             "STATIC_CANDIDATE_NOT_VERIFIED")

    def test_subprocess_without_shell_true_is_not_automatically_suspect(self):
        with tempfile.TemporaryDirectory() as folder:
            file = fixture(folder, "subprocess.py", """
import subprocess
subprocess.run(['true'], shell=False)
subprocess.Popen(['true'])
""")
            self.assertEqual(module.analyze_file(file)["findings_count"], 0)

    def test_local_unused_assignment_is_candidate_only(self):
        with tempfile.TemporaryDirectory() as folder:
            file = fixture(folder, "unused.py", """
def sample():
    x = 12
    return 42
""")
            data = module.analyze_file(file)
            self.assertEqual(data["findings"][0]["rule_id"], "SMELL002")
            self.assertFalse(data["unused_variables_verified"])

    def test_locals_and_dynamic_inspection_disable_unsafe_unused_guessing(self):
        with tempfile.TemporaryDirectory() as folder:
            file = fixture(folder, "locals.py", """
def sample():
    secret_value = 'private'
    return locals()
""")
            data = module.analyze_file(file)
            self.assertEqual(data["findings_count"], 0)
            self.assertNotIn("private", json.dumps(data))

    def test_constant_false_and_true_branches_are_reported_syntactically(self):
        with tempfile.TemporaryDirectory() as folder:
            file = fixture(folder, "branches.py", """
if False:
    a = 1
if True:
    b = 2
else:
    c = 3
""")
            data = module.analyze_file(file)
            issues = [f for f in data["findings"] if f["rule_id"] == "SMELL004"]
            self.assertEqual(len(issues), 2)
            self.assertTrue(all(f["confidence"] ==
                                "PROVEN_LITERAL_IF_BRANCH_UNREACHABLE" for f in issues))

    def test_statement_after_return_is_unreachable_same_block_only(self):
        with tempfile.TemporaryDirectory() as folder:
            file = fixture(folder, "afterreturn.py", """
def func():
    return 1
    x = 2
    print(x)
""")
            data = module.analyze_file(file)
            issues = [f for f in data["findings"] if f["rule_id"] == "SMELL003"]
            self.assertEqual(len(issues), 2)

    def test_bare_unawaited_local_async_call_remains_unverified(self):
        with tempfile.TemporaryDirectory() as folder:
            file = fixture(folder, "coroutine.py", """
async def pending():
    return 1
pending()
async def caller():
    await pending()
""")
            data = module.analyze_file(file)
            findings = [f for f in data["findings"] if f["rule_id"] == "ASYNC001"]
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["confidence"], "STATIC_CANDIDATE_NOT_VERIFIED")
            self.assertFalse(data["unawaited_coroutines_verified"])

    def test_missing_and_oversized_source_never_claims_inspection(self):
        with tempfile.TemporaryDirectory() as folder:
            missing = module.analyze_file(Path(folder) / "missing.py")
            self.assertEqual(missing["status"], "NOT_RUN")
            huge = Path(folder) / "huge.py"
            huge.write_bytes(b"x" * (module.MAX_SOURCE_BYTES + 1))
            data = module.analyze_file(huge)
            self.assertEqual(data["status"], "NOT_RUN")
            self.assertEqual(data["reason"], "source_size_limit")

    def test_symlink_and_hardlink_source_refused_without_content_leak(self):
        with tempfile.TemporaryDirectory() as folder:
            original = fixture(folder, "private.py", "secret = 'VERY_PRIVATE_TOKEN_9823'\n")
            symlink = Path(folder) / "link.py"
            symlink.symlink_to(original)
            self.assertEqual(module.analyze_file(symlink)["reason"],
                             "source_not_regular_file")
            hardlink = Path(folder) / "hardlink.py"
            os.link(original, hardlink)
            data = module.analyze_file(original)
            self.assertEqual(data["reason"], "source_hardlink_refused")
            self.assertNotIn("VERY_PRIVATE_TOKEN_9823", json.dumps(data))

    def test_source_encodings_and_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as folder:
            latin = Path(folder) / "latin.py"
            latin.write_bytes(b"# coding: latin-1\nvalue = 'caf\xe9'\n")
            self.assertEqual(module.analyze_file(latin)["status"], "INSPECTED_PARTIAL")
            bad = Path(folder) / "bad.py"
            bad.write_bytes(b"value = '\xff'\n")
            self.assertEqual(module.analyze_file(bad)["status"], "INVALID_ENCODING")

    def test_versioned_pattern_matching_uses_selected_ast_parser(self):
        with tempfile.TemporaryDirectory() as folder:
            file = fixture(folder, "modern.py", "match 3:\n    case 3:\n        pass\n")
            observed = module.analyze_file(file)
            expected = "SYNTAX_ERROR" if sys.version_info.minor == 9 else "INSPECTED_PARTIAL"
            self.assertEqual(observed["status"], expected)

    def test_finding_quotas_cannot_turn_truncated_result_into_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            file = fixture(folder, "findings.py", "eval('1')\neval('2')\n")
            prior = module.MAX_FINDINGS
            try:
                module.MAX_FINDINGS = 1
                result = module.analyze_file(file)
            finally:
                module.MAX_FINDINGS = prior
            self.assertEqual(result["status"], "NOT_RUN")
            self.assertEqual(result["reason"], "finding_limit")

    def test_ast_node_quotas_cannot_turn_truncated_result_into_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            file = fixture(folder, "nodes.py", "value = 1\nvalue += 2\n")
            prior = module.MAX_NODES
            try:
                module.MAX_NODES = 2
                result = module.analyze_file(file)
            finally:
                module.MAX_NODES = prior
            self.assertEqual(result["status"], "NOT_RUN")
            self.assertEqual(result["reason"], "ast_node_limit")

    def test_cli_reads_risky_source_without_executing_or_leaking_it(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / "would_run.txt"
            source = fixture(folder, "source.py", """
import pathlib
pathlib.Path({!r}).write_text('never')
password = 'SECRET_PASSWORD_99261'
""".format(str(marker)))
            proc = subprocess.run([
                sys.executable, "-I", "-S", "-B",
                str(ROOT / "python" / "static_quality.py"), str(source)],
                capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual(report["status"], "INSPECTED_PARTIAL")
            self.assertFalse(report["source_executed"])
            self.assertFalse(marker.exists())
            self.assertNotIn("SECRET_PASSWORD_99261", proc.stdout)

    def test_classify_cli_refuses_unknown_rule_without_claiming_security(self):
        command = [sys.executable, "-I", "-S", "-B",
                   str(ROOT / "python" / "static_quality.py"), "--classify"]
        good = subprocess.run(command + ["SEC001"], capture_output=True, text=True,
                              check=False)
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertEqual(json.loads(good.stdout)["category"], "SECURITY")
        unknown = subprocess.run(command + ["INVALID"], capture_output=True, text=True,
                                 check=False)
        self.assertEqual(unknown.returncode, 0, unknown.stderr)
        self.assertEqual(json.loads(unknown.stdout)["status"], "UNKNOWN_UNCLASSIFIED")


if __name__ == "__main__":
    unittest.main()
