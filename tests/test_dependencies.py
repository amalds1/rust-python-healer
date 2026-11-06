"""Offline dependency introspection under every CPython 3.9+ runtime."""

from importlib.util import module_from_spec, spec_from_file_location
import ast
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("dependencies", ROOT / "python" / "dependencies.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(root, folder, name, version, constraint):
    target = Path(root) / folder
    target.mkdir()
    (target / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: {}\nVersion: {}\nRequires-Python: {}\nRequires-Dist: flask>=2\n".format(
            name, version, constraint), encoding="utf-8"
    )


class DependencyTests(unittest.TestCase):
    def test_pep508_platform_marker_on_active_interpreter(self):
        self.assertEqual(module.environment_marker('sys_platform == "{}"'.format(sys.platform)),
                         "SATISFIED")
        self.assertEqual(module.environment_marker('sys_platform != "{}"'.format(sys.platform)),
                         "UNSATISFIED")
        self.assertEqual(module.environment_marker('os_name in "posix nt"'), "SATISFIED")

    def test_pep508_python_versions_compare_numerically(self):
        minor = sys.version_info.minor
        self.assertEqual(module.environment_marker('python_version >= "3.9"'), "SATISFIED")
        self.assertEqual(module.environment_marker('python_version < "3.16"'), "SATISFIED")
        self.assertEqual(module.environment_marker('python_version > "3.{}"'.format(minor)),
                         "UNSATISFIED")
        self.assertEqual(module.environment_marker('python_full_version >= "3.9.0"'), "SATISFIED")

    def test_pep508_extras_need_explicit_selection(self):
        expr = 'extra == "PDF"'
        self.assertEqual(module.environment_marker(expr), "UNKNOWN")
        self.assertEqual(module.environment_marker(expr, ["pdf"]), "SATISFIED")
        self.assertEqual(module.environment_marker(expr, ["dev"]), "UNSATISFIED")
        self.assertEqual(module.environment_marker('extra == "pdf" or extra == "dev"', ["dev"]),
                         "SATISFIED")

    def test_pep508_boolean_precedence_and_unknown_fields(self):
        self.assertEqual(module.environment_marker(
            'python_version >= "3.9" and (sys_platform == "invalid-os" or os_name == ' + json.dumps(os.name) + ')'),
            "SATISFIED")
        self.assertEqual(module.environment_marker('python_version < "3.9" and unknown == "x"'),
                         "UNSATISFIED")
        self.assertEqual(module.environment_marker('python_version >= "3.9" and unknown == "x"'),
                         "UNKNOWN")
        self.assertEqual(module.environment_marker('sys_platform > "linux"'), "UNKNOWN")

    def test_pep508_rejects_execution_and_unsupported_grammar(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "would_execute"
            source = "__import__('pathlib').Path({!r}).write_text('BAD')".format(str(marker))
            self.assertEqual(module.environment_marker(source), "UNKNOWN")
            self.assertEqual(module.environment_marker('sys_platform == "linux" and (' + source + ')'),
                             "UNKNOWN")
            self.assertFalse(marker.exists(), "marker evaluator executed injected Python")
        for invalid in ("", "python_version ~= '3.9'", "extra > 'dev'", "extras == 'a'",
                        'python_version >= "3.9"' * 1000):
            self.assertEqual(module.environment_marker(invalid), "UNKNOWN")

    def test_invalid_grammar_never_hidden_by_true_or_false_branch(self):
        for invalid in ("__import__('os')", "x.attribute == 'a'", "x[0] == 'a'",
                        "(lambda: True)()", "x is 'a'", "x == 1", "not (x == 'a')"):
            for expression in ('sys_platform == "impossible" and (' + invalid + ')',
                               'os_name in "posix nt" or (' + invalid + ')'):
                with self.subTest(expression=expression):
                    self.assertEqual(module.environment_marker(expression), "UNKNOWN")

    def test_unknown_metadata_preserves_three_valued_boolean_contract(self):
        environment = {"sys_platform": "win32"}
        for expression, expected in (("sys_platform == 'other' and missing == 'x'", "UNSATISFIED"),
                                     ("sys_platform == 'win32' or missing == 'x'", "SATISFIED"),
                                     ("sys_platform == 'win32' and missing == 'x'", "UNKNOWN")):
            self.assertEqual(module.environment_marker(expression, environment=environment), expected)

    def test_all_ast_nodes_and_actual_depth_are_bounded(self):
        for count, expected in ((50, "SATISFIED"), (51, "UNKNOWN")):
            expression = " and ".join(['os_name in "posix nt"'] * count)
            actual_nodes = len(list(ast.walk(ast.parse(expression, mode="eval"))))
            self.assertEqual(actual_nodes <= 256, count == 50)
            self.assertEqual(module.environment_marker(expression), expected)
        for levels, expected in ((13, "SATISFIED"), (14, "UNKNOWN")):
            expression = 'os_name in "posix nt"'
            for _ in range(levels):
                expression = 'os_name in "posix nt" and (' + expression + ')'
            self.assertEqual(module.environment_marker(expression), expected)

    def test_inspect_reports_pep508_marker_result_alongside_raw_metadata(self):
        with tempfile.TemporaryDirectory() as root:
            fixture(root, "alpha-1.2.dist-info", "alpha", "1.2", ">=3.9")
            metadata_file = Path(root) / "alpha-1.2.dist-info" / "METADATA"
            with metadata_file.open("a", encoding="utf-8") as handle:
                handle.write('Requires-Dist: pypdf>=3; extra == "pdf"\n')
                handle.write('Requires-Dist: pywin32; sys_platform == "win32"\n')
            item = module.inspect(["alpha"], [root], ["pdf"])["packages"][0]["distributions"][0]
            self.assertEqual(item["requirement_marker_results"][0]["marker_status"], "NOT_DECLARED")
            self.assertEqual(item["requirement_marker_results"][1]["marker_status"], "SATISFIED")
            self.assertEqual(item["requirement_marker_results"][2]["marker_status"],
                             "UNSATISFIED" if sys.platform != "win32" else "SATISFIED")
            self.assertEqual(item["requirement_marker_results"][1]["specifier_parse"], "NOT_RUN")

    def test_normalizes_valid_distribution_names(self):
        self.assertEqual(module.normalize("Example_Test.Pkg"), "example-test-pkg")

    def test_rejects_path_traversal_package(self):
        for bad in ("../etc", "", "../foo", "a b", "a/../../x"):
            with self.assertRaises(ValueError):
                module.normalize(bad)

    def test_simple_supported_range_satisfied(self):
        self.assertEqual(module.requires_python(">=3.9,<3.16", sys.version_info), "SATISFIED")

    def test_future_requirement_is_unsatisfied(self):
        self.assertEqual(module.requires_python(">=3.16", sys.version_info), "UNSATISFIED")

    def test_unsupported_specifier_is_unknown(self):
        self.assertEqual(module.requires_python("~=3", sys.version_info), "UNKNOWN")
        self.assertEqual(module.requires_python("", sys.version_info), "UNKNOWN")

    def test_compatible_release_matches_python_minor_without_running_code(self):
        version = sys.version_info
        minor = version.minor
        self.assertEqual(module.requires_python("~=3.9", version), "SATISFIED")
        self.assertEqual(module.requires_python("~=3.{}.0".format(minor), version), "SATISFIED")
        self.assertEqual(module.requires_python("~=3.{}.0".format(minor + 1), version), "UNSATISFIED")
        self.assertEqual(module.requires_python("~=3.9.0", version),
                         "SATISFIED" if minor == 9 else "UNSATISFIED")
        self.assertEqual(module.requires_python("~= 3.{}.0".format(minor), version), "SATISFIED")

    def test_zero_epochs_and_future_epochs_are_distinct(self):
        version = sys.version_info
        self.assertEqual(module.requires_python(">=0!3.9", version), "SATISFIED")
        self.assertEqual(module.requires_python(">=1!0.0", version), "UNSATISFIED")
        self.assertEqual(module.requires_python("<1!0.0", version), "SATISFIED")
        self.assertEqual(module.requires_python("!=1!3.{}.0".format(version.minor), version),
                         "SATISFIED")
        self.assertEqual(module.requires_python("~=1!3.9", version), "UNSATISFIED")
        self.assertEqual(module.requires_python("==0!3.{}.*".format(version.minor), version),
                         "SATISFIED")

    def test_arbitrary_equality_is_exact_not_padded(self):
        version = sys.version_info
        exact = "{}.{}.{}".format(*version[:3])
        self.assertEqual(module.requires_python("===" + exact, version), "SATISFIED")
        self.assertEqual(module.requires_python("===3.{}".format(version.minor), version),
                         "UNSATISFIED")
        self.assertEqual(module.requires_python("===not-a-python-release", version), "UNSATISFIED")
        self.assertEqual(module.requires_python("=={}".format(exact), version), "SATISFIED")

    def test_zero_padding_beyond_three_components(self):
        version = sys.version_info
        exact = "{}.{}.{}".format(*version[:3])
        self.assertEqual(module.requires_python("==" + exact + ".0.0", version), "SATISFIED")
        self.assertEqual(module.requires_python("==" + exact + ".0.1", version), "UNSATISFIED")
        self.assertEqual(module.requires_python("=={}.*".format(exact), version), "SATISFIED")

    def test_unsupported_pep440_or_injected_tail_never_claims_proof(self):
        version = sys.version_info
        for expression in (
                "~=3", "~=3.16a1", "==3.15rc1", ">=3.9.post1", ">=3.9+private",
                "===secret\u2603", ">=3.16,completely invalid", "~=3.9.*",
                "===", ">=3.9," + "!=3.9" * 2000, ">=3.9," * 17,
                "==3.9; __import__('os').system('false')"):
            self.assertEqual(module.requires_python(expression, version), "UNKNOWN", expression)
        self.assertEqual(module.requires_python(">=3.9", (3, 16, 0, "alpha", 1)), "UNKNOWN")

    def test_strict_greater_excludes_only_specified_release(self):
        self.assertEqual(module.requires_python(">3.9", (3, 9, 25, "final", 0)), "SATISFIED")
        self.assertEqual(module.requires_python(">3.9.0", (3, 9, 25, "final", 0)), "SATISFIED")
        self.assertEqual(module.requires_python(">3.9", (3, 9, 0, "final", 0)), "UNSATISFIED")

    def test_installed_fixture_metadata_is_inspected_without_import(self):
        with tempfile.TemporaryDirectory() as root:
            fixture(root, "alpha-1.2.dist-info", "alpha", "1.2", ">=3.9,<3.16")
            result = module.inspect(["alpha"], [root])
            self.assertEqual(result["status"], "INSPECTED")
            self.assertEqual(result["packages"][0]["status"], "FOUND")
            item = result["packages"][0]["distributions"][0]
            self.assertEqual(item["python_constraint_status"], "SATISFIED")
            self.assertEqual(item["requires_dist"], ["flask>=2"])
            self.assertEqual(item["direct_url"]["status"], "NOT_DECLARED")
            self.assertEqual(result["runtime_compatibility"], "NOT_VERIFIED")

    def test_direct_url_vcs_origin_redacts_credentials_and_url_path(self):
        with tempfile.TemporaryDirectory() as root:
            folder = "alpha-1.2.dist-info"
            fixture(root, folder, "alpha", "1.2", ">=3.9")
            (Path(root) / folder / "direct_url.json").write_text(json.dumps({
                "url": "git+https://demo:supersecret@example.org/private/repo?token=hidden",
                "vcs_info": {"vcs": "git", "commit_id": "abc123"}
            }), encoding="utf-8")
            record = module.inspect(["alpha"], [root])["packages"][0]["distributions"][0]["direct_url"]
            self.assertEqual(record["status"], "RECORDED_NOT_VERIFIED")
            self.assertEqual(record["kind"], "VCS")
            self.assertEqual(record["host"], "example.org")
            self.assertTrue(record["commit_recorded"])
            rendered = json.dumps(record)
            for secret in ("supersecret", "token=hidden", "/private/repo", "demo:"):
                self.assertNotIn(secret, rendered)

    def test_editable_direct_url_does_not_expose_local_path(self):
        with tempfile.TemporaryDirectory() as root:
            folder = "alpha-1.2.dist-info"
            fixture(root, folder, "alpha", "1.2", ">=3.9")
            (Path(root) / folder / "direct_url.json").write_text(json.dumps({
                "url": "file:///home/private/customer-workspace",
                "dir_info": {"editable": True}
            }), encoding="utf-8")
            record = module.inspect(["alpha"], [root])["packages"][0]["distributions"][0]["direct_url"]
            self.assertEqual(record["kind"], "DIRECTORY")
            self.assertEqual(record["scheme"], "file")
            self.assertTrue(record["editable"])
            self.assertNotIn("customer-workspace", json.dumps(record))

    def test_oversized_or_malformed_origin_never_claims_verified(self):
        with tempfile.TemporaryDirectory() as root:
            folder = "alpha-1.2.dist-info"
            fixture(root, folder, "alpha", "1.2", ">=3.9")
            file = Path(root) / folder / "direct_url.json"
            file.write_text("x" * (module.MAX_DIRECT_URL_BYTES + 1))
            record = module.inspect(["alpha"], [root])["packages"][0]["distributions"][0]["direct_url"]
            self.assertEqual(record, {"status": "INVALID", "reason": "size_limit"})
            file.write_text("{bad json")
            record = module.inspect(["alpha"], [root])["packages"][0]["distributions"][0]["direct_url"]
            self.assertEqual(record["status"], "INVALID")

    def test_symlinked_direct_url_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            folder = "alpha-1.2.dist-info"
            fixture(root, folder, "alpha", "1.2", ">=3.9")
            private = Path(root) / "secret.txt"
            private.write_text("private metadata")
            (Path(root) / folder / "direct_url.json").symlink_to(private)
            record = module.inspect(["alpha"], [root])["packages"][0]["distributions"][0]["direct_url"]
            self.assertEqual(record, {"status": "INVALID", "reason": "symlink_refused"})

    def test_two_distributions_are_ambiguous_not_pass(self):
        with tempfile.TemporaryDirectory() as root:
            fixture(root, "alpha-1.2.dist-info", "alpha", "1.2", ">=3.9")
            fixture(root, "alpha-2.0.dist-info", "alpha", "2.0", ">=3.9")
            result = module.inspect(["alpha"], [root])
            self.assertEqual(result["packages"][0]["status"], "AMBIGUOUS")

    def test_missing_distribution_is_not_marked_installed(self):
        with tempfile.TemporaryDirectory() as root:
            result = module.inspect(["absent-zzq987"], [root])
            self.assertEqual(result["packages"][0]["status"], "MISSING")

    def test_invalid_extra_metadata_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                module.inspect(["alpha"], [str(Path(root) / "absent")])


if __name__ == "__main__":
    unittest.main()
