"""Versioned offline PEP 440/508/735/751 and Windows lexical regression suite."""

import sys
import unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("packaging_expansion_v21", ROOT / "python" / "packaging_expansion_v21.py")
pkg = module_from_spec(spec)
spec.loader.exec_module(pkg)
MAJOR, MINOR = sys.version_info[:2]
ENV_WINDOWS = {
    "implementation_name": "cpython", "implementation_version": f"{MAJOR}.{MINOR}.0",
    "os_name": "nt", "platform_machine": "AMD64",
    "platform_python_implementation": "CPython", "platform_release": "10",
    "platform_system": "Windows", "platform_version": "10.0",
    "python_full_version": f"{MAJOR}.{MINOR}.0",
    "python_version": f"{MAJOR}.{MINOR}", "sys_platform": "win32",
}
ENV_LINUX = dict(ENV_WINDOWS, os_name="posix", platform_system="Linux",
                 sys_platform="linux", platform_machine="x86_64",
                 platform_release="6", platform_version="6.1")
DIGEST = "ab" * 32
WHEEL_NAME = "attrs-25.1.0-py3-none-any.whl"


def pylock_fixture():
    return ("lock-version = '1.0'\ncreated-by = 'local-fixture'\n"
            "requires-python = '>=3.9'\n"
            "[[packages]]\nname = 'attrs'\nversion = '25.1.0'\n"
            "[[packages.wheels]]\nname = '" + WHEEL_NAME + "'\n"
            "hashes = {sha256 = '" + DIGEST + "'}\n")


def tool_lock(kind):
    if kind == "uv":
        return "version = 1\n[[package]]\nname = 'attrs'\nversion = '25.1.0'\n"
    if kind == "poetry":
        return "[metadata]\nlock-version = '2.1'\n[[package]]\nname = 'attrs'\nversion = '25.1.0'\n"
    if kind == "pdm":
        return "[metadata]\nlock_version = '4.5'\n[[package]]\nname = 'attrs'\nversion = '25.1.0'\n"
    raise AssertionError(kind)


class PackagingExpansionV21Tests(unittest.TestCase):
    def test_pep440_epoch_and_local_canonicalization(self):
        result = pkg.pep440("1!2.03+ABC.004")
        self.assertEqual(result["canonical"], "1!2.3+abc.4")
        self.assertEqual(result["epoch"], 1)
        self.assertEqual(result["release"], [2, 3])
        self.assertEqual(result["local"], "abc.4")

    def test_pep440_pre_rc_and_dev(self):
        for raw, expected in (("1.0a1", "1.0a1"), ("1.0b2", "1.0b2"),
                              ("1.0rc3", "1.0rc3"), ("1.0.dev4", "1.0.dev4"),
                              ("v1.02", "1.2")):
            with self.subTest(raw=raw):
                self.assertEqual(pkg.pep440(raw)["canonical"], expected)
        self.assertTrue(pkg.pep440("1.0rc3")["is_prerelease"])
        self.assertTrue(pkg.pep440("1.0.dev4")["is_prerelease"])

    def test_pep440_post_release_and_legacy_numeric_post(self):
        self.assertEqual(pkg.pep440("1.0.post2")["post"], 2)
        self.assertTrue(pkg.pep440("1.0.post2")["is_postrelease"])
        self.assertEqual(pkg.pep440("1.0-1")["canonical"], "1.0.post1")

    def test_pep440_specifier_match_and_mismatch(self):
        self.assertTrue(pkg.pep440("1.2.3", ">=1.2,<2")["specifier_matches"])
        self.assertFalse(pkg.pep440("2.1", ">=1.2,<2")["specifier_matches"])
        self.assertFalse(pkg.pep440("1.0rc1", ">=1.0")["specifier_matches"])

    def test_pep440_local_version_is_not_automatically_invalid(self):
        self.assertEqual(pkg.pep440("1.0+Private.BUILD")["canonical"],
                         "1.0+private.build")
        self.assertFalse(pkg.pep440("1.0+private")["external_registry_verified"])

    def test_pep440_invalid_source_injection_and_length(self):
        for value in ("1.0;import os", "import os", "", "1.2.3; rm -rf", "x" * 300):
            with self.subTest(value=value[:20]), self.assertRaises(ValueError):
                pkg.pep440(value)

    def test_pep440_invalid_specifier_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid_pep440_specifier"):
            pkg.pep440("1.2.3", "!!!3")

    def test_pep508_windows_linux_markers_exact_environment(self):
        requirement = "demo>=1; sys_platform == 'win32' and python_version >= '3.9'"
        self.assertTrue(pkg.pep508(requirement, ENV_WINDOWS)["applies_any_selected_extra"])
        self.assertFalse(pkg.pep508(requirement, ENV_LINUX)["applies_any_selected_extra"])

    def test_pep508_python_version_switches_from_3_13_to_3_14(self):
        requirement = "demo>=1; python_version < '3.14'"
        self.assertEqual(pkg.pep508(requirement, ENV_WINDOWS)["applies_any_selected_extra"],
                         MINOR < 14)

    def test_pep508_multiple_extras_marker_and_requested_extras(self):
        result = pkg.pep508("demo[Security]>=2; extra == 'docs'",
                            ENV_WINDOWS, ("docs", "tests"))
        self.assertEqual([name.lower() for name in result["requested_extras"]],
                         ["security"])
        self.assertEqual(result["evaluations"], [{"extra": "docs", "applies": True},
                                                  {"extra": "tests", "applies": False}])

    def test_pep508_empty_extra_no_marker_wildcard(self):
        result = pkg.pep508("demo>=2; extra == 'docs'", ENV_WINDOWS)
        self.assertFalse(result["applies_any_selected_extra"])
        self.assertEqual(result["evaluations"], [{"extra": "", "applies": False}])

    def test_pep508_direct_url_is_not_download_or_authorized(self):
        result = pkg.pep508("demo @ https://example.org/demo.whl", ENV_WINDOWS)
        self.assertTrue(result["direct_url_present"])
        self.assertFalse(result["direct_url_authorized"])
        self.assertFalse(result["source_executed"])

    def test_pep508_malformed_requirement_and_missing_env_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid_pep508_requirement"):
            pkg.pep508("demo;__import__('os')", ENV_WINDOWS)
        with self.assertRaisesRegex(ValueError, "full_explicit_marker_environment_required"):
            pkg.pep508("demo", {"python_version": ENV_WINDOWS["python_version"]})

    def test_pep508_incoherent_python_full_minor_rejected(self):
        wrong = dict(ENV_WINDOWS, python_version="3.99")
        with self.assertRaisesRegex(ValueError, "marker_python_minor_full_version_mismatch"):
            pkg.pep508("demo", wrong)

    def test_pep508_invalid_extras_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid_selected_extras"):
            pkg.pep508("demo", ENV_WINDOWS, ("x;rm",))

    def test_pep751_pylock_wheel_subset_parses_all_seven(self):
        result = pkg.pylock(pylock_fixture(), ENV_WINDOWS)
        self.assertEqual(result["status"], "PARSED_WHEEL_SUBSET_ONLY")
        self.assertEqual(result["packages"][0]["name"], "attrs")
        self.assertEqual(result["packages"][0]["version"], "25.1.0")
        self.assertEqual(result["issues"], [])
        self.assertFalse(result["full_pep751_conformance_verified"])
        self.assertFalse(result["artifact_bytes_verified"])

    def test_pep751_filename_multilock_support_and_invalid_name(self):
        result = pkg.pylock(pylock_fixture(), ENV_WINDOWS, "pylock.ci.toml")
        self.assertEqual(result["status"], "PARSED_WHEEL_SUBSET_ONLY")
        for filename in ("pylock.toml.exe", "../pylock.toml", "pylock..toml"):
            with self.assertRaisesRegex(ValueError, "invalid_pylock_filename"):
                pkg.pylock(pylock_fixture(), ENV_WINDOWS, filename)

    def test_pep751_new_unknown_major_lock_version_not_accepted(self):
        changed = pylock_fixture().replace("lock-version = '1.0'", "lock-version = '2.0'")
        self.assertEqual(pkg.pylock(changed, ENV_WINDOWS)["status"],
                         "UNSUPPORTED_LOCK_VERSION")

    def test_pep751_environment_marker_target_mismatch(self):
        text = pylock_fixture().replace("requires-python", "environments = [\"sys_platform == 'linux'\"]\nrequires-python")
        self.assertEqual(pkg.pylock(text, ENV_WINDOWS)["status"], "TARGET_MISMATCH")

    def test_pep751_requires_python_target_mismatch(self):
        text = pylock_fixture().replace("'>=3.9'", "'>=99.0'")
        result = pkg.pylock(text, ENV_WINDOWS)
        self.assertEqual(result["status"], "TARGET_MISMATCH")
        self.assertEqual(result["reason"], "python_requires_mismatch")

    def test_pep751_invalid_wheel_filename_and_hash_review(self):
        text = pylock_fixture().replace(WHEEL_NAME, "../../malicious.whl")
        result = pkg.pylock(text, ENV_WINDOWS)
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        text = pylock_fixture().replace(DIGEST, "invalid-digest")
        result = pkg.pylock(text, ENV_WINDOWS)
        self.assertIn("wheel_digest_missing_or_invalid", [x["reason"] for x in result["issues"]])

    def test_pep751_wheel_identity_mismatch_is_reported(self):
        text = pylock_fixture().replace(WHEEL_NAME, "other-25.1.0-py3-none-any.whl")
        self.assertEqual(pkg.pylock(text, ENV_WINDOWS)["status"], "REVIEW_REQUIRED")

    def test_pep751_required_packages_list_missing_rejected(self):
        with self.assertRaisesRegex(ValueError, "pylock_packages_required"):
            pkg.pylock("lock-version='1.0'\ncreated-by='fixture'\n", ENV_WINDOWS)

    def test_pep751_package_marker_not_falsely_evaluated(self):
        text = pylock_fixture().replace("version = '25.1.0'",
                                        "version = '25.1.0'\nmarker = \"sys_platform == 'linux'\"")
        result = pkg.pylock(text, ENV_WINDOWS)
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertIn("package_specific_conditions_not_evaluated",
                      [item["reason"] for item in result["issues"]])

    def test_pep751_vcs_source_without_version_is_explicitly_unverified(self):
        text = ("lock-version='1.0'\ncreated-by='fixture'\n[[packages]]\n"
                "name='worktree'\n[packages.vcs]\ntype='git'\n"
                "url='https://example.org/repo'\ncommit-id='aabbcc'\n")
        result = pkg.pylock(text, ENV_WINDOWS)
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertIsNone(result["packages"][0]["version"])

    def test_pep751_vcs_and_directory_unsupported_not_silent_pass(self):
        text = pylock_fixture().replace("[[packages.wheels]]", "[packages.vcs]\ntype = 'git'\nurl = 'https://example.org/x'\n[[packages.wheels]]")
        result = pkg.pylock(text, ENV_WINDOWS)
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertIn("unsupported_nonwheel_source", [x["reason"] for x in result["issues"]])

    def test_pep751_toml_invalid_before_use(self):
        with self.assertRaisesRegex(ValueError, "invalid_toml_document"):
            pkg.pylock("lock-version = [", ENV_WINDOWS)

    def test_pep735_include_order_and_duplicate_requirement_preserved(self):
        text = ("[dependency-groups]\ndocs = ['sphinx>=7']\n"
                "Dev_Test = ['pytest>=8', {include-group = 'docs'}, 'pytest>=8']\n")
        result = pkg.dependency_group(text, "dev-test")
        self.assertEqual(result["requirements"], ["pytest>=8", "sphinx>=7", "pytest>=8"])
        self.assertTrue(result["duplicates_preserved"])

    def test_pep735_nested_recursive_group_include(self):
        text = ("[dependency-groups]\nroot = ['pytest', {include-group = 'mid'}]\n"
                "mid = ['coverage', {include-group = 'base'}]\nbase = ['ruff']\n")
        self.assertEqual(pkg.dependency_group(text, "root")["requirements"],
                         ["pytest", "coverage", "ruff"])

    def test_pep735_include_cycle_refused(self):
        text = ("[dependency-groups]\na = [{include-group = 'b'}]\n"
                "b = [{include-group = 'a'}]\n")
        with self.assertRaisesRegex(ValueError, "dependency_group_cycle"):
            pkg.dependency_group(text, "a")

    def test_pep735_normalized_group_name_collision_refused(self):
        text = "[dependency-groups]\nDev_Test = ['pytest']\ndev-test = ['ruff']\n"
        with self.assertRaisesRegex(ValueError, "duplicate_normalized_group_name"):
            pkg.dependency_group(text, "dev-test")

    def test_pep735_invalid_include_table_and_unknown_target(self):
        bad = "[dependency-groups]\ntest = [{include-group = 'docs', flags = true}]\n"
        with self.assertRaisesRegex(ValueError, "invalid_dependency_group_include"):
            pkg.dependency_group(bad, "test")
        with self.assertRaisesRegex(ValueError, "unknown_included_dependency_group"):
            pkg.dependency_group("[dependency-groups]\na = [{include-group='b'}]", "a")

    def test_pep735_requirements_not_executed(self):
        text = "[dependency-groups]\ndev = ['foo>=1; python_version < \"3.15\"']\n"
        result = pkg.dependency_group(text, "dev")
        self.assertEqual(len(result["requirements"]), 1)
        self.assertFalse(result["target_imports_executed"])

    def test_pep735_invalid_requirement_fails_closed(self):
        text = "[dependency-groups]\ntest = ['foo; __import__(\"os\")']\n"
        with self.assertRaisesRegex(ValueError, "invalid_group_pep508_requirement"):
            pkg.dependency_group(text, "test")

    def test_uv_lock_inventory_not_resolution(self):
        result = pkg.inspect_tool_lock("uv", tool_lock("uv"))
        self.assertEqual(result["tool_lock_version"], 1)
        self.assertEqual(result["packages"][0]["version"], "25.1.0")
        self.assertFalse(result["resolution_verified"])

    def test_poetry_lock_inventory_not_install(self):
        result = pkg.inspect_tool_lock("poetry", tool_lock("poetry"))
        self.assertEqual(result["tool_lock_version"], "2.1")
        self.assertEqual(result["status"], "PARSED_PARTIAL_TOOL_SCHEMA")
        self.assertFalse(result["installation_performed"])

    def test_pdm_lock_inventory_not_full_schema(self):
        result = pkg.inspect_tool_lock("pdm", tool_lock("pdm"))
        self.assertEqual(result["tool_lock_version"], "4.5")
        self.assertFalse(result["schema_fully_supported"])

    def test_unknown_lock_kind_and_missing_metadata_denied(self):
        with self.assertRaisesRegex(ValueError, "unsupported_lock_tool"):
            pkg.inspect_tool_lock("unknown", tool_lock("uv"))
        with self.assertRaisesRegex(ValueError, "missing_lock_metadata"):
            pkg.inspect_tool_lock("poetry", "[[package]]\nname='a'\nversion='1.0'")

    def test_uv_invalid_tool_version_and_malformed_package_denied(self):
        for text in ("version = 'bad'\n[[package]]\nname='a'\nversion='1.0'",
                     "version = 0\n[[package]]\nname='a'\nversion='1.0'"):
            with self.assertRaisesRegex(ValueError, "invalid_uv_lock_version"):
                pkg.inspect_tool_lock("uv", text)
        with self.assertRaisesRegex(ValueError, "invalid_tool_lock_package_version"):
            pkg.inspect_tool_lock("uv", "version=1\n[[package]]\nname='a'\nversion='malicious'")

    def test_windows_relative_safe_path_and_lexical_scope(self):
        result = pkg.windows_relative_path("src\\subdir\\module.py")
        self.assertEqual(result["canonical_windows"], "src\\subdir\\module.py")
        self.assertFalse(result["filesystem_checked"])
        self.assertFalse(result["junction_or_symlink_checked"])

    def test_windows_traversal_drive_unc_ads_and_reserved_rejected(self):
        for path in ("C:\\Windows\\x", "C:relative", "\\\\server\\share\\x",
                     "..\\secret", "folder\\..\\secret", "file.txt:ads",
                     "CON.txt", "LPT1", "COM¹.txt", "CONIN$", "trailing.", "name ", "a\\\\b",
                     "\\\\?\\C:\\evil", "a\x00b"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                pkg.windows_relative_path(path)

    def test_powershell_quotes_literal_single_quote_and_metacharacters(self):
        unsafe = "a'; Remove-Item C:\\valuable; '"
        result = pkg.powershell_literal(unsafe)
        self.assertEqual(result["literal"], "'a''; Remove-Item C:\\valuable; '''")
        self.assertFalse(result["command_executed"])
        self.assertFalse(result["command_escaped"])

    def test_powershell_rejects_multiline_and_controls(self):
        for raw in ("a\nb", "a\rb", "a\x00b", "a\tb"):
            with self.assertRaisesRegex(ValueError, "unsafe_powershell_control_character"):
                pkg.powershell_literal(raw)

    def test_integrity_of_results_no_external_execution_or_install(self):
        self.assertFalse(pkg.pep440("1.0")["source_executed"])
        self.assertFalse(pkg.pep508("demo", ENV_WINDOWS)["target_package_imported"])
        self.assertFalse(pkg.pylock(pylock_fixture(), ENV_WINDOWS)["network_used"])
        for tool in ("uv", "poetry", "pdm"):
            self.assertFalse(pkg.inspect_tool_lock(tool, tool_lock(tool))["package_code_executed"])


if __name__ == "__main__":
    unittest.main()
