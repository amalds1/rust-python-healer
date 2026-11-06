"""Actual bounded PEP 751, tool-lock, PEP 610 and PEP 668 proofs."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "package_policy_v22.py"
spec = importlib.util.spec_from_file_location("package_policy_v22", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

DIGEST = "ab" * 32
ALPHA_WHEEL = "alpha-1.2.3-py3-none-any.whl"
BETA_WHEEL = "beta-2.0-py3-none-any.whl"


def pylock_fixture():
    return ("lock-version = '1.0'\n"
            "created-by = 'trusted-offline-fixture'\n"
            "requires-python = '>=3.9'\n"
            "[[packages]]\n"
            "name = 'alpha'\n"
            "version = '1.2.3'\n"
            "[[packages.wheels]]\n"
            "name = '" + ALPHA_WHEEL + "'\n"
            "[packages.wheels.hashes]\n"
            "sha256 = '" + DIGEST + "'\n"
            "[[packages.dependencies]]\n"
            "name = 'beta'\n"
            "version = '2.0'\n"
            "[[packages]]\n"
            "name = 'beta'\n"
            "version = '2.0'\n"
            "[[packages.wheels]]\n"
            "name = '" + BETA_WHEEL + "'\n"
            "[packages.wheels.hashes]\n"
            "sha256 = '" + DIGEST + "'\n")


def uv_fixture():
    return ("version = 1\n"
            "[[package]]\nname='alpha'\nversion='1.2.3'\n"
            "dependencies=[{name='beta',version='2.0'}]\n"
            "wheels=[{filename='" + ALPHA_WHEEL + "', hash='sha256:" + DIGEST + "'}]\n"
            "[[package]]\nname='beta'\nversion='2.0'\n"
            "wheels=[{filename='" + BETA_WHEEL + "', hash='sha256:" + DIGEST + "'}]\n")


def poetry_fixture():
    return ("[metadata]\nlock-version='2.1'\n"
            "[[package]]\nname='alpha'\nversion='1.2.3'\n"
            "[package.dependencies]\nbeta='^2.0'\n"
            "[[package.files]]\nfile='" + ALPHA_WHEEL + "'\nhash='sha256:" + DIGEST + "'\n"
            "[[package]]\nname='beta'\nversion='2.0'\n"
            "[[package.files]]\nfile='" + BETA_WHEEL + "'\nhash='sha256:" + DIGEST + "'\n")


def pdm_fixture():
    return ("[metadata]\nlock_version='4.5'\n"
            "[[package]]\nname='alpha'\nversion='1.2.3'\n"
            "dependencies=['beta>=2']\n"
            "files=[{file='" + ALPHA_WHEEL + "', hash='sha256:" + DIGEST + "'}]\n"
            "[[package]]\nname='beta'\nversion='2.0'\n"
            "files=[{file='" + BETA_WHEEL + "', hash='sha256:" + DIGEST + "'}]\n")


class PackagePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rph-policy-v22-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    # F060: AST project imports joined with pyproject and locks.
    def test_static_ast_import_graph_joins_project_dependencies_and_lock(self):
        pkg = self.base / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("# package\n")
        (pkg / "util.py").write_text("safe = True\n")
        (pkg / "core.py").write_text("from . import util\nimport json\n")
        (self.base / "pyproject.toml").write_text(
            "[project]\nname='demo'\ndependencies=['requests>=2']\n")
        (self.base / "pylock.toml").write_text(pylock_fixture())
        report = mod.analyze_project(self.base)
        self.assertEqual(report["status"], "PROJECT_STATIC_IMPORT_AND_PACKAGE_GRAPH")
        self.assertIn(["pkg.core", "pkg.util"], report["possible_import_edges"])
        self.assertEqual(report["pyproject_dependencies"], ["requests"])
        self.assertEqual(report["local_lock_package_counts"], {"pylock.toml": 2})
        self.assertFalse(report["unknown_source_executed"])

    def test_static_imports_never_execute_traps(self):
        (self.base / "poison.py").write_text("open('/should-never-be-written','w').write('bad')\n")
        self.assertEqual(mod.analyze_project(self.base)["modules"], ["poison"])

    def test_project_rejects_source_symlink(self):
        target = self.base / "private.txt"
        target.write_text("private")
        (self.base / "linked.py").symlink_to(target)
        with self.assertRaisesRegex(ValueError, "unsafe_nonregular"):
            mod.analyze_project(self.base)

    def test_project_rejects_hardlinked_source(self):
        target = self.base / "linked-from.py"
        target.write_text("safe = True\n")
        linked = self.base / "linked-to.py"
        os.link(target, linked)
        with self.assertRaisesRegex(ValueError, "hardlinked"):
            mod.analyze_project(self.base)

    def test_project_rejects_broken_pyproject_dependency(self):
        (self.base / "pyproject.toml").write_text("[project]\ndependencies = ['not a valid req ??']\n")
        with self.assertRaisesRegex(ValueError, "invalid_pyproject"):
            mod.analyze_project(self.base)

    def test_project_rejects_bogus_source_syntax(self):
        (self.base / "broken.py").write_text("def incomplete(\n")
        with self.assertRaisesRegex(ValueError, "unparseable_python"):
            mod.analyze_project(self.base)

    def test_project_ignores_non_python_script_execution(self):
        (self.base / "setup.py").write_text("raise RuntimeError('NEVER_EXECUTE')\n")
        report = mod.analyze_project(self.base)
        self.assertFalse(report["unknown_source_executed"])

    # F181: actual PEP 751 wheel graph and marker conditions.
    def test_pylock_graph_two_nodes_exact_dependency(self):
        result = mod.validate_pylock_graph(pylock_fixture(), "3.12.14")
        self.assertEqual(result["status"], "PEP751_V1_WHEEL_GRAPH_VALIDATED_LOCAL_ONLY")
        self.assertEqual(result["dependency_audit_edges"],
                         [{"from": ["alpha", "1.2.3"], "to": ["beta", "2.0"]}])
        self.assertFalse(result["installation_performed"])
        self.assertTrue(result["dependencies_not_used_for_installation"])

    def test_pylock_graph_all_python_minor_markers(self):
        for minor in range(9, 16):
            result = mod.validate_pylock_graph(pylock_fixture(), "3." + str(minor) + ".0")
            self.assertEqual(result["status"], "PEP751_V1_WHEEL_GRAPH_VALIDATED_LOCAL_ONLY")

    def test_pylock_unsupported_major_version_explicit(self):
        result = mod.validate_pylock_graph(pylock_fixture().replace("'1.0'", "'2.0'", 1), "3.12")
        self.assertEqual(result["status"], "NOT_SUPPORTED_LOCK_VERSION")

    def test_pylock_rejects_unknown_or_unpinned_wheel(self):
        with self.assertRaisesRegex(ValueError, "wheel_unpinned"):
            mod.validate_pylock_graph(pylock_fixture().replace(DIGEST, "d" * 10, 1), "3.12")

    def test_pylock_catches_ambiguous_dependency_and_duplicates(self):
        broken = pylock_fixture().replace("name = 'beta'\nversion = '2.0'\n[[packages.wheels]]",
                                           "name = 'gamma'\nversion = '2.0'\n[[packages.wheels]]")
        with self.assertRaisesRegex(ValueError, "wheel_identity_mismatch|dependency_missing"):
            mod.validate_pylock_graph(broken, "3.12")
        duplicated = pylock_fixture() + ("[[packages]]\nname='beta'\nversion='2.0'\n"
                                           "[[packages.wheels]]\nname='" + BETA_WHEEL + "'\n"
                                           "[packages.wheels.hashes]\nsha256='" + DIGEST + "'\n")
        with self.assertRaisesRegex(ValueError, "ambiguous_package_identity"):
            mod.validate_pylock_graph(duplicated, "3.12")

    def test_pylock_selected_target_environment_blocks_foreign_platform(self):
        text = pylock_fixture().replace("created-by", "environments = [\"sys_platform == 'win32'\"]\ncreated-by", 1)
        self.assertEqual(mod.validate_pylock_graph(text, "3.12", "linux")["status"],
                         "TARGET_NOT_INCLUDED")
        self.assertEqual(mod.validate_pylock_graph(text, "3.12", "win32")["status"],
                         "PEP751_V1_WHEEL_GRAPH_VALIDATED_LOCAL_ONLY")

    def test_pylock_source_vcs_fails_closed(self):
        text = pylock_fixture().replace("version = '1.2.3'", "version = '1.2.3'\n[packages.vcs]\nurl='https://example.org/repo'", 1)
        self.assertEqual(mod.validate_pylock_graph(text, "3.12")["status"],
                         "UNSUPPORTED_NONWHEEL_SOURCE")

    def test_pylock_missing_marked_dependency_is_never_pass(self):
        text = pylock_fixture().replace("name = 'beta'\nversion = '2.0'\n[[packages.wheels]]",
                                       "name = 'beta'\nversion = '2.0'\nmarker = \"sys_platform == 'win32'\"\n[[packages.wheels]]")
        with self.assertRaisesRegex(ValueError, "dependency_missing_or_ambiguous"):
            mod.validate_pylock_graph(text, "3.12", "linux")

    def test_pylock_filename_is_a_safe_file_name(self):
        for filename in ("../pylock.toml", "pylock..toml", "pylock.toml.bak", "pylock.a/b.toml"):
            with self.assertRaisesRegex(ValueError, "invalid_pylock_filename"):
                mod.validate_pylock_graph(pylock_fixture(), "3.12", filename=filename)

    def test_pylock_invalid_marker_rejected(self):
        text = pylock_fixture().replace("version = '1.2.3'", "version = '1.2.3'\nmarker='unknown @ marker'", 1)
        with self.assertRaisesRegex(ValueError, "invalid_environment_marker"):
            mod.validate_pylock_graph(text, "3.12")

    def test_pylock_python_version_gate(self):
        text = pylock_fixture().replace("'>=3.9'", "'>=3.13'", 1)
        self.assertEqual(mod.validate_pylock_graph(text, "3.12")["status"],
                         "TARGET_NOT_INCLUDED")

    # F182: independently typed tool-lock graph adapters.
    def test_uv_tool_lock_import_with_exact_dependencies_and_hashes(self):
        result = mod.import_tool_lock("uv", uv_fixture())
        self.assertEqual(len(result["dependency_audit_edges"]), 1)
        self.assertEqual(result["packages"][0]["wheels"][0]["sha256"], DIGEST)
        self.assertFalse(result["installation_performed"])

    def test_poetry_tool_lock_import_with_exact_dependencies_and_hashes(self):
        result = mod.import_tool_lock("poetry", poetry_fixture())
        self.assertEqual(result["tool"], "poetry")
        self.assertEqual(len(result["dependency_audit_edges"]), 1)

    def test_pdm_tool_lock_import_with_exact_dependencies_and_hashes(self):
        result = mod.import_tool_lock("pdm", pdm_fixture())
        self.assertEqual(result["tool"], "pdm")
        self.assertEqual(len(result["dependency_audit_edges"]), 1)

    def test_tool_lock_missing_reference_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "dependency_missing"):
            mod.import_tool_lock("uv", uv_fixture().replace("version='2.0'", "version='9.9'", 1))

    def test_tool_lock_wrong_wheel_identity_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "wheel_identity_mismatch"):
            mod.import_tool_lock("pdm", pdm_fixture().replace(ALPHA_WHEEL, BETA_WHEEL, 1))

    def test_tool_lock_duplicate_package_identity_is_not_accepted(self):
        duplicate = ("[[package]]\nname='alpha'\nversion='1.2.3'\n"
                     "wheels=[{filename='" + ALPHA_WHEEL + "',hash='sha256:" + DIGEST + "'}]\n")
        with self.assertRaisesRegex(ValueError, "ambiguous_package_identity"):
            mod.import_tool_lock("uv", uv_fixture() + duplicate)

    def test_tool_lock_source_without_wheels_never_claims_success(self):
        text = uv_fixture().replace("wheels=[{filename='" + ALPHA_WHEEL + "', hash='sha256:" + DIGEST + "'}]", "wheels=[]")
        result = mod.import_tool_lock("uv", text)
        self.assertEqual(result["status"], "NONWHEEL_TOOL_SOURCE_NOT_AUDITED")

    def test_tool_lock_invalid_kind_and_toml(self):
        with self.assertRaises(ValueError):
            mod.import_tool_lock("unknown", uv_fixture())
        with self.assertRaisesRegex(ValueError, "invalid_toml"):
            mod.import_tool_lock("uv", "not valid = [")

    # F185: real local artifact bytes, VCS metadata and editable classification.
    def test_pep610_real_local_archive_sha256_positive(self):
        file = self.base / "package.whl"
        file.write_bytes(b"immutable trusted wheel fixture bytes")
        digest = hashlib.sha256(file.read_bytes()).hexdigest()
        data = json.dumps({"url": file.as_uri(), "archive_info": {"hashes": {"sha256": digest}}})
        result = mod.inspect_direct_url(data, file)
        self.assertEqual(result["status"], "LOCAL_ARCHIVE_BYTES_VERIFIED")
        self.assertTrue(result["artifact_authenticated"])
        self.assertFalse(result["publisher_identity_authenticated"])

    def test_pep610_mismatched_archive_hash_fails_closed(self):
        file = self.base / "package.whl"
        file.write_bytes(b"modified")
        data = json.dumps({"url": file.as_uri(), "archive_info": {"hashes": {"sha256": DIGEST}}})
        with self.assertRaisesRegex(ValueError, "archive_sha256_mismatch"):
            mod.inspect_direct_url(data, file)

    def test_pep610_mismatched_declared_file_url_fails_closed(self):
        recorded = self.base / "recorded.whl"
        actual = self.base / "actual.whl"
        recorded.write_bytes(b"one")
        actual.write_bytes(b"two")
        data = json.dumps({"url": recorded.as_uri(), "archive_info": {"hashes":
                           {"sha256": hashlib.sha256(actual.read_bytes()).hexdigest()}}})
        with self.assertRaisesRegex(ValueError, "supplied_artifact_differs"):
            mod.inspect_direct_url(data, actual)

    def test_pep610_unfetched_archive_never_claims_verified_bytes(self):
        file = self.base / "package.whl"
        file.write_bytes(b"not supplied to verifier")
        data = json.dumps({"url": file.as_uri(), "archive_info": {"hashes": {"sha256": DIGEST}}})
        report = mod.inspect_direct_url(data)
        self.assertEqual(report["status"], "ARCHIVE_PIN_DECLARED_BYTES_NOT_VERIFIED")
        self.assertFalse(report["artifact_authenticated"])

    def test_pep610_git_commit_metadata_is_not_publisher_attestation(self):
        data = json.dumps({"url": "https://code.example/repo.git", "vcs_info":
                           {"vcs": "git", "requested_revision": "main", "commit_id": "a" * 40}})
        result = mod.inspect_direct_url(data)
        self.assertEqual(result["status"], "VCS_COMMIT_METADATA_VALIDATED_BUT_UNATTESTED")
        self.assertFalse(result["publisher_identity_authenticated"])

    def test_pep610_git_tag_only_and_credentials_rejected(self):
        for data in (
                {"url": "https://example.org/repo", "vcs_info": {"vcs": "git", "commit_id": "v1"}},
                {"url": "https://username:secret@example.org/repo", "vcs_info": {"vcs": "git", "commit_id": "a" * 40}},
                {"url": "https://example.org/repo?token=SECRET", "vcs_info": {"vcs": "git", "commit_id": "a" * 40}}):
            with self.assertRaises(ValueError):
                mod.inspect_direct_url(json.dumps(data))

    def test_pep610_actual_editable_local_directory_only(self):
        data = json.dumps({"url": self.base.as_uri(), "dir_info": {"editable": True}})
        result = mod.inspect_direct_url(data)
        self.assertEqual(result["status"], "LOCAL_EDITABLE_ORIGIN_CLASSIFIED")
        self.assertTrue(result["editable"])
        self.assertFalse(result["location_disclosed"])

    def test_pep610_editable_nonexistent_directory_fails_closed(self):
        location = self.base / "missing-editable-project"
        data = json.dumps({"url": location.as_uri(), "dir_info": {"editable": True}})
        with self.assertRaisesRegex(ValueError, "local_directory_missing"):
            mod.inspect_direct_url(data)

    @unittest.skipUnless(os.name == "nt", "Windows local-drive URI contract")
    def test_windows_file_uri_roundtrip_spaces_and_reject_alias_encodings(self):
        file = self.base / "package space.whl"
        file.write_bytes(b"fixed wheel bytes")
        digest = hashlib.sha256(file.read_bytes()).hexdigest()
        def record(uri):
            return json.dumps({"url": uri, "archive_info": {"hashes": {"sha256": digest}}})
        result = mod.inspect_direct_url(record(file.as_uri()), file)
        self.assertTrue(result["artifact_authenticated"])
        drive = self.base.drive[0]
        for uri in ("file://server/share/x.whl", "file:////server/share/x.whl",
                    "file:///" + drive + ":/x.whl%3Astream",
                    "file:///" + drive + ":/dir%2Fx.whl",
                    "file:///" + drive + ":/dir%5Cx.whl",
                    "file:///" + drive + ":/x%00.whl"):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                mod.inspect_direct_url(record(uri), file)

    def test_pep610_multiple_kinds_duplicate_keys_and_unsafe_subdirectory(self):
        with self.assertRaisesRegex(ValueError, "exactly_one_origin"):
            mod.inspect_direct_url(json.dumps({"url": self.base.as_uri(), "dir_info": {}, "archive_info": {}}))
        with self.assertRaisesRegex(ValueError, "invalid_direct_url"):
            mod.inspect_direct_url('{"url":"file:///x","url":"file:///y","dir_info":{}}')
        with self.assertRaisesRegex(ValueError, "unsafe_source_path"):
            mod.inspect_direct_url(json.dumps({"url": self.base.as_uri(), "dir_info": {}, "subdirectory": "../escape"}))

    def test_pep610_symlinked_archive_source_refused(self):
        base = self.base / "base.whl"
        base.write_bytes(b"fixture")
        link = self.base / "outside.whl"
        link.symlink_to(base)
        data = json.dumps({"url": link.as_uri(), "archive_info": {"hashes":
                           {"sha256": hashlib.sha256(base.read_bytes()).hexdigest()}}})
        with self.assertRaisesRegex(ValueError, "unsafe_file_url_target"):
            mod.inspect_direct_url(data, link)

    # F186: marker and venv state must fail closed without pip.
    def test_managed_base_interpreter_real_marker_forces_denial(self):
        marker = self.base / "EXTERNALLY-MANAGED"
        marker.write_text("[externally-managed]\nError=System managed\n")
        report = mod.externally_managed_guard("/usr/local/python", "/usr/local/python", str(self.base))
        self.assertEqual(report["status"], "EXTERNALLY_MANAGED_DENIED")
        self.assertFalse(report["global_install_allowed"])
        self.assertFalse(report["pip_executed"])

    def test_managed_virtual_env_private_target_preflight_only(self):
        (self.base / "EXTERNALLY-MANAGED").write_text("managed")
        private = self.base / "install-target"
        private.mkdir(mode=0o700)
        if os.name == "nt":
            from windows_privacy_fixtures import set_private_acl
            set_private_acl(private)
        report = mod.externally_managed_guard("/private/venv", "/usr/python", str(self.base), private)
        self.assertEqual(report["status"], "VENV_PRIVATE_TARGET_ALLOWED")
        self.assertFalse(report["system_packages_mutated"])

    def test_managed_public_target_denied(self):
        private = self.base / "bad-target"
        private.mkdir(mode=0o755)
        if os.name == "nt":
            from windows_privacy_fixtures import set_public_read_acl
            set_public_read_acl(private)
        report = mod.externally_managed_guard("/private/venv", "/usr/python", str(self.base), private)
        self.assertEqual(report["status"], "INSTALL_NOT_AUTHORIZED")

    def test_managed_symlinked_marker_denied(self):
        original = self.base / "origin"
        original.write_text("managed")
        (self.base / "EXTERNALLY-MANAGED").symlink_to(original)
        with self.assertRaisesRegex(ValueError, "unsafe_managed"):
            mod.externally_managed_guard("/opt/a", "/opt/a", str(self.base))

    def test_managed_hardlinked_marker_denied(self):
        original = self.base / "origin"
        original.write_text("managed")
        os.link(original, self.base / "EXTERNALLY-MANAGED")
        with self.assertRaisesRegex(ValueError, "unsafe_managed"):
            mod.externally_managed_guard("/opt/a", "/opt/a", str(self.base))

    def test_cli_capabilities_no_unknown_input_and_json(self):
        proc = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)],
                              capture_output=True, check=False, timeout=8)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["status"], "READ_ONLY_PACKAGE_POLICY_AVAILABLE")
        self.assertFalse(report["user_code_executed"])

    def test_cli_pylock_graph_from_real_file(self):
        lock = self.base / "pylock.toml"
        lock.write_text(pylock_fixture())
        proc = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT),
                               "--mode", "pylock", "--path", str(lock),
                               "--python-version", "3.12"],
                              capture_output=True, check=False, timeout=8)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["status"],
                         "PEP751_V1_WHEEL_GRAPH_VALIDATED_LOCAL_ONLY")

    def test_cli_missing_input_fails_closed(self):
        proc = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                               "--mode", "pylock"],
                              capture_output=True, check=False, timeout=8)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(proc.stdout)["status"], "REFUSED")


if __name__ == "__main__":
    unittest.main()
