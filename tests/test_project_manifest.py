"""Static project manifest checks across CPython 3.9 through current."""

import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("project_manifest", ROOT / "python" / "project_manifest.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


class ProjectManifestTests(unittest.TestCase):
    def test_manifest_hash_preserves_actual_lf_and_crlf_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "pyproject.toml"
            digests = []
            for newline in (b"\n", b"\r\n"):
                raw = newline.join((b"[project]", b'name = "fixed-fixture"', b""))
                path.write_bytes(raw)
                report = module.inspect(folder)
                observed = report["manifests"][0]["sha256"]
                self.assertEqual(observed, hashlib.sha256(raw).hexdigest())
                self.assertEqual(report["manifests"][0]["size_bytes"], len(raw))
                digests.append(observed)
            self.assertNotEqual(*digests)

    def test_pep735_groups_extras_build_requirements_are_structured_not_installed(self):
        with tempfile.TemporaryDirectory() as folder:
            source = ('[project]\nname = "example"\n'
                      '[project.optional-dependencies]\nPDF = ["pypdf>=4"]\n'
                      'test = ["pytest>=8", "coverage"]\n'
                      '[dependency-groups]\n'
                      'coverage = ["coverage[toml]"]\n'
                      'test = ["pytest>7", {include-group = "coverage"}]\n'
                      'all = [{include-group = "test"}, "ruff"]\n'
                      '[build-system]\nrequires = ["setuptools>=68", "wheel"]\n'
                      'build-backend = "malicious.module:builder"\n')
            (Path(folder) / "pyproject.toml").write_text(source)
            result = module.inspect(folder)
            parsed = result["pyproject"]
            self.assertFalse(result["source_executed"])
            self.assertEqual(result["dependency_resolution"], "NOT_RUN")
            if sys.version_info < (3, 11):
                self.assertEqual(parsed["status"], "PARTIAL")
                self.assertEqual(parsed["dependency_groups"], "NOT_RUN")
                self.assertEqual(parsed["optional_dependencies"], "NOT_RUN")
                self.assertEqual(parsed["build_requires"], "NOT_RUN")
            else:
                self.assertEqual(parsed["status"], "INSPECTED_NOT_RESOLVED")
                self.assertEqual(parsed["build_requires_count"], 2)
                self.assertEqual(parsed["optional_dependencies"], [
                    {"name": "pdf", "direct_requirements": 1},
                    {"name": "test", "direct_requirements": 2},
                ])
                groups = {r["name"]: r for r in parsed["dependency_groups"]}
                self.assertEqual(groups["coverage"]["expanded_requirements_count"], 1)
                self.assertEqual(groups["test"]["expanded_requirements_count"], 2)
                self.assertEqual(groups["all"]["expanded_requirements_count"], 3)
                self.assertEqual(groups["all"]["includes"], ["test"])
                self.assertEqual(parsed["requirements_syntax"], "NOT_VERIFIED")
                self.assertFalse(parsed["dependency_versions_resolved"])
                self.assertFalse(parsed["build_backend_executed"])

    def test_normalized_extra_and_group_collisions_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            pyproject = Path(folder) / "pyproject.toml"
            pyproject.write_text('[project.optional-dependencies]\nPDF = ["one"]\np_d_f = ["two"]\n')
            # p_d_f normalizes to p-d-f, not pdf: different identifiers.
            result = module.inspect(folder)["pyproject"]
            self.assertEqual(result["status"], "PARTIAL" if sys.version_info < (3, 11)
                             else "INSPECTED_NOT_RESOLVED")
            pyproject.write_text('[project.optional-dependencies]\nfoo_bar = ["one"]\nfoo-bar = ["two"]\n')
            result = module.inspect(folder)["pyproject"]
            if sys.version_info >= (3, 11):
                self.assertEqual(result["status"], "INVALID_STRUCTURE")
                self.assertEqual(result["reason"], "duplicate_normalized_extra")
            else:
                self.assertEqual(result["status"], "PARTIAL")
            pyproject.write_text('[dependency-groups]\nfoo_bar = ["one"]\n"foo.bar" = ["two"]\n')
            result = module.inspect(folder)["pyproject"]
            if sys.version_info >= (3, 11):
                self.assertEqual(result["status"], "INVALID_STRUCTURE")
                self.assertEqual(result["reason"], "duplicate_normalized_dependency_group")
            else:
                self.assertEqual(result["status"], "PARTIAL")

    def test_cycle_and_unknown_group_includes_never_count_as_resolved(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "pyproject.toml"
            for source, reason in (
                ('[dependency-groups]\na = [{include-group = "b"}]\nb = [{include-group = "a"}]\n',
                 "dependency_group_include_cycle"),
                ('[dependency-groups]\na = [{include-group = "missing"}]\n',
                 "dependency_group_include_unknown"),
                ('[dependency-groups]\na = [{unexpected = "b"}]\n',
                 "invalid_dependency_group_entry"),
            ):
                target.write_text(source)
                result = module.inspect(folder)["pyproject"]
                if sys.version_info < (3, 11):
                    self.assertEqual(result["status"], "PARTIAL")
                else:
                    self.assertEqual(result["status"], "INVALID_STRUCTURE")
                    self.assertEqual(result["reason"], reason)

    def test_group_and_build_lists_obey_quotas_and_never_execute_code(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "pyproject.toml"
            marker = Path(folder) / "not_run"
            poison = '__import__("pathlib").Path({!r}).write_text("BAD")'.format(str(marker))
            target.write_text('[dependency-groups]\nrun = [{include-group = "bad", execute = ' +
                              json.dumps(poison) + '}]\n')
            result = module.inspect(folder)["pyproject"]
            if sys.version_info >= (3, 11):
                self.assertEqual(result["status"], "INVALID_STRUCTURE")
                self.assertNotIn(poison, json.dumps(result))
            else:
                self.assertEqual(result["status"], "PARTIAL")
            self.assertFalse(marker.exists())
            target.write_text('[build-system]\nrequires = [' + ','.join('"x"' for _ in range(201)) + ']\n')
            result = module.inspect(folder)["pyproject"]
            self.assertEqual(result["status"], "PARTIAL" if sys.version_info < (3, 11)
                             else "INVALID_STRUCTURE")

    def test_direct_group_counter_does_not_run_setup_or_resolve_requirements(self):
        project = {"optional-dependencies": {"PDF": ["doc>=1"]}, "dynamic": []}
        build = {"requires": ["hatchling", "wheel"]}
        parsed = {"dependency-groups": {
            "coverage": ["coverage"],
            "test": ["pytest", {"include-group": "coverage"}],
        }}
        result = module.dependency_sections(project, build, parsed)
        self.assertEqual(result["build_requires_count"], 2)
        self.assertEqual(result["optional_dependencies"][0]["name"], "pdf")
        self.assertEqual(result["dependency_groups"][1]["expanded_requirements_count"], 2)
        self.assertEqual(result["requirements_syntax"], "NOT_VERIFIED")
        self.assertFalse(result["dependency_versions_resolved"])

    def test_invalid_extra_name_does_not_leak_or_guess(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "pyproject.toml"
            target.write_text('[project.optional-dependencies]\n"../secrets" = ["oops"]\n')
            result = module.inspect(folder)["pyproject"]
            if sys.version_info >= (3, 11):
                self.assertEqual(result["status"], "INVALID_STRUCTURE")
                self.assertEqual(result["reason"], "invalid_dependency_group_name")
            else:
                self.assertEqual(result["status"], "PARTIAL")
            self.assertNotIn("../secrets", json.dumps(result))

    def test_dynamic_fields_do_not_override_static_dependency_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "pyproject.toml"
            for source in (
                '[project]\ndynamic = ["dependencies"]\ndependencies = ["opaque"]\n',
                '[project]\ndynamic = ["optional-dependencies"]\n'
                '[project.optional-dependencies]\nfoo = ["opaque"]\n',
            ):
                target.write_text(source)
                parsed = module.inspect(folder)["pyproject"]
                if sys.version_info < (3, 11):
                    self.assertEqual(parsed["status"], "PARTIAL")
                else:
                    self.assertEqual(parsed["status"], "INVALID_STRUCTURE")
                    self.assertEqual(parsed["reason"],
                                     "static_and_dynamic_dependency_conflict")
            target.write_text('[project]\ndynamic = ["optional-dependencies"]\n')
            parsed = module.inspect(folder)["pyproject"]
            if sys.version_info >= (3, 11):
                self.assertEqual(parsed["status"], "INSPECTED_NOT_RESOLVED")
                self.assertTrue(parsed["optional_dependencies_dynamic"])
                self.assertEqual(parsed["optional_dependencies"], [])
                self.assertFalse(parsed["dependency_versions_resolved"])
            else:
                self.assertEqual(parsed["optional_dependencies"], "NOT_RUN")

    def test_transitive_group_expansion_and_include_depth_are_bounded(self):
        many = {"base": ["package"] * 200,
                "all": [{"include-group": "base"}] * 26}
        with self.assertRaisesRegex(ValueError, "dependency_group_expansion_limit"):
            module.dependency_sections({}, {}, {"dependency-groups": many})

        deep = {"group%d" % index: [{"include-group": "group%d" % (index + 1)}]
                for index in range(33)}
        deep["group33"] = ["package"]
        with self.assertRaisesRegex(ValueError, "dependency_group_include_too_deep"):
            module.dependency_sections({}, {}, {"dependency-groups": deep})

    def test_raw_requirement_strings_are_never_reflected_in_reports(self):
        secret = "my-private-token-1234567890"
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "pyproject.toml"
            target.write_text('[project]\n'
                              'dependencies = ["pkg @ https://example.test/{}"]\n'
                              '[project.optional-dependencies]\n'
                              'security = ["package[{}]"]\n'
                              '[dependency-groups]\n'
                              'dev = ["private=={}"]\n'
                              '[build-system]\n'
                              'requires = ["builder=={}"]\n'.format(*([secret] * 4)))
            parsed = module.inspect(folder)["pyproject"]
            self.assertNotIn(secret, json.dumps(parsed))
            if sys.version_info >= (3, 11):
                self.assertEqual(parsed["status"], "INSPECTED_NOT_RESOLVED")
                self.assertEqual(parsed["dependency_count"], 1)
                self.assertEqual(parsed["optional_dependencies"][0]["direct_requirements"], 1)
                self.assertEqual(parsed["dependency_groups"][0]["expanded_requirements_count"], 1)
                self.assertEqual(parsed["build_requires_count"], 1)
            else:
                self.assertEqual(parsed["status"], "PARTIAL")

    def test_missing_manifest_never_claims_success(self):
        with tempfile.TemporaryDirectory() as folder:
            result = module.inspect(folder)
            self.assertEqual(result["status"], "NOT_FOUND")
            self.assertEqual(result["files_present"], 0)
            self.assertEqual(result["dependency_resolution"], "NOT_RUN")

    def test_pyproject_summary_is_bounded_and_never_resolves_dependencies(self):
        with tempfile.TemporaryDirectory() as folder:
            source = '[project]\nname = "safe-package"\nversion = "1.0"\nrequires-python = ">=3.9"\ndependencies = ["requests>=2"]\n[build-system]\nbuild-backend = "malicious.plugin:build"\n'
            (Path(folder) / "pyproject.toml").write_text(source, encoding="utf-8")
            result = module.inspect(folder)
            self.assertEqual(result["status"], "INSPECTED_PARTIAL")
            self.assertEqual(result["manifests"][0]["sha256"],
                             hashlib.sha256((Path(folder) / "pyproject.toml").read_bytes()).hexdigest())
            self.assertFalse(result["source_executed"])
            self.assertFalse(result["install_performed"])
            if sys.version_info >= (3, 11):
                parsed = result["pyproject"]
                self.assertEqual(parsed["status"], "INSPECTED_NOT_RESOLVED")
                self.assertEqual(parsed["name"], "safe-package")
                self.assertEqual(parsed["dependency_count"], 1)
                self.assertFalse(parsed["build_backend_executed"])
            else:
                self.assertEqual(result["pyproject"]["status"], "PARTIAL")
                self.assertEqual(result["pyproject"]["name_candidate"], "safe-package")
                self.assertEqual(result["pyproject"]["dependencies"], "NOT_RUN")

    def test_lockfiles_are_hashed_but_never_verified(self):
        with tempfile.TemporaryDirectory() as folder:
            for name in ("Pipfile.lock", "poetry.lock", "uv.lock", "pylock.toml", "setup.py"):
                (Path(folder) / name).write_text("import os; os.system('bad')" if name == "setup.py" else "lock payload")
            result = module.inspect(folder)
            self.assertEqual(result["files_present"], 5)
            self.assertEqual(result["lockfile_verification"], "NOT_RUN")
            self.assertTrue(all(item["status"] == "HASHED_NOT_VERIFIED" for item in result["manifests"]))
            self.assertTrue(all(item["content_executed"] is False for item in result["manifests"]))

    def test_symlinked_manifest_is_refused_and_outside_data_not_read(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            child = root / "project"
            child.mkdir()
            outside = root / "outside"
            outside.write_text("sensitive password")
            (child / "pyproject.toml").symlink_to(outside)
            result = module.inspect(child)
            self.assertEqual(result["pyproject"]["status"], "REFUSED_SYMLINK")
            self.assertEqual(result["manifests"][0]["status"], "REFUSED_SYMLINK")
            self.assertNotIn("password", json.dumps(result))

    def test_symlink_project_root_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "project"
            source.mkdir()
            link = root / "link"
            link.symlink_to(source, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink_project_root_refused"):
                module.inspect(link)

    def test_oversized_manifest_is_rejected_before_parsing(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "pyproject.toml").write_bytes(b"x" * (module.MAX_FILE_BYTES + 1))
            result = module.inspect(folder)
            self.assertEqual(result["pyproject"]["status"], "TOO_LARGE")
            self.assertEqual(result["manifests"][0]["status"], "TOO_LARGE")

    def test_secondary_toml_parser_budget_is_independent_of_file_budget(self):
        with tempfile.TemporaryDirectory() as folder:
            content = b"#" * (module.MAX_TOML_BYTES + 1)
            (Path(folder) / "pyproject.toml").write_bytes(content)
            result = module.inspect(folder)
            self.assertEqual(result["manifests"][0]["status"], "HASHED_NOT_VERIFIED")
            self.assertEqual(result["pyproject"]["status"], "TOO_LARGE")
            self.assertEqual(result["pyproject"]["reason"], "toml_limit_256k")

    def test_invalid_utf8_is_rejected_before_toml_interpretation(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "pyproject.toml").write_bytes(b"[project]\nname = \"\xff\"\n")
            result = module.inspect(folder)
            self.assertEqual(result["pyproject"]["status"], "INVALID_UTF8")
            self.assertEqual(result["dependency_resolution"], "NOT_RUN")

    def test_command_line_executes_only_embedded_helper(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            marker = root / "never_run"
            (root / "setup.py").write_text("from pathlib import Path\nPath({!r}).write_text('bad')\n".format(str(marker)))
            tool = (ROOT / "python" / "project_manifest.py").read_text(encoding="utf-8")
            proc = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", tool, str(root)],
                                  capture_output=True, text=True, timeout=10, check=True)
            result = json.loads(proc.stdout)
            self.assertEqual(result["files_present"], 1)
            self.assertFalse(result["source_executed"])
            self.assertFalse(marker.exists())

    def test_malformed_toml_has_no_false_validated_status(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "pyproject.toml").write_text('[project]\nname = "alpha"\nname = "beta"\n')
            result = module.inspect(folder)
            self.assertNotEqual(result["pyproject"]["status"], "INSPECTED_NOT_RESOLVED")
            self.assertNotIn("name", result["pyproject"])


if __name__ == "__main__":
    unittest.main()
