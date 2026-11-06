"""Independent exhaustive oracle for bounded local transitive resolution."""

from importlib.util import module_from_spec, spec_from_file_location
import itertools
import json
import os
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "python" / "transitive_resolver.py"
spec = spec_from_file_location("transitive_resolver", MODULE)
resolver = module_from_spec(spec)
spec.loader.exec_module(resolver)


def oracle_match(value, text):
    """Intentionally separate version parser and comparison from solver code."""
    if not text.strip():
        return True

    def comparable(value):
        bits = tuple(map(int, value.split("."))) if isinstance(value, str) else value
        return bits + (0,) * (6 - len(bits))

    own = comparable(value)
    for clause in text.split(","):
        match = re.fullmatch(r"\s*(==|!=|>=|<=|>|<|~=)\s*([0-9.]+)\s*", clause)
        assert match, text
        op, version = match.groups()
        requested = comparable(version)
        result = {
            "==": own == requested, "!=": own != requested,
            ">=": own >= requested, "<=": own <= requested,
            ">": own > requested, "<": own < requested,
        }
        if op == "~=":
            components = tuple(map(int, version.split(".")))
            top = components[:-1]
            top = top[:-1] + (top[-1] + 1,)
            result[op] = own >= requested and own < comparable(top)
        if not result[op]:
            return False
    return True


def oracle_assignment_valid(catalog, roots, assignment, python_version):
    """Evaluate a complete Cartesian-product assignment independently."""
    required = {}
    extras = {}
    for req in roots:
        if oracle_match(python_version, req.get("python", "")):
            required.setdefault(req["name"], []).append(req.get("specifier", ""))
            extras.setdefault(req["name"], set()).update(req.get("extras", []))
    fired = set()
    while True:
        changed = False
        for name in sorted(required):
            if name not in assignment:
                return False
            candidate = assignment[name]
            if not oracle_match(python_version, candidate.get("requires_python", "")):
                return False
            for index, req in enumerate(candidate.get("requires", [])):
                key = (name, index)
                if key in fired:
                    continue
                if req.get("when_extras") and not set(req["when_extras"]).intersection(extras.get(name, set())):
                    continue
                if not oracle_match(python_version, req.get("python", "")):
                    continue
                fired.add(key)
                required.setdefault(req["name"], []).append(req.get("specifier", ""))
                extras.setdefault(req["name"], set()).update(req.get("extras", []))
                changed = True
        if not changed:
            break
    return all(all(oracle_match(assignment[name]["version"], clause) for clause in clauses)
               for name, clauses in required.items())


def exhaustive_oracle(catalog, roots, python_version):
    packages = sorted(catalog)
    possible = itertools.product(*(catalog[name] for name in packages))
    for choices in possible:
        assignment = dict(zip(packages, choices))
        if oracle_assignment_valid(catalog, roots, assignment, python_version):
            return True
    return False


class ResolverTests(unittest.TestCase):
    def test_exact_simple_transitive_solution(self):
        catalog = {
            "a": [{"version": "1.0", "requires": [{"name": "b", "specifier": ">=2"}]}],
            "b": [{"version": "1.0"}, {"version": "2.0"}],
        }
        report = resolver.resolve(catalog, [{"name": "a"}])
        self.assertEqual(report["status"], "SATISFIABLE_IN_LOCAL_FINAL_RELEASE_CATALOG")
        self.assertEqual(report["assignment"], {"a": "1.0", "b": "2.0"})
        self.assertFalse(report["installed_packages"])
        self.assertFalse(report["network_used"])

    def test_conflicting_transitive_witness(self):
        catalog = {
            "app": [{"version": "1", "requires": [{"name": "dep", "specifier": ">=2"},
                                                      {"name": "lib", "specifier": "==1"}]}],
            "lib": [{"version": "1", "requires": [{"name": "dep", "specifier": "<2"}]}],
            "dep": [{"version": "1"}, {"version": "2"}],
        }
        result = resolver.resolve(catalog, [{"name": "app"}])
        self.assertEqual(result["status"], "CONFLICT_PROVEN_IN_EXPLICIT_LOCAL_CATALOG")
        witness = result["conflict_witness"]
        self.assertEqual(witness["package"], "dep")
        self.assertEqual({row["specifier"] for row in witness["requirements"]}, {">=2", "<2"})

    def test_mutual_cyclic_dependencies_terminate_with_solution(self):
        catalog = {
            "a": [{"version": "1.0", "requires": [{"name": "b", "specifier": ">=1"}]}],
            "b": [{"version": "1.0", "requires": [{"name": "a", "specifier": "==1"}]}],
        }
        report = resolver.resolve(catalog, [{"name": "a"}])
        self.assertEqual(report["status"], "SATISFIABLE_IN_LOCAL_FINAL_RELEASE_CATALOG")
        self.assertEqual(set(report["assignment"]), {"a", "b"})
        self.assertLess(report["states_explored"], 10)

    def test_self_dependency_conflict_is_a_real_unsat(self):
        catalog = {"a": [{"version": "1", "requires": [{"name": "a", "specifier": ">1"}]}]}
        result = resolver.resolve(catalog, [{"name": "a"}])
        self.assertEqual(result["status"], "CONFLICT_PROVEN_IN_EXPLICIT_LOCAL_CATALOG")

    def test_backtracking_downgrades_conflicting_latest_candidate(self):
        catalog = {
            "app": [{"version": "2", "requires": [{"name": "missing", "specifier": ">=2"}]},
                    {"version": "1", "requires": [{"name": "existing", "specifier": ">=1"}]}],
            "existing": [{"version": "1"}], "missing": [{"version": "1"}],
        }
        report = resolver.resolve(catalog, [{"name": "app"}])
        self.assertEqual(report["assignment"]["app"], "1")

    def test_extras_activation_can_propagate_after_package_selection(self):
        catalog = {
            "a": [{"version": "1", "requires": [{"name": "b"}, {"name": "c"}]}],
            "b": [{"version": "1", "requires": [{"name": "d", "specifier": ">=2",
                                                      "when_extras": ["fast"]}]}],
            "c": [{"version": "1", "requires": [{"name": "b", "extras": ["fast"]}]}],
            "d": [{"version": "1"}, {"version": "2"}],
        }
        report = resolver.resolve(catalog, [{"name": "a"}])
        self.assertEqual(report["assignment"]["d"], "2")
        self.assertEqual(report["status"], "SATISFIABLE_IN_LOCAL_FINAL_RELEASE_CATALOG")

    def test_unrequested_extras_do_not_activate_dependency(self):
        catalog = {"a": [{"version": "1", "requires": [{"name": "missing", "when_extras": ["fast"]}]}]}
        result = resolver.resolve(catalog, [{"name": "a"}])
        self.assertEqual(result["assignment"], {"a": "1"})

    def test_root_extras_activate_optional_dependency(self):
        catalog = {"a": [{"version": "1", "requires": [{"name": "b", "when_extras": ["fast"]}]}],
                   "b": [{"version": "1"}]}
        report = resolver.resolve(catalog, [{"name": "a", "extras": ["fast"]}])
        self.assertEqual(set(report["assignment"]), {"a", "b"})

    def test_python_version_filter_on_candidate_versions(self):
        catalog = {"a": [{"version": "2", "requires_python": ">=3.12"},
                         {"version": "1", "requires_python": "<3.12"}]}
        self.assertEqual(resolver.resolve(catalog, [{"name": "a"}], "3.9")["assignment"]["a"], "1")
        self.assertEqual(resolver.resolve(catalog, [{"name": "a"}], "3.15")["assignment"]["a"], "2")

    def test_python_conditional_dependency_edges(self):
        catalog = {"a": [{"version": "1", "requires": [{"name": "b", "python": ">=3.12"}]}],
                   "b": [{"version": "1"}]}
        self.assertEqual(set(resolver.resolve(catalog, [{"name": "a"}], "3.9")["assignment"]), {"a"})
        self.assertEqual(set(resolver.resolve(catalog, [{"name": "a"}], "3.15")["assignment"]), {"a", "b"})

    def test_compatible_release_and_padded_equality(self):
        self.assertTrue(resolver.satisfies((1, 4, 5), resolver.clauses("~=1.4")))
        self.assertFalse(resolver.satisfies((2, 0), resolver.clauses("~=1.4")))
        self.assertTrue(resolver.satisfies((1, 4, 9), resolver.clauses("~=1.4.2")))
        self.assertFalse(resolver.satisfies((1, 5), resolver.clauses("~=1.4.2")))
        self.assertTrue(resolver.satisfies((1,), resolver.clauses("==1.0.0")))

    def test_missing_catalog_is_unknown_not_conflict(self):
        catalog = {"a": [{"version": "1", "requires": [{"name": "unlisted"}]}]}
        result = resolver.resolve(catalog, [{"name": "a"}])
        self.assertEqual(result["status"], "UNKNOWN_MISSING_LOCAL_CANDIDATES")
        self.assertTrue(result["conflict_witness"]["missing_candidate_catalog"])

    def test_unknown_on_unrecognized_prerelease_epoch_local_and_wildcards(self):
        bad = ["1.0rc1", "1.0.dev1", "1.0+local", "1!2.0", "1.0.post1"]
        for version in bad:
            result = resolver.resolve({"a": [{"version": version}]}, [{"name": "a"}])
            self.assertEqual(result["status"], "UNKNOWN_UNSUPPORTED_INPUT", version)
        for constraint in ("==1.*", ">=1.0rc1", "~=1", "===1.0", "!=1.0+local"):
            result = resolver.resolve({"a": [{"version": "1"}]},
                                      [{"name": "a", "specifier": constraint}])
            self.assertEqual(result["status"], "UNKNOWN_UNSUPPORTED_INPUT", constraint)

    def test_canonical_collisions_and_duplicate_version_are_unknown(self):
        self.assertEqual(resolver.resolve({"A_B": [{"version": "1"}], "a-b": [{"version": "2"}]},
                                          [{"name": "a-b"}])["status"], "UNKNOWN_UNSUPPORTED_INPUT")
        self.assertEqual(resolver.resolve({"a": [{"version": "1"}, {"version": "1.0"}]},
                                          [{"name": "a"}])["status"], "UNKNOWN_UNSUPPORTED_INPUT")

    def test_conflict_only_after_all_candidate_branches_exhausted(self):
        catalog = {"a": [{"version": "3", "requires": [{"name": "b", "specifier": ">=3"}]},
                         {"version": "2", "requires": [{"name": "b", "specifier": ">=2"}]}],
                   "b": [{"version": "1"}]}
        report = resolver.resolve(catalog, [{"name": "a"}])
        self.assertEqual(report["status"], "CONFLICT_PROVEN_IN_EXPLICIT_LOCAL_CATALOG")
        self.assertGreater(report["states_explored"], 2)

    def test_search_budget_exhaustion_is_not_a_pass_or_proven_conflict(self):
        catalog = {"a": [{"version": "1"}]}
        report = resolver.resolve(catalog, [{"name": "a"}], max_states=1)
        self.assertEqual(report["status"], "NOT_RUN_BUDGET_EXHAUSTED")
        self.assertFalse(report["environment_installability_proven"])

    def test_branch_with_unknown_cannot_be_reported_proven_unsat(self):
        catalog = {"a": [{"version": "2", "requires": [{"name": "unlisted"}]},
                         {"version": "1", "requires": [{"name": "b", "specifier": ">2"}]}],
                   "b": [{"version": "1"}]}
        report = resolver.resolve(catalog, [{"name": "a"}])
        self.assertEqual(report["status"], "UNKNOWN_MISSING_LOCAL_CANDIDATES")

    def test_deterministic_result_across_runs(self):
        catalog = {"a": [{"version": "1", "requires": [{"name": "b"}]}],
                   "b": [{"version": "1"}, {"version": "2"}]}
        reports = [resolver.resolve(catalog, [{"name": "a"}], "3.12") for _ in range(4)]
        self.assertTrue(all(reports[0] == report for report in reports))

    def test_independent_exhaustive_oracle_on_random_small_graphs(self):
        randomizer = random.Random(0xF059)
        runtime = "3.{}".format(sys.version_info.minor)
        clauses = ("", ">=1", ">=2", "<=1", "<3", "!=2", "==1.0", "~=1.1")
        py = ("", ">=3.10", "<3.11", ">=3.14")
        for trial in range(130):
            names = ["p{}".format(i) for i in range(randomizer.randrange(2, 6))]
            catalog = {}
            for name in names:
                candidates = []
                for v in range(1, randomizer.randrange(2, 4)):
                    reqs = []
                    for _ in range(randomizer.randrange(0, 4)):
                        req = {"name": randomizer.choice(names),
                               "specifier": randomizer.choice(clauses),
                               "python": randomizer.choice(py)}
                        if randomizer.randrange(4) == 0:
                            req["when_extras"] = ["fast"]
                        if randomizer.randrange(5) == 0:
                            req["extras"] = ["fast"]
                        reqs.append(req)
                    candidates.append({"version": "{}.{}".format(v, randomizer.randrange(0, 4)),
                                       "requires_python": randomizer.choice(py), "requires": reqs})
                catalog[name] = candidates
            roots = [{"name": names[0], "extras": ["fast"] if randomizer.randrange(2) else [],
                      "specifier": randomizer.choice(clauses)}]
            expected = exhaustive_oracle(catalog, roots, runtime)
            actual = resolver.resolve(catalog, roots, runtime, max_states=5000)
            with self.subTest(trial=trial, runtime=runtime):
                self.assertEqual(actual["status"] == "SATISFIABLE_IN_LOCAL_FINAL_RELEASE_CATALOG",
                                 expected, actual)
                self.assertNotEqual(actual["status"], "UNKNOWN_UNSUPPORTED_INPUT")
                self.assertNotEqual(actual["status"], "NOT_RUN_BUDGET_EXHAUSTED")
                if expected:
                    assignment = {name: next(item for item in catalog[name]
                                             if item["version"] == value)
                                  for name, value in actual["assignment"].items()}
                    # Complete with arbitrary candidates for unrelated packages.
                    assignment.update({name: catalog[name][0] for name in catalog if name not in assignment})
                    self.assertTrue(oracle_assignment_valid(catalog, roots, assignment, runtime))

    def test_versioned_cli_json_matches_live_interpreter(self):
        with tempfile.TemporaryDirectory() as root:
            filename = Path(root) / "catalog.json"
            filename.write_text(json.dumps({"catalog": {"a": [{"version": "1"}]},
                                            "roots": [{"name": "a"}]}), encoding="utf-8")
            process = subprocess.run([sys.executable, "-I", "-S", "-B", str(MODULE),
                                      "--input", str(filename)],
                                     capture_output=True, text=True, timeout=15, check=True)
            report = json.loads(process.stdout)
            self.assertEqual(report["status"], "SATISFIABLE_IN_LOCAL_FINAL_RELEASE_CATALOG")
            self.assertFalse(report["user_code_executed"])

    def test_cli_rejects_symlink_hardlink_and_large_input(self):
        with tempfile.TemporaryDirectory() as root:
            original = Path(root) / "secrets.json"
            original.write_text('{"secret":"PRIVATE_TOKEN_456"}')
            symlink = Path(root) / "link.json"
            symlink.symlink_to(original)
            hardlink = Path(root) / "hard.json"
            os.link(original, hardlink)
            for file in (symlink, hardlink, original):
                process = subprocess.run([sys.executable, "-I", "-S", "-B", str(MODULE),
                                          "--input", str(file)], capture_output=True,
                                         text=True, timeout=15)
                report = json.loads(process.stdout)
                self.assertEqual(report["status"], "UNKNOWN_UNSUPPORTED_INPUT")
                self.assertNotIn("PRIVATE_TOKEN", process.stdout)
            big = Path(root) / "huge.json"
            with big.open("wb") as output:
                output.truncate(resolver.MAX_INPUT_BYTES + 1)
            process = subprocess.run([sys.executable, "-I", "-S", "-B", str(MODULE),
                                      "--input", str(big)], capture_output=True, text=True, timeout=15)
            self.assertEqual(json.loads(process.stdout)["status"], "UNKNOWN_UNSUPPORTED_INPUT")

    def test_cli_rejects_ambiguous_duplicate_json_fields(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "duplicate.json"
            path.write_text('{"catalog":{},"catalog":{"a":[{"version":"1"}]},'
                            '"roots":[{"name":"a"}]}', encoding="utf-8")
            process = subprocess.run([sys.executable, "-I", "-S", "-B", str(MODULE),
                                      "--input", str(path)], capture_output=True, text=True,
                                     timeout=15, check=True)
            self.assertEqual(json.loads(process.stdout)["status"], "UNKNOWN_UNSUPPORTED_INPUT")


if __name__ == "__main__":
    unittest.main()
