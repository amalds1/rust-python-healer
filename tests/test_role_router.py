"""Deterministic, offline policy tests for the 36 planned Python specialists."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
ROUTER = ROOT / "python" / "role_router.py"
ROLES = ROOT / "config" / "agent_roles.json"
MODULE_SPEC = importlib.util.spec_from_file_location("role_router_under_test", str(ROUTER))
router = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(router)


def request(tasks=None, budget=100, slots=5, feedback=None):
    return {
        "schema_version": 1,
        "budget_units": budget,
        "max_reserved_slots": slots,
        "tasks": tasks if tasks is not None else [task()],
        "model_feedback": feedback if feedback is not None else {},
    }


def task(name="Alpha", capabilities=None, priority=50, risk="LOW", cost=1000,
         latency=600000, quality=0):
    return {
        "task_id": name,
        "required_capabilities": capabilities if capabilities is not None else ["python_syntax", "ast"],
        "priority": priority,
        "risk_tier": risk,
        "max_cost_units": cost,
        "max_latency_ms": latency,
        "min_quality_percent": quality,
    }


class RoleRouterTests(unittest.TestCase):
    def test_public_json_document_is_read_as_data(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "public.json"
            path.write_bytes(b'{"public":true}')
            if os.name == "nt":
                from windows_privacy_fixtures import set_public_read_acl
                set_public_read_acl(path)
            else:
                path.chmod(0o644)
            parsed, observed = router._read_document(str(path), 1024)
            self.assertEqual(parsed, {"public":True})
            self.assertEqual(observed, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_same_inode_leaf_alias_inserted_during_open_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "document.json"; backing = Path(folder) / "backing.json"
            path.write_bytes(b'{"fixed":true}')
            if os.name == "nt":
                boundary = router._windows_security()
                original_open = boundary._open
                def swapped_windows(*args, **kwargs):
                    path.rename(backing); path.symlink_to(backing)
                    return original_open(*args, **kwargs)
                with mock.patch.object(boundary, "_open", side_effect=swapped_windows):
                    with self.assertRaises(router.RoutingError):
                        router._read_document(str(path), 1024)
            else:
                original_open = router.os.open
                def swapped_posix(*args, **kwargs):
                    path.rename(backing); path.symlink_to(backing)
                    return original_open(*args, **kwargs)
                with mock.patch.object(router.os, "open", side_effect=swapped_posix):
                    with self.assertRaises(router.RoutingError):
                        router._read_document(str(path), 1024)

    @classmethod
    def setUpClass(cls):
        with ROLES.open("r", encoding="utf-8") as stream:
            cls.registry = json.load(stream)

    def route(self, input_request=None, registry=None):
        return router.plan_routes(
            copy.deepcopy(self.registry if registry is None else registry),
            copy.deepcopy(request() if input_request is None else input_request),
        )

    def rejects(self, change, target="request"):
        registry = copy.deepcopy(self.registry)
        sample = request()
        if target == "registry":
            change(registry)
        else:
            change(sample)
        with self.assertRaises(router.RoutingError):
            self.route(sample, registry)

    def test_01_exactly_36_unique_roles(self):
        rows = router.validate_roles(copy.deepcopy(self.registry))
        self.assertEqual(len(rows), 36)
        self.assertEqual({r["id"] for r in rows}, {"R%02d" % i for i in range(1, 37)})
        self.assertEqual(len({r["name"] for r in rows}), 36)

    def test_02_clusters_are_six_by_six(self):
        rows = self.registry["roles"]
        self.assertEqual({cluster: sum(r["cluster"] == cluster for r in rows)
                          for cluster in router.ROLE_CLUSTERS},
                         {cluster: 6 for cluster in router.ROLE_CLUSTERS})

    def test_03_all_roles_have_real_capabilities_and_model_hints(self):
        for role in self.registry["roles"]:
            self.assertTrue(role["capabilities"], role["id"])
            self.assertTrue(role["model_hints"], role["id"])
            self.assertIn(role["model_hints"][0], router.MODEL_NAMES)

    def test_04_every_declared_specialist_capability_is_routable(self):
        for role in self.registry["roles"]:
            with self.subTest(role=role["id"]):
                sample = request(tasks=[task(capabilities=role["capabilities"])])
                result = self.route(sample)
                self.assertEqual(len(result["assignments"]), 1, result["unassigned"])
                picked = next(item for item in self.registry["roles"]
                              if item["id"] == result["assignments"][0]["role_id"])
                self.assertTrue(set(role["capabilities"]).issubset(picked["capabilities"]))

    def test_05_python_syntax_specialist(self):
        result = self.route()
        self.assertEqual(result["assignments"][0]["role_id"], "R07")

    def test_06_security_specialist(self):
        result = self.route(request(tasks=[task(capabilities=["sandbox", "threat_model"])]))
        self.assertEqual(result["assignments"][0]["role_id"], "R32")

    def test_07_orchestrator_specialist(self):
        result = self.route(request(tasks=[task(capabilities=["task_planning", "routing"])]))
        self.assertEqual(result["assignments"][0]["role_id"], "R01")

    def test_08_priority_before_submission_order(self):
        sample = request(tasks=[task("Low", priority=2), task("High", priority=99)], slots=2)
        result = self.route(sample)
        self.assertEqual([x["task_id"] for x in result["assignments"]], ["High", "Low"])

    def test_09_equal_priority_lexical_tie_break(self):
        sample = request(tasks=[task("Zebra"), task("Alpha")], slots=2)
        result = self.route(sample)
        self.assertEqual([x["task_id"] for x in result["assignments"]], ["Alpha", "Zebra"])

    def test_10_global_slot_cap(self):
        sample = request(tasks=[task("A"), task("B"), task("C")], slots=1)
        result = self.route(sample)
        self.assertEqual(len(result["assignments"]), 1)
        self.assertEqual([e["reason"] for e in result["unassigned"]],
                         ["GLOBAL_CAPACITY_LIMIT", "GLOBAL_CAPACITY_LIMIT"])

    def test_11_role_slot_cap(self):
        sample = request(tasks=[task("A"), task("B"), task("C")], slots=3)
        result = self.route(sample)
        self.assertEqual(len(result["assignments"]), 2)
        self.assertEqual(result["unassigned"][0]["reason"], "ROLE_CAPACITY_LIMIT")

    def test_12_priority_reserves_budget_first(self):
        sample = request(tasks=[task("Low", priority=1), task("High", priority=99)],
                         budget=5, slots=2)
        result = self.route(sample)
        self.assertEqual([r["task_id"] for r in result["assignments"]], ["High"])
        self.assertEqual(result["unassigned"][0]["reason"], "BUDGET_LIMIT")

    def test_13_insufficient_total_budget(self):
        sample = request(budget=1)
        result = self.route(sample)
        self.assertEqual(result["assignments"], [])
        self.assertEqual(result["unassigned"][0]["reason"], "BUDGET_LIMIT")

    def test_14_budget_accounting_is_exact(self):
        result = self.route()
        spent = sum(row["reserved_cost_units"] for row in result["assignments"])
        self.assertEqual(result["reserved_cost_units"], spent)
        self.assertEqual(result["remaining_budget_units"] + spent, result["budget_units"])

    def test_15_unavailable_capability_is_explicit(self):
        sample = request(tasks=[task(capabilities=["imaginary_superpower"])])
        result = self.route(sample)
        self.assertEqual(result["unassigned"][0]["reason"], "NO_SUITABLE_ROLE")

    def test_16_high_risk_denied_when_role_has_medium_trust(self):
        sample = request(tasks=[task(capabilities=["python_syntax"], risk="HIGH")])
        result = self.route(sample)
        self.assertEqual(result["unassigned"][0]["reason"], "NO_SUITABLE_ROLE")

    def test_17_per_task_cost_policy(self):
        sample = request(tasks=[task(cost=1)])
        result = self.route(sample)
        self.assertEqual(result["unassigned"][0]["reason"], "MODEL_POLICY_LIMIT")

    def test_18_per_task_latency_policy(self):
        sample = request(tasks=[task(latency=1)])
        self.assertEqual(self.route(sample)["unassigned"][0]["reason"], "MODEL_POLICY_LIMIT")

    def test_19_per_task_quality_policy(self):
        sample = request(tasks=[task(quality=100)])
        self.assertEqual(self.route(sample)["unassigned"][0]["reason"], "MODEL_POLICY_LIMIT")

    def test_20_feedback_models_select_quality_when_affordable(self):
        feedback = {
            "gpt-6.1-sol": {"quality_percent": 80, "cost_units": 2, "latency_ms": 1000},
            "gpt-6-astra": {"quality_percent": 95, "cost_units": 8, "latency_ms": 3000},
        }
        result = self.route(request(feedback=feedback))
        self.assertEqual(result["assignments"][0]["model_hint"], "gpt-6-astra")
        self.assertEqual(result["assignments"][0]["estimate_source"],
                         "UNVERIFIED_SUPPLIED_FEEDBACK")

    def test_21_feedback_models_select_low_cost_under_budget(self):
        feedback = {
            "gpt-6.1-sol": {"quality_percent": 80, "cost_units": 2, "latency_ms": 1000},
            "gpt-6-astra": {"quality_percent": 95, "cost_units": 8, "latency_ms": 3000},
        }
        result = self.route(request(feedback=feedback, budget=2))
        self.assertEqual(result["assignments"][0]["model_hint"], "gpt-6.1-sol")

    def test_22_feedback_changes_model_deterministically(self):
        feedback = {
            "gpt-6.1-sol": {"quality_percent": 99, "cost_units": 3, "latency_ms": 2000},
            "gpt-6-astra": {"quality_percent": 82, "cost_units": 3, "latency_ms": 1000},
        }
        self.assertEqual(self.route(request(feedback=feedback))["assignments"][0]["model_hint"],
                         "gpt-6.1-sol")

    def test_23_absent_model_feedback_never_assumed_measured(self):
        result = self.route()
        self.assertEqual(result["assignments"][0]["estimate_source"],
                         "UNVERIFIED_MANIFEST_HINT")

    def test_24_feedback_for_incompatible_models_is_not_forced(self):
        sample = request(feedback={"gpt-6-luna": {
            "quality_percent": 99, "cost_units": 1, "latency_ms": 100}})
        result = self.route(sample)
        self.assertEqual(result["unassigned"][0]["reason"], "MODEL_POLICY_LIMIT")

    def test_25_never_claim_workers_or_models(self):
        result = self.route()
        self.assertEqual(result["status"], "PLANNED_ONLY_NOT_EXECUTED")
        self.assertEqual(result["active_agents_started"], 0)
        self.assertEqual(result["models_invoked"], 0)
        self.assertEqual(result["tasks_executed"], 0)
        self.assertFalse(result["feedback_verified"])
        self.assertTrue(result["policy_only"])

    def test_26_repeated_calls_are_identical(self):
        sample = request(tasks=[task("A"), task("B", capabilities=["sandbox"])])
        self.assertEqual(self.route(sample), self.route(sample))

    def test_27_reject_duplicate_role_id(self):
        self.rejects(lambda r: r["roles"][1].update(id="R01"), "registry")

    def test_28_reject_missing_role(self):
        self.rejects(lambda r: r["roles"].pop(), "registry")

    def test_29_reject_role_claiming_processes(self):
        self.rejects(lambda r: r.update(active_processes_declared=36), "registry")

    def test_30_reject_wrong_role_cluster(self):
        self.rejects(lambda r: r["roles"][0].update(cluster="QA"), "registry")

    def test_31_reject_fake_model(self):
        self.rejects(lambda r: r["roles"][0].update(model_hints=["model-unlisted"]), "registry")

    def test_32_reject_role_schema_extra_keys(self):
        self.rejects(lambda r: r["roles"][0].update(credential="secret"), "registry")

    def test_33_reject_duplicate_task_id(self):
        self.rejects(lambda r: r["tasks"].append(task()))

    def test_34_reject_more_than_64_tasks(self):
        self.rejects(lambda r: r.update(tasks=[task("T%d" % i) for i in range(65)]))

    def test_35_reject_missing_request_budget(self):
        self.rejects(lambda r: r.pop("budget_units"))

    def test_36_reject_boolean_masquerading_as_integer(self):
        self.rejects(lambda r: r.update(budget_units=True))

    def test_37_reject_duplicate_capabilities(self):
        self.rejects(lambda r: r["tasks"][0].update(required_capabilities=["ast", "ast"]))

    def test_38_reject_task_code_not_in_schema(self):
        self.rejects(lambda r: r["tasks"][0].update(command="curl example.com"))

    def test_39_reject_invalid_task_priority(self):
        self.rejects(lambda r: r["tasks"][0].update(priority=101))

    def test_40_reject_invalid_metric(self):
        self.rejects(lambda r: r.update(model_feedback={"gpt-6-astra": {
            "quality_percent": float("nan"), "cost_units": 1, "latency_ms": 2}}))

    def test_41_reject_invalid_risk_tier(self):
        self.rejects(lambda r: r["tasks"][0].update(risk_tier="SUPERUSER"))

    def test_42_reject_request_budget_over_limit(self):
        self.rejects(lambda r: r.update(budget_units=100001))

    def test_43_reject_slot_count_over_limit(self):
        self.rejects(lambda r: r.update(max_reserved_slots=37))

    def test_44_reject_untrusted_source_manifest(self):
        self.rejects(lambda r: r.update(source="https://example.net/roles"), "registry")

    def test_45_duplicate_json_field_is_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema_version":1,"schema_version":2}', encoding="utf-8")
            with self.assertRaises(router.RoutingError):
                router._read_document(str(path), router.MAX_REQUEST_BYTES)

    def test_46_json_nan_constant_is_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nan.json"
            path.write_text('{"x":NaN}', encoding="utf-8")
            with self.assertRaises(router.RoutingError):
                router._read_document(str(path), router.MAX_REQUEST_BYTES)

    def test_47_oversize_request_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversize.json"
            path.write_bytes(b"X" * (router.MAX_REQUEST_BYTES + 1))
            with self.assertRaises(router.RoutingError):
                router._read_document(str(path), router.MAX_REQUEST_BYTES)

    def test_48_symlink_document_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original.json"
            original.write_text("{}", encoding="utf-8")
            link = Path(directory) / "link.json"
            link.symlink_to(original)
            with self.assertRaises(router.RoutingError):
                router._read_document(str(link), router.MAX_REQUEST_BYTES)

    def test_49_hardlink_document_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original.json"
            original.write_text("{}", encoding="utf-8")
            link = Path(directory) / "link.json"
            os.link(str(original), str(link))
            with self.assertRaises(router.RoutingError):
                router._read_document(str(link), router.MAX_REQUEST_BYTES)

    def test_50_invalid_utf8_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_bytes(b"\xff\xfe")
            with self.assertRaises(router.RoutingError):
                router._read_document(str(path), router.MAX_REQUEST_BYTES)

    def test_51_cli_valid_json_and_sha256(self):
        with tempfile.TemporaryDirectory() as directory:
            tasks_path = Path(directory) / "tasks.json"
            tasks_path.write_text(json.dumps(request()), encoding="utf-8")
            cmd = [sys.executable, "-I", "-S", "-B", str(ROUTER), "--roles", str(ROLES),
                   "--tasks", str(tasks_path)]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            output = json.loads(result.stdout)
            self.assertEqual(output["roles_registered"], 36)
            self.assertEqual(len(output["roles_sha256"]), 64)
            self.assertEqual(len(output["request_sha256"]), 64)

    def test_52_cli_invalid_json_no_path_leak(self):
        with tempfile.TemporaryDirectory() as directory:
            tasks_path = Path(directory) / "secret-token-DO_NOT_PRINT.json"
            tasks_path.write_text('bad input "secret-value"', encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B", str(ROUTER), "--roles", str(ROLES),
                 "--tasks", str(tasks_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)["status"], "NOT_RUN")
            self.assertNotIn("DO_NOT_PRINT", result.stdout)
            self.assertNotIn("secret-value", result.stdout)

    def test_53_task_json_preserves_no_mutation(self):
        original = request()
        snapshot = copy.deepcopy(original)
        registry = copy.deepcopy(self.registry)
        self.route(original, registry)
        self.assertEqual(original, snapshot)
        self.assertEqual(registry, self.registry)

    def test_54_no_shell_or_dynamic_import_in_router(self):
        content = ROUTER.read_text(encoding="utf-8")
        self.assertNotIn("import subprocess", content)
        self.assertNotIn("os.system", content)
        self.assertNotIn("eval(", content)
        self.assertNotIn("exec(", content)


if __name__ == "__main__":
    unittest.main(verbosity=1)
