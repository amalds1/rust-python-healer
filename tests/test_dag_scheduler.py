"""DAG, bounded queue and deadline tests; target source is never executed."""

from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("dag_scheduler", ROOT / "python" / "dag_scheduler.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


def task(name, deps=None, priority=1, duration=10, deadline=None):
    return {"id": name, "deps": list(deps or []), "priority": priority,
            "duration_ms": duration, "deadline_ms": deadline}


def plan(tasks=None, actions=None, workers=2, capacity=8):
    return {"schema_version": 1, "tasks": tasks or [task("one")],
            "actions": actions or [], "max_pending": capacity, "workers": workers}


class DagSchedulerTests(unittest.TestCase):
    def test_dag_order_and_critical_path_from_declared_costs(self):
        data = plan([task("a", duration=10), task("b", ["a"], duration=20),
                     task("c", ["a"], duration=5),
                     task("d", ["b", "c"], duration=30)])
        report = module.inspect(data)
        self.assertEqual(report["topological_order"], ["a", "b", "c", "d"])
        self.assertEqual(report["critical_path_ms_estimate"], 60)
        self.assertFalse(report["critical_path_proven"])
        self.assertFalse(report["task_code_executed"])

    def test_dependency_cycles_are_rejected_before_any_dispatch(self):
        for tasks in ([task("a", ["b"]), task("b", ["a"])],
                      [task("a", ["b"]), task("b", ["c"]), task("c", ["a"])],
                      [task("self", ["self"])],
                      [task("a", ["missing"])],
                      [task("a", ["b", "b"]), task("b")]):
            with self.assertRaises(ValueError):
                module.inspect(plan(tasks))

    def test_ready_tasks_are_never_dispatched_before_dependencies_complete(self):
        acts = [{"kind": "DISPATCH", "at_ms": 0},
                {"kind": "COMPLETE", "task": "first", "at_ms": 10},
                {"kind": "DISPATCH", "at_ms": 10}]
        result = module.inspect(plan([task("first"), task("next", ["first"])],
                                     acts, workers=2))
        self.assertEqual([e["task"] for e in result["events"]
                          if e["kind"] == "DISPATCHED_NO_EXECUTION"],
                         ["first", "next"])
        self.assertEqual(result["states"]["first"], "COMPLETE_REPORTED")
        self.assertEqual(result["states"]["next"], "RUNNING_REPORTED")
        self.assertFalse(result["external_completions_verified"])

    def test_priority_precedes_critical_path_in_reservations(self):
        tasks = [task("slow", priority=2, duration=50),
                 task("urgent", priority=100, duration=1),
                 task("medium", priority=50, duration=4)]
        result = module.inspect(plan(tasks, [{"kind": "DISPATCH", "at_ms": 0}],
                                     workers=2))
        started = [e["task"] for e in result["events"]
                   if e["kind"] == "DISPATCHED_NO_EXECUTION"]
        self.assertEqual(started, ["urgent", "medium"])
        self.assertEqual(result["peak_ready_tokens"], 3)
        self.assertEqual(result["peak_inflight_tokens"], 2)

    def test_critical_path_is_used_as_tiebreaker_for_equal_priority(self):
        tasks = [task("long", duration=50), task("short", duration=1),
                 task("child", ["long"], duration=20)]
        response = module.inspect(plan(tasks, [{"kind": "DISPATCH", "at_ms": 0}],
                                       workers=1))
        self.assertEqual(response["events"][0]["task"], "long")
        self.assertEqual(response["critical_path_ms_estimate"], 70)

    def test_backpressure_rejects_entire_batch_without_partial_success(self):
        data = plan([task("a"), task("b"), task("c")], capacity=2)
        with self.assertRaisesRegex(ValueError, "BACKPRESSURE_REJECTED"):
            module.inspect(data)
        self.assertEqual(module.inspect(plan([task("a"), task("b")],
                                             capacity=2))["queue_capacity"], 2)

    def test_dynamic_admission_applies_backpressure_then_recovers(self):
        tasks = [task("first"), task("second"), task("third")]
        actions = [
            {"kind": "SUBMIT", "task": "first", "at_ms": 0},
            {"kind": "SUBMIT", "task": "second", "at_ms": 0},
            {"kind": "SUBMIT", "task": "third", "at_ms": 0},
            {"kind": "DISPATCH", "at_ms": 0},
            {"kind": "COMPLETE", "task": "first", "at_ms": 1},
            {"kind": "SUBMIT", "task": "third", "at_ms": 2},
            {"kind": "DISPATCH", "at_ms": 2},
        ]
        result = module.inspect(plan(tasks, actions, workers=2, capacity=2))
        self.assertTrue(result["dynamic_admission"])
        self.assertEqual(result["backpressure_rejections"], 1)
        self.assertEqual(result["peak_pending_tokens"], 2)
        self.assertEqual([event["task"] for event in result["events"]
                          if event["kind"] == "REJECTED_BACKPRESSURE"], ["third"])
        self.assertEqual(result["states"]["first"], "COMPLETE_REPORTED")
        self.assertEqual(result["states"]["third"], "RUNNING_REPORTED")

    def test_dynamic_submission_still_respects_dependent_task_gates(self):
        tasks = [task("first"), task("second", ["first"])]
        actions = [
            {"kind": "SUBMIT", "task": "second", "at_ms": 0},
            {"kind": "DISPATCH", "at_ms": 0},
            {"kind": "SUBMIT", "task": "first", "at_ms": 1},
            {"kind": "DISPATCH", "at_ms": 1},
            {"kind": "COMPLETE", "task": "first", "at_ms": 2},
            {"kind": "DISPATCH", "at_ms": 2},
        ]
        result = module.inspect(plan(tasks, actions, capacity=2, workers=1))
        self.assertEqual([event["task"] for event in result["events"]
                          if event["kind"] == "DISPATCHED_NO_EXECUTION"],
                         ["first", "second"])

    def test_dynamic_duplicate_admission_is_refused(self):
        actions = [{"kind": "SUBMIT", "task": "one", "at_ms": 0},
                   {"kind": "SUBMIT", "task": "one", "at_ms": 0}]
        with self.assertRaisesRegex(ValueError, "duplicate_or_expired_submission"):
            module.inspect(plan(actions=actions))

    def test_reported_throughput_turnaround_and_queue_pressure(self):
        actions = [
            {"kind": "SUBMIT", "task": "a", "at_ms": 10},
            {"kind": "SUBMIT", "task": "b", "at_ms": 10},
            {"kind": "DISPATCH", "at_ms": 20},
            {"kind": "COMPLETE", "task": "a", "at_ms": 30},
            {"kind": "DISPATCH", "at_ms": 30},
            {"kind": "COMPLETE", "task": "b", "at_ms": 60},
        ]
        report = module.inspect(plan([task("a"), task("b")], actions,
                                     workers=1, capacity=2))
        self.assertEqual(report["mean_admission_to_dispatch_ms"], 15)
        self.assertEqual(report["mean_reported_turnaround_ms"], 35)
        self.assertEqual(report["reported_complete_tokens"], 2)
        self.assertEqual(report["reported_throughput_tokens_per_second"], 40)
        self.assertEqual(report["peak_queue_pressure_ratio"], 1)
        self.assertFalse(report["actual_worker_throughput_verified"])

    def test_no_completed_work_never_fabricates_measured_throughput(self):
        output = module.inspect(plan(actions=[{"kind": "DISPATCH", "at_ms": 0}]))
        self.assertIsNone(output["mean_reported_turnaround_ms"])
        self.assertIsNone(output["reported_throughput_tokens_per_second"])
        self.assertFalse(output["actual_worker_throughput_verified"])

    def test_deadline_expired_and_downstream_blocked(self):
        data = plan([task("a", duration=11, deadline=10),
                     task("b", ["a"], duration=1, deadline=100)],
                    [{"kind": "DISPATCH", "at_ms": 0}])
        result = module.inspect(data)
        self.assertEqual(result["states"], {
            "a": "DEADLINE_EXPIRED", "b": "DEPENDENCY_BLOCKED"})
        self.assertNotIn("DISPATCHED_NO_EXECUTION",
                         [event["kind"] for event in result["events"]])

    def test_running_token_expires_when_external_completion_is_late(self):
        data = plan([task("a", duration=10, deadline=10)],
                    [{"kind": "DISPATCH", "at_ms": 0},
                     {"kind": "TICK", "at_ms": 11}])
        result = module.inspect(data)
        self.assertEqual(result["states"]["a"], "DEADLINE_EXPIRED")

    def test_completion_is_never_created_without_real_reservation_token(self):
        data = plan([task("a")], [{"kind": "COMPLETE", "task": "a", "at_ms": 0}])
        with self.assertRaisesRegex(ValueError, "completion_requires_dispatched_task"):
            module.inspect(data)
        data["actions"] = [{"kind": "DISPATCH", "at_ms": 0},
                           {"kind": "COMPLETE", "task": "a", "at_ms": 1},
                           {"kind": "COMPLETE", "task": "a", "at_ms": 2}]
        with self.assertRaisesRegex(ValueError, "completion_requires_dispatched_task"):
            module.inspect(data)

    def test_worker_slots_bound_parallel_reservations(self):
        actions = [{"kind": "DISPATCH", "at_ms": 0},
                   {"kind": "DISPATCH", "at_ms": 1}]
        result = module.inspect(plan([task("a"), task("b"), task("c")],
                                     actions, workers=1))
        self.assertEqual(result["peak_inflight_tokens"], 1)
        self.assertEqual(len([e for e in result["events"]
                              if e["kind"] == "DISPATCHED_NO_EXECUTION"]), 1)

    def test_rejects_boolean_integer_quotas_and_invalid_ids(self):
        invalids = []
        base = plan()
        for field in ("max_pending", "workers", "schema_version"):
            bad = dict(base)
            bad[field] = True
            invalids.append(bad)
        invalids.extend([plan([task("one"), task("one")]),
                         plan([task("/private", priority=1)]),
                         plan([task("a", duration=0)]),
                         plan([task("a", deadline=-1)]),
                         plan([task("a", priority=101)])])
        for value in invalids:
            with self.assertRaises(ValueError):
                module.inspect(value)

    def test_action_timestamps_must_be_monotonic(self):
        for actions in ([{"kind": "TICK", "at_ms": 5},
                         {"kind": "TICK", "at_ms": 4}],
                        [{"kind": "TICK", "at_ms": True}],
                        [{"kind": "COMPLETE", "at_ms": 1, "task": []}],
                        [{"kind": "TICK", "at_ms": 0, "untrusted": "x"}]):
            with self.assertRaises(ValueError):
                module.inspect(plan(actions=actions))

    def test_symlink_hardlink_and_oversized_input_never_loads(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            original = root / "plan.json"
            original.write_text(json.dumps(plan()))
            soft = root / "soft.json"
            soft.symlink_to(original)
            with self.assertRaisesRegex(ValueError, "input_symlink_refused"):
                module.load_manifest(soft)
            other = root / "hard.json"
            os.link(original, other)
            with self.assertRaisesRegex(ValueError, "input_not_unique_bounded_file"):
                module.load_manifest(original)
            original.unlink()
            other.unlink()
            original.write_bytes(b"x" * (module.MAX_INPUT_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "input_not_unique_bounded_file"):
                module.load_manifest(original)

    def test_duplicate_and_nonfinite_json_values_cannot_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "duplicate.json"
            for body in (b'{"schema_version":1,"schema_version":1}',
                         b'{"x":NaN}', b'\xff\xfe'):
                target.write_bytes(body)
                with self.assertRaises(ValueError):
                    module.load_manifest(target)

    def test_cli_embedded_helper_never_executes_untrusted_source(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            marker = root / "never_run.txt"
            document = plan([task("should-not-run")],
                            [{"kind": "DISPATCH", "at_ms": 0}])
            # This is deliberately an untrusted extra field: the schema
            # must fail closed instead of interpreting it as Python code.
            manifest = root / "safe.json"
            manifest.write_text(json.dumps(document))
            child = subprocess.run([sys.executable, "-I", "-S", "-B",
                                    str(ROOT / "python" / "dag_scheduler.py"),
                                    "--manifest", str(manifest)], capture_output=True,
                                   text=True, check=False)
            self.assertEqual(child.returncode, 0, child.stderr)
            output = json.loads(child.stdout)
            self.assertEqual(output["status"], "QUEUED_DATA_ONLY_NOT_EXECUTED")
            self.assertFalse(output["task_code_executed"])
            self.assertEqual(len(output["events"]), 1)
            self.assertFalse(marker.exists())
            document["exec"] = "open({!r},'w').write('bad')".format(str(marker))
            manifest.write_text(json.dumps(document))
            denied = subprocess.run([sys.executable, "-I", "-S", "-B",
                                     str(ROOT / "python" / "dag_scheduler.py"),
                                     "--manifest", str(manifest)], capture_output=True,
                                    text=True, check=False)
            self.assertNotEqual(denied.returncode, 0)
            self.assertFalse(marker.exists())

    def test_cli_errors_do_not_reveal_untrusted_absolute_paths(self):
        private = "/unavailable/private/Alice/secrets/plan.json"
        child = subprocess.run([sys.executable, "-I", "-S", "-B",
                                str(ROOT / "python" / "dag_scheduler.py"),
                                "--manifest", private], capture_output=True,
                               text=True, check=False)
        self.assertEqual(child.returncode, 2)
        report = json.loads(child.stdout)
        self.assertEqual(report["status"], "NOT_RUN")
        self.assertEqual(report["reason"], "invalid_queue_input")
        self.assertNotIn("Alice", child.stdout + child.stderr)

    def test_same_priority_uses_stable_identity_order(self):
        taskset = [task("z"), task("a"), task("b")]
        first = module.inspect(plan(taskset, [{"kind": "DISPATCH", "at_ms": 0}],
                                    workers=2))["events"]
        second = module.inspect(plan(list(reversed(taskset)),
                                     [{"kind": "DISPATCH", "at_ms": 0}],
                                     workers=2))["events"]
        self.assertEqual([e["task"] for e in first], ["a", "b"])
        self.assertEqual(first, second)

    def test_seeded_acyclic_graphs_preserve_all_edges_and_path_costs(self):
        rng = random.Random(12345)
        for size in range(1, 31):
            nodes = []
            for index in range(size):
                deps = ["t{}".format(i) for i in range(index) if rng.random() < 0.13]
                nodes.append(task("t{}".format(index), deps,
                                  duration=rng.randint(1, 100)))
            rng.shuffle(nodes)
            report = module.inspect(plan(nodes, capacity=size))
            index_by_id = {ident: index for index, ident in
                           enumerate(report["topological_order"])}
            self.assertEqual(len(index_by_id), size)
            for node in nodes:
                for dependency in node["deps"]:
                    self.assertLess(index_by_id[dependency], index_by_id[node["id"]])
            # Independent reference: compute all root-to-leaf longest paths.
            by_id = {node["id"]: node for node in nodes}
            def longest(ident):
                next_nodes = [node["id"] for node in nodes
                              if ident in node["deps"]]
                return by_id[ident]["duration_ms"] + max(
                    (longest(successor) for successor in next_nodes), default=0)
            self.assertEqual(report["critical_path_ms_estimate"],
                             max(longest(node["id"]) for node in nodes))

    def test_action_quotas_block_runaway_token_events(self):
        flooded = [{"kind": "TICK", "at_ms": 0}] * (module.MAX_ACTIONS + 1)
        with self.assertRaisesRegex(ValueError, "invalid_action_count"):
            module.inspect(plan(actions=flooded))

    def test_worker_pressure_never_exceeds_declared_slots_in_many_dispatches(self):
        tasks = [task("t{:02d}".format(i)) for i in range(20)]
        actions = [{"kind": "SUBMIT", "task": "t{:02d}".format(i), "at_ms": 0}
                   for i in range(20)]
        actions.append({"kind": "DISPATCH", "at_ms": 0})
        for now in range(1, 7):
            for i in range((now - 1) * 3, now * 3):
                actions.append({"kind": "COMPLETE", "task": "t{:02d}".format(i),
                                "at_ms": now})
            actions.append({"kind": "DISPATCH", "at_ms": now})
        report = module.inspect(plan(tasks, actions, workers=3, capacity=20))
        self.assertEqual(report["peak_inflight_tokens"], 3)
        self.assertFalse(report["task_code_executed"])


if __name__ == "__main__":
    unittest.main()
