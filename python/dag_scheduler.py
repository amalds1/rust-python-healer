"""Fail-closed DAG and bounded priority/deadline token queue for Python 3.9+.

This is an actual in-memory queue *state machine*, but no worker executes
supplied tasks, code, shell commands, modules, or source. Completion actions
are external assertions, not independently verified behavior. The critical
path is an estimate derived from declared durations, not measured runtime.
"""

import argparse
import hashlib
import heapq
import json
import os
from pathlib import Path
import re
import stat
import sys


MAX_INPUT_BYTES = 131_072
MAX_TASKS = 128
MAX_ACTIONS = 512
MAX_WORKERS = 32
MAX_DURATION_MS = 86_400_000
MAX_CLOCK_MS = 10**12
IDENT = re.compile(r"[a-zA-Z][a-zA-Z0-9_.-]{0,63}\Z")


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_key")
        value[key] = item
    return value


def load_manifest(path):
    """Read bounded unique regular JSON; never follow a symlink or print paths."""
    target = Path(path)
    if target.is_symlink():
        raise ValueError("input_symlink_refused")
    desc = os.open(str(target), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                   getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(desc, "rb") as stream:
        first = os.fstat(stream.fileno())
        if (not stat.S_ISREG(first.st_mode) or first.st_nlink != 1 or
                first.st_size > MAX_INPUT_BYTES):
            raise ValueError("input_not_unique_bounded_file")
        body = stream.read(MAX_INPUT_BYTES + 1)
        after = os.fstat(stream.fileno())
        if (len(body) > MAX_INPUT_BYTES or
                (first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise ValueError("input_changed_or_oversized")
    try:
        parsed = json.loads(body.decode("utf-8"), object_pairs_hook=strict_object,
                            parse_constant=lambda _: (_ for _ in ()).throw(
                                ValueError("nonfinite_json_number")))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ValueError("invalid_task_manifest_json") from error
    return parsed, hashlib.sha256(body).hexdigest()


def valid_identity(value):
    return isinstance(value, str) and bool(IDENT.fullmatch(value))


def validated_plan(document):
    """Validate all dependency edges, deadlines and quotas before enqueueing."""
    if (not isinstance(document, dict) or set(document) != {
            "schema_version", "max_pending", "workers", "tasks", "actions"} or
            type(document["schema_version"]) is not int or
            document["schema_version"] != 1):
        raise ValueError("invalid_plan_structure")
    capacity, workers = document["max_pending"], document["workers"]
    if (type(capacity) is not int or not 1 <= capacity <= MAX_TASKS or
            type(workers) is not int or not 1 <= workers <= MAX_WORKERS):
        raise ValueError("invalid_queue_capacity_or_workers")
    supplied = document["tasks"]
    if not isinstance(supplied, list) or not 1 <= len(supplied) <= MAX_TASKS:
        raise ValueError("invalid_task_count")
    records = {}
    for original in supplied:
        if not isinstance(original, dict) or set(original) != {
                "id", "priority", "duration_ms", "deadline_ms", "deps"}:
            raise ValueError("invalid_task_structure")
        ident = original["id"]
        priority, duration, deadline = (original["priority"],
                                        original["duration_ms"],
                                        original["deadline_ms"])
        if (not valid_identity(ident) or ident in records or
                type(priority) is not int or not 0 <= priority <= 100 or
                type(duration) is not int or not 1 <= duration <= MAX_DURATION_MS or
                deadline is not None and
                (type(deadline) is not int or not 0 <= deadline <= MAX_CLOCK_MS)):
            raise ValueError("invalid_task_identity_priority_duration_or_deadline")
        dependencies = original["deps"]
        if (not isinstance(dependencies, list) or len(dependencies) > MAX_TASKS or
                any(not valid_identity(value) for value in dependencies) or
                len(set(dependencies)) != len(dependencies)):
            raise ValueError("invalid_dependency_list")
        records[ident] = dict(original)
    successors = {ident: [] for ident in records}
    indegrees = {}
    for ident, record in records.items():
        for dependency in record["deps"]:
            if dependency not in records or dependency == ident:
                raise ValueError("unknown_or_self_dependency")
            successors[dependency].append(ident)
        indegrees[ident] = len(record["deps"])
    available = [ident for ident, degree in indegrees.items() if degree == 0]
    heapq.heapify(available)
    order = []
    while available:
        ident = heapq.heappop(available)
        order.append(ident)
        for following in successors[ident]:
            indegrees[following] -= 1
            if indegrees[following] == 0:
                heapq.heappush(available, following)
    if len(order) != len(records):
        raise ValueError("dependency_cycle_refused")
    critical = {}
    for ident in reversed(order):
        critical[ident] = records[ident]["duration_ms"] + max(
            (critical[next_id] for next_id in successors[ident]), default=0)

    actions = document["actions"]
    if not isinstance(actions, list) or len(actions) > MAX_ACTIONS:
        raise ValueError("invalid_action_count")
    last_time = -1
    for action in actions:
        if not isinstance(action, dict) or action.get("kind") not in (
                "DISPATCH", "COMPLETE", "TICK", "SUBMIT"):
            raise ValueError("invalid_queue_action")
        kind = action["kind"]
        expected = {"kind", "at_ms", "task"} if kind in ("COMPLETE", "SUBMIT") else {
            "kind", "at_ms"}
        instant = action.get("at_ms")
        if (set(action) != expected or type(instant) is not int or
                not 0 <= instant <= MAX_CLOCK_MS or instant < last_time):
            raise ValueError("invalid_action_time_or_fields")
        if kind in ("COMPLETE", "SUBMIT") and (
                not valid_identity(action["task"]) or action["task"] not in records):
            raise ValueError("unknown_completion")
        last_time = instant
    if len(supplied) > capacity and not any(
            action["kind"] == "SUBMIT" for action in actions):
        raise ValueError("BACKPRESSURE_REJECTED")
    return records, order, critical


class QueueManager:
    """Reserve work tokens, enforce gates, accept explicit completion events."""

    def __init__(self, document):
        self.tasks, self.topological_order, self.critical = validated_plan(document)
        self.workers = document["workers"]
        self.capacity = document["max_pending"]
        self.dynamic_admission = any(action["kind"] == "SUBMIT"
                                     for action in document["actions"])
        first_state = "NOT_SUBMITTED" if self.dynamic_admission else "PENDING"
        self.states = {ident: first_state for ident in self.tasks}
        self.submitted = {} if self.dynamic_admission else {
            ident: 0 for ident in self.tasks}
        self.started = {}
        self.finished = {}
        self.clock_ms = 0
        self.events = []
        self.peak_running = 0
        self.peak_ready = 0
        self.peak_pending = len(self.tasks) if not self.dynamic_admission else 0
        self.rejected_backpressure = 0

    def _mark_deadlines(self, now):
        for ident, item in self.tasks.items():
            state = self.states[ident]
            if state in ("NOT_SUBMITTED", "COMPLETE_REPORTED", "DEADLINE_EXPIRED",
                         "DEPENDENCY_BLOCKED"):
                continue
            if (item["deadline_ms"] is not None and
                    (now > item["deadline_ms"] or
                     (state == "PENDING" and
                      now + item["duration_ms"] > item["deadline_ms"]))):
                self.states[ident] = "DEADLINE_EXPIRED"
                self.events.append({"kind": "DEADLINE_EXPIRED", "task": ident,
                                    "at_ms": now})
        for ident in self.topological_order:
            if self.states[ident] != "PENDING":
                continue
            if any(self.states[dependency] in ("DEADLINE_EXPIRED",
                                                  "DEPENDENCY_BLOCKED")
                   for dependency in self.tasks[ident]["deps"]):
                self.states[ident] = "DEPENDENCY_BLOCKED"
                self.events.append({"kind": "DEPENDENCY_BLOCKED", "task": ident,
                                    "at_ms": now})

    def tick(self, now):
        if now < self.clock_ms:
            raise ValueError("time_must_be_monotonic")
        self.clock_ms = now
        self._mark_deadlines(now)

    def submit(self, ident, now):
        """Admit an immutable task token, or report bounded backpressure."""
        self.tick(now)
        if self.states[ident] != "NOT_SUBMITTED":
            raise ValueError("duplicate_or_expired_submission")
        active = sum(state in ("PENDING", "RUNNING_REPORTED")
                     for state in self.states.values())
        if active >= self.capacity:
            self.rejected_backpressure += 1
            self.events.append({"kind": "REJECTED_BACKPRESSURE",
                                "task": ident, "at_ms": now})
            return False
        self.states[ident] = "PENDING"
        self.submitted[ident] = now
        self.peak_pending = max(self.peak_pending, active + 1)
        self.events.append({"kind": "SUBMITTED", "task": ident, "at_ms": now})
        self._mark_deadlines(now)
        return self.states[ident] == "PENDING"

    def dispatch(self, now):
        self.tick(now)
        slots = self.workers - sum(state == "RUNNING_REPORTED" for state in self.states.values())
        ready = []
        for ident, item in self.tasks.items():
            if (self.states[ident] == "PENDING" and
                    all(self.states[dependency] == "COMPLETE_REPORTED"
                        for dependency in item["deps"])):
                heapq.heappush(ready, (-item["priority"], -self.critical[ident],
                                       item["deadline_ms"] if item["deadline_ms"] is not None
                                       else MAX_CLOCK_MS + 1, ident))
        self.peak_ready = max(self.peak_ready, len(ready))
        started = []
        while ready and slots > 0:
            _, _, _, ident = heapq.heappop(ready)
            self.states[ident] = "RUNNING_REPORTED"
            self.started[ident] = now
            started.append(ident)
            self.events.append({"kind": "DISPATCHED_NO_EXECUTION",
                                "task": ident, "at_ms": now})
            slots -= 1
        self.peak_running = max(self.peak_running,
                                sum(state == "RUNNING_REPORTED"
                                    for state in self.states.values()))
        return started

    def complete(self, ident, now):
        self.tick(now)
        if self.states[ident] != "RUNNING_REPORTED":
            raise ValueError("completion_requires_dispatched_task")
        self.states[ident] = "COMPLETE_REPORTED"
        self.finished[ident] = now
        self.events.append({"kind": "EXTERNAL_COMPLETION_NOT_VERIFIED",
                            "task": ident, "at_ms": now})

    def apply(self, actions):
        for action in actions:
            kind, now = action["kind"], action["at_ms"]
            if kind == "DISPATCH":
                self.dispatch(now)
            elif kind == "COMPLETE":
                self.complete(action["task"], now)
            elif kind == "SUBMIT":
                self.submit(action["task"], now)
            else:
                self.tick(now)

    def summary(self):
        duration_ms = sum(self.tasks[ident]["duration_ms"] for ident in self.tasks)
        waits = [started_at - self.submitted[ident]
                 for ident, started_at in self.started.items()]
        turnarounds = [ended_at - self.submitted[ident]
                       for ident, ended_at in self.finished.items()]
        def rounded_mean(values):
            return round(sum(values) / len(values), 3) if values else None
        elapsed = (self.clock_ms - min(self.submitted.values())) if self.submitted else 0
        throughput = (round(len(self.finished) * 1000 / elapsed, 3)
                      if elapsed > 0 else None)
        return {
            "schema_version": 1,
            "status": "QUEUED_DATA_ONLY_NOT_EXECUTED",
            "topological_order": self.topological_order,
            "critical_path_ms_estimate": max(self.critical.values()),
            "critical_path_proven": False,
            "declared_work_ms": duration_ms,
            "queue_capacity": self.capacity,
            "submitted_task_tokens": len(self.tasks),
            "worker_slots": self.workers,
            "peak_inflight_tokens": self.peak_running,
            "peak_ready_tokens": self.peak_ready,
            "peak_pending_tokens": self.peak_pending,
            "backpressure_rejections": self.rejected_backpressure,
            "dynamic_admission": self.dynamic_admission,
            "states": dict(sorted(self.states.items())),
            "events": self.events,
            "queue_time_ms": self.clock_ms,
            "reported_complete_tokens": len(self.finished),
            "mean_reported_turnaround_ms": rounded_mean(turnarounds),
            "mean_admission_to_dispatch_ms": rounded_mean(waits),
            "reported_throughput_tokens_per_second": throughput,
            "peak_queue_pressure_ratio": round(self.peak_pending / self.capacity, 3),
            "actual_worker_throughput_verified": False,
            "task_code_executed": False,
            "external_completions_verified": False,
            "actual_process_resources_measured": False,
            "source_code_loaded": False,
        }


def inspect(document):
    scheduler = QueueManager(document)
    scheduler.apply(document["actions"])
    return scheduler.summary()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    try:
        document, digest = load_manifest(args.manifest)
        report = inspect(document)
    except (ValueError, OSError, TypeError) as error:
        # Exception objects from OS APIs may embed absolute sensitive paths.
        # Only return short internal machine-readable reason names.
        reason = str(error) if isinstance(error, ValueError) else "invalid_queue_input"
        if not re.fullmatch(r"[a-zA-Z_]{1,80}", reason):
            reason = "invalid_queue_input"
        print(json.dumps({"status": "NOT_RUN", "reason": reason,
                          "task_code_executed": False,
                          "external_completions_verified": False}))
        return 2
    report["manifest_sha256"] = digest
    print(json.dumps(report, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
