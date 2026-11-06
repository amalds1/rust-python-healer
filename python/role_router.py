"""Bounded, deterministic, data-only routing for 36 *planned* specialist roles.

No model is called, no subprocess is started, and no task is executed.  This
module makes reservation decisions that a separately authorised executor could
consume, after its own verification and approval controls.

CLI: python -I -S -B python/role_router.py --roles config/agent_roles.json
     --tasks /path/to/task_request.json
"""

import argparse
import hashlib
import importlib.util
from functools import lru_cache
import json
import os
import re
import stat
import sys
from pathlib import Path
from collections import Counter


ROLE_CLUSTERS = ("Regie", "Diagnose", "Herstel", "Kennis", "Data", "QA")
MODEL_NAMES = ("gpt-6.1-sol", "gpt-6-astra", "gpt-6-luna")
RISK_LEVELS = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
ROLE_KEYS = frozenset(("id", "name", "cluster", "capabilities", "model_hints",
                       "risk_tier", "max_parallel", "quality_hint_percent",
                       "cost_hint_units", "latency_hint_ms"))
TASK_KEYS = frozenset(("task_id", "required_capabilities", "priority", "risk_tier",
                       "max_cost_units", "max_latency_ms", "min_quality_percent"))
CAPABILITY_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,39}$", re.ASCII)
TASK_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$", re.ASCII)
MAX_ROLES_BYTES = 131072
MAX_REQUEST_BYTES = 65536
MAX_TASKS = 64


class RoutingError(ValueError):
    """Input was rejected before any work or resource reservation."""


def _integer(value, minimum, maximum, name):
    if type(value) is not int or not minimum <= value <= maximum:
        raise RoutingError("Invalid " + name)
    return value


def _exact_keys(value, keys, label):
    if type(value) is not dict or frozenset(value) != frozenset(keys):
        raise RoutingError("Invalid " + label + " fields")


def _unique_pairs(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise RoutingError("Duplicate JSON field")
        data[key] = value
    return data


def _bad_number(_value):
    raise RoutingError("Non-finite number prohibited")


@lru_cache(maxsize=1)
def _windows_security():
    embedded = globals().get("_RPH_WINDOWS_SECURITY")
    if embedded is not None:
        return embedded
    spec = importlib.util.spec_from_file_location("rph_role_windows_security",
        Path(__file__).with_name("windows_descriptor_security_v029.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_posix_document_bytes(path, byte_limit):
    """POSIX no-follow regular-file read with explicit descriptor ownership."""
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_NONBLOCK", 0))
    except (OSError, ValueError, TypeError):
        raise RoutingError("Document cannot be read")
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RoutingError("Document must be a single-link regular file")
        if info.st_size > byte_limit:
            raise RoutingError("Document size limit exceeded")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(byte_limit + 1)
        after = os.fstat(descriptor)
        if (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
                or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) !=
                   (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or len(payload) != info.st_size or len(payload) > byte_limit):
            raise RoutingError("Document changed or size limit exceeded")
    except OSError:
        raise RoutingError("Document cannot be read")
    finally:
        os.close(descriptor)
    return payload


def _read_document(path, byte_limit):
    """Public bounded JSON data; Windows reads the held no-follow leaf HANDLE.

    JSON is not required to be private. Every Windows parent/leaf is checked
    by the existing native descriptor adapter; no sandbox guarantee is made.
    """
    if os.name == "nt":
        try:
            location = Path(path).absolute()
            payload = _windows_security().read_project_file(
                location.parent, [location.name], byte_limit)
        except (OSError, ValueError, TypeError):
            raise RoutingError("Document cannot be read") from None
    else:
        payload = _read_posix_document_bytes(path, byte_limit)
    try:
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_pairs,
                              parse_constant=_bad_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise RoutingError("Invalid UTF-8 JSON document")
    return document, hashlib.sha256(payload).hexdigest()


def _words(items, maximum, label):
    if (type(items) is not list or not 1 <= len(items) <= maximum
            or any(type(item) is not str or not CAPABILITY_PATTERN.fullmatch(item)
                   for item in items) or len(set(items)) != len(items)):
        raise RoutingError("Invalid " + label)
    return items


def validate_roles(document):
    """Require exactly the planned 36 role IDs, grouped six by six."""
    _exact_keys(document, ("schema_version", "source", "active_processes_declared", "roles"),
                "roles manifest")
    if document["schema_version"] != 1 or type(document["schema_version"]) is not int:
        raise RoutingError("Unsupported roles schema")
    if document["source"] != "docs/ARCHITECTURE.md#36-specialistische-rollen":
        raise RoutingError("Unknown roles source")
    if type(document["active_processes_declared"]) is not int or document["active_processes_declared"] != 0:
        raise RoutingError("Roles must not claim active processes")
    roles = document["roles"]
    if type(roles) is not list or len(roles) != 36:
        raise RoutingError("Expected exactly 36 specialist roles")
    identifiers = set()
    names = set()
    clusters = Counter()
    for role in roles:
        _exact_keys(role, ROLE_KEYS, "role")
        role_id = role["id"]
        if type(role_id) is not str or not re.fullmatch(r"R(0[1-9]|[12][0-9]|3[0-6])", role_id):
            raise RoutingError("Invalid specialist ID")
        if role_id in identifiers:
            raise RoutingError("Duplicate specialist ID")
        identifiers.add(role_id)
        name = role["name"]
        if (type(name) is not str or not 2 <= len(name) <= 48
                or not name.isascii() or any(not (c.isalnum() or c in " -/") for c in name)
                or name in names):
            raise RoutingError("Invalid specialist name")
        names.add(name)
        cluster = role["cluster"]
        if type(cluster) is not str or cluster not in ROLE_CLUSTERS:
            raise RoutingError("Invalid specialist cluster")
        expected_cluster = ROLE_CLUSTERS[(int(role_id[1:]) - 1) // 6]
        if cluster != expected_cluster:
            raise RoutingError("Specialist cluster does not match stable role ID")
        clusters[cluster] += 1
        _words(role["capabilities"], 6, "role capabilities")
        models = role["model_hints"]
        if (type(models) is not list or not 1 <= len(models) <= len(MODEL_NAMES)
                or any(type(model) is not str or model not in MODEL_NAMES for model in models)
                or len(set(models)) != len(models)):
            raise RoutingError("Invalid model hints")
        if type(role["risk_tier"]) is not str or role["risk_tier"] not in RISK_LEVELS:
            raise RoutingError("Invalid specialist risk policy")
        _integer(role["max_parallel"], 1, 8, "specialist slots")
        _integer(role["quality_hint_percent"], 0, 100, "quality hint")
        _integer(role["cost_hint_units"], 1, 1000, "cost hint")
        _integer(role["latency_hint_ms"], 1, 600000, "latency hint")
    if identifiers != {"R%02d" % number for number in range(1, 37)}:
        raise RoutingError("Incomplete specialist registry")
    if set(clusters) != set(ROLE_CLUSTERS) or any(value != 6 for value in clusters.values()):
        raise RoutingError("Incomplete specialist clusters")
    return roles


def validate_request(document):
    if type(document) is not dict or frozenset(document) != frozenset(
            ("schema_version", "budget_units", "max_reserved_slots", "tasks", "model_feedback")):
        raise RoutingError("Invalid routing request fields")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise RoutingError("Unsupported request schema")
    _integer(document["budget_units"], 1, 100000, "budget")
    _integer(document["max_reserved_slots"], 1, 36, "slot capacity")
    tasks = document["tasks"]
    if type(tasks) is not list or not 1 <= len(tasks) <= MAX_TASKS:
        raise RoutingError("Invalid task count")
    identifiers = set()
    for task in tasks:
        _exact_keys(task, TASK_KEYS, "routing task")
        task_id = task["task_id"]
        if (type(task_id) is not str or not TASK_ID_PATTERN.fullmatch(task_id)
                or task_id in identifiers):
            raise RoutingError("Invalid or duplicate task ID")
        identifiers.add(task_id)
        _words(task["required_capabilities"], 6, "task capabilities")
        _integer(task["priority"], 0, 100, "task priority")
        if type(task["risk_tier"]) is not str or task["risk_tier"] not in RISK_LEVELS:
            raise RoutingError("Invalid task risk")
        _integer(task["max_cost_units"], 1, 1000, "task cost ceiling")
        _integer(task["max_latency_ms"], 1, 600000, "task latency ceiling")
        _integer(task["min_quality_percent"], 0, 100, "task quality floor")
    feedback = document["model_feedback"]
    if (type(feedback) is not dict or len(feedback) > len(MODEL_NAMES)
            or any(type(model) is not str or model not in MODEL_NAMES for model in feedback)):
        raise RoutingError("Invalid model feedback keys")
    for metrics in feedback.values():
        _exact_keys(metrics, ("quality_percent", "cost_units", "latency_ms"), "model feedback")
        _integer(metrics["quality_percent"], 0, 100, "model feedback quality")
        _integer(metrics["cost_units"], 1, 1000, "model feedback cost")
        _integer(metrics["latency_ms"], 1, 600000, "model feedback latency")
    return tasks, feedback


def _model_metrics(role, model, feedback):
    if feedback:
        if model not in feedback:
            return None
        return feedback[model], "UNVERIFIED_SUPPLIED_FEEDBACK"
    return {
        "quality_percent": role["quality_hint_percent"],
        "cost_units": role["cost_hint_units"],
        "latency_ms": role["latency_hint_ms"],
    }, "UNVERIFIED_MANIFEST_HINT"


def plan_routes(roles_document, request_document, roles_sha256=None, request_sha256=None):
    """Reserve bounded *intent only*; never create live agents or invoke models."""
    roles = validate_roles(roles_document)
    tasks, feedback = validate_request(request_document)
    remaining_budget = request_document["budget_units"]
    maximum_slots = request_document["max_reserved_slots"]
    role_slots = Counter()
    assignments = []
    unassigned = []
    for task in sorted(tasks, key=lambda value: (-value["priority"], value["task_id"])):
        capabilities = set(task["required_capabilities"])
        compatible = [role for role in roles
                      if capabilities.issubset(set(role["capabilities"]))
                      and RISK_LEVELS[role["risk_tier"]] >= RISK_LEVELS[task["risk_tier"]]]
        if not compatible:
            unassigned.append({"task_id": task["task_id"], "reason": "NO_SUITABLE_ROLE"})
            continue
        candidates = []
        for role in compatible:
            for model in role["model_hints"]:
                measured = _model_metrics(role, model, feedback)
                if measured is None:
                    continue
                metrics, evidence = measured
                if (metrics["cost_units"] > task["max_cost_units"]
                        or metrics["latency_ms"] > task["max_latency_ms"]
                        or metrics["quality_percent"] < task["min_quality_percent"]):
                    continue
                candidates.append((role, model, metrics, evidence))
        if not candidates:
            unassigned.append({"task_id": task["task_id"], "reason": "MODEL_POLICY_LIMIT"})
            continue
        if len(assignments) >= maximum_slots:
            unassigned.append({"task_id": task["task_id"], "reason": "GLOBAL_CAPACITY_LIMIT"})
            continue
        capacity = [candidate for candidate in candidates
                    if role_slots[candidate[0]["id"]] < candidate[0]["max_parallel"]]
        if not capacity:
            unassigned.append({"task_id": task["task_id"], "reason": "ROLE_CAPACITY_LIMIT"})
            continue
        affordable = [candidate for candidate in capacity
                      if candidate[2]["cost_units"] <= remaining_budget]
        if not affordable:
            unassigned.append({"task_id": task["task_id"], "reason": "BUDGET_LIMIT"})
            continue
        # Prefer quality, then lower cost, then lower latency, then a stable ID.
        selected = min(affordable, key=lambda candidate: (
            -candidate[2]["quality_percent"], candidate[2]["cost_units"],
            candidate[2]["latency_ms"], candidate[0]["id"], candidate[1]))
        role, model, metrics, evidence = selected
        role_slots[role["id"]] += 1
        remaining_budget -= metrics["cost_units"]
        assignments.append({
            "task_id": task["task_id"], "priority": task["priority"],
            "role_id": role["id"], "role_name": role["name"],
            "model_hint": model, "estimated_quality_percent": metrics["quality_percent"],
            "reserved_cost_units": metrics["cost_units"],
            "estimated_latency_ms": metrics["latency_ms"],
            "estimate_source": evidence, "execution_state": "NOT_EXECUTED",
        })
    return {
        "status": "PLANNED_ONLY_NOT_EXECUTED",
        "schema_version": 1,
        "roles_registered": 36,
        "role_registry_source": roles_document["source"],
        "roles_sha256": roles_sha256,
        "request_sha256": request_sha256,
        "task_count": len(tasks),
        "assignments": assignments,
        "unassigned": unassigned,
        "max_reserved_slots": maximum_slots,
        "budget_units": request_document["budget_units"],
        "reserved_cost_units": request_document["budget_units"] - remaining_budget,
        "remaining_budget_units": remaining_budget,
        "active_agents_started": 0,
        "models_invoked": 0,
        "tasks_executed": 0,
        "feedback_verified": False,
        "policy_only": True,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roles", required=True, help="36-role registry JSON")
    parser.add_argument("--tasks", required=True, help="bounded routing request JSON")
    args = parser.parse_args(argv)
    try:
        roles, roles_sha256 = _read_document(args.roles, MAX_ROLES_BYTES)
        request, request_sha256 = _read_document(args.tasks, MAX_REQUEST_BYTES)
        result = plan_routes(roles, request, roles_sha256, request_sha256)
    except RoutingError as exc:
        result = {"status": "NOT_RUN", "reason": str(exc),
                  "active_agents_started": 0, "models_invoked": 0,
                  "tasks_executed": 0}
        print(json.dumps(result, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
