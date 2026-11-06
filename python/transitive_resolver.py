"""F059 deterministic, bounded backtracking for an *explicit local* catalog.

Supports only final-release numeric PEP 440 versions and operators ==, !=,
<, <=, >, >=, ~= (no prereleases, epoch, local, wildcard, PEP 508 text markers).
Dependencies/extras are structured, not imported or evaluated. A missing
candidate or unsupported syntax produces UNKNOWN, never a fabricated PASS.
This does not discover packages, install dependencies, access the network or
execute any user code; solving the supplied finite catalog is not proof of an
actual environment's installability, binary ABI, platform or trust.
"""

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys


MAX_INPUT_BYTES = 1_000_000
MAX_PACKAGES = 64
MAX_VERSIONS_PER_PACKAGE = 12
MAX_TOTAL_DEPENDENCIES = 500
MAX_ROOTS = 64
MAX_STATE_BUDGET = 20_000
MAX_CLAUSES = 8
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}\Z", re.ASCII)
_FINAL = re.compile(r"\d+(?:\.\d+){0,4}\Z", re.ASCII)
_CLAUSE = re.compile(r"(==|!=|>=|<=|~=|>|<)\s*(\d+(?:\.\d+){0,4})\Z", re.ASCII)
_PYTHON = re.compile(r"3\.(?:9|1[0-5])\Z", re.ASCII)


class UnsupportedCatalog(Exception):
    pass


def canonical(value):
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise UnsupportedCatalog("unsupported_package_or_extra_name")
    return re.sub(r"[-_.]+", "-", value).lower()


def final_version(value):
    if not isinstance(value, str) or not _FINAL.fullmatch(value):
        raise UnsupportedCatalog("unsupported_pep440_version")
    chunks = value.split(".")
    if any(len(chunk) > 8 or (len(chunk) > 1 and chunk.startswith("0")) for chunk in chunks):
        raise UnsupportedCatalog("unsupported_pep440_version")
    return tuple(int(chunk) for chunk in chunks)


def clauses(value):
    if not isinstance(value, str) or len(value) > 200:
        raise UnsupportedCatalog("unsupported_pep440_specifier")
    if not value.strip():
        return ()
    parts = value.split(",")
    if len(parts) > MAX_CLAUSES:
        raise UnsupportedCatalog("unsupported_pep440_specifier")
    parsed = []
    for part in parts:
        match = _CLAUSE.fullmatch(part.strip())
        if not match:
            raise UnsupportedCatalog("unsupported_pep440_specifier")
        op, raw = match.groups()
        release = final_version(raw)
        if op == "~=" and len(release) < 2:
            raise UnsupportedCatalog("unsupported_pep440_specifier")
        parsed.append((op, release))
    return tuple(parsed)


def _compare(a, b):
    width = max(len(a), len(b))
    left, right = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (left > right) - (left < right)


def satisfies(version, spec):
    for op, value in spec:
        order = _compare(version, value)
        if op == "==" and order != 0:
            return False
        if op == "!=" and order == 0:
            return False
        if op == ">" and order <= 0:
            return False
        if op == ">=" and order < 0:
            return False
        if op == "<" and order >= 0:
            return False
        if op == "<=" and order > 0:
            return False
        if op == "~=":
            # ~=1.4.5 means >=1.4.5,<1.5; ~=1.4 means >=1.4,<2.
            prefix = value[:-1]
            ceiling = prefix[:-1] + (prefix[-1] + 1,)
            if order < 0 or _compare(version, ceiling) >= 0:
                return False
    return True


def _extra_list(value):
    if not isinstance(value, list) or len(value) > 16:
        raise UnsupportedCatalog("invalid_extras")
    extras = [canonical(name) for name in value]
    if len(extras) != len(set(extras)):
        raise UnsupportedCatalog("duplicate_extras")
    return tuple(sorted(extras))


def _requirement(raw):
    if not isinstance(raw, dict) or set(raw) - {"name", "specifier", "extras", "when_extras", "python"}:
        raise UnsupportedCatalog("invalid_requirement_fields")
    if "name" not in raw:
        raise UnsupportedCatalog("missing_requirement_name")
    return {
        "name": canonical(raw["name"]),
        "specifier": str(raw.get("specifier", "")) if isinstance(raw.get("specifier", ""), str) else "INVALID",
        "constraints": clauses(raw.get("specifier", "")),
        "extras": _extra_list(raw.get("extras", [])),
        "when_extras": _extra_list(raw.get("when_extras", [])),
        "python": clauses(raw.get("python", "")),
    }


def _prepare(catalog, roots, python_version, max_states):
    if (not isinstance(python_version, str) or not _PYTHON.fullmatch(python_version)
            or not isinstance(max_states, int) or type(max_states) is bool
            or not 1 <= max_states <= MAX_STATE_BUDGET):
        raise UnsupportedCatalog("invalid_runtime_or_budget")
    if not isinstance(catalog, dict) or len(catalog) > MAX_PACKAGES:
        raise UnsupportedCatalog("catalog_package_budget_exceeded")
    if not isinstance(roots, list) or not 1 <= len(roots) <= MAX_ROOTS:
        raise UnsupportedCatalog("invalid_root_requirements")
    target = final_version(python_version)
    versions = {}
    seen_names = set()
    dependencies = 0
    for raw_name, candidates in catalog.items():
        name = canonical(raw_name)
        if name in seen_names:
            raise UnsupportedCatalog("canonical_package_name_collision")
        seen_names.add(name)
        if (not isinstance(candidates, list)
                or len(candidates) > MAX_VERSIONS_PER_PACKAGE):
            raise UnsupportedCatalog("package_candidate_budget_exceeded")
        normalized = []
        version_seen = set()
        for item in candidates:
            if not isinstance(item, dict) or set(item) - {"version", "requires_python", "requires"}:
                raise UnsupportedCatalog("invalid_candidate_fields")
            label = item.get("version")
            release = final_version(label)
            norm = release + (0,) * (5 - len(release))
            if norm in version_seen:
                raise UnsupportedCatalog("duplicate_normalized_version")
            version_seen.add(norm)
            requires = item.get("requires", [])
            if not isinstance(requires, list) or len(requires) > 64:
                raise UnsupportedCatalog("dependency_budget_exceeded")
            dependencies += len(requires)
            normalized.append({"version": label, "release": release,
                               "requires_python": clauses(item.get("requires_python", "")),
                               "requires": tuple(_requirement(req) for req in requires)})
        versions[name] = sorted(normalized, key=lambda item: item["release"], reverse=True)
    if dependencies > MAX_TOTAL_DEPENDENCIES:
        raise UnsupportedCatalog("dependency_budget_exceeded")
    selected_roots = [_requirement(root) for root in roots]
    if any(req["when_extras"] for req in selected_roots):
        raise UnsupportedCatalog("root_cannot_be_optional")
    return versions, selected_roots, target


def _propagate(selected, roots, target):
    constraints = {}
    extras = {}
    for root in roots:
        if not satisfies(target, root["python"]):
            continue
        constraints.setdefault(root["name"], []).append((root["specifier"], root["constraints"], "ROOT"))
        extras.setdefault(root["name"], set()).update(root["extras"])
    activated = set()
    while True:
        changed = False
        for pkg in sorted(selected):
            if pkg not in constraints:
                continue
            candidate = selected[pkg]
            for index, requirement in enumerate(candidate["requires"]):
                key = (pkg, index)
                if key in activated:
                    continue
                if (requirement["when_extras"] and not
                        set(requirement["when_extras"]).intersection(extras.get(pkg, set()))):
                    continue
                if not satisfies(target, requirement["python"]):
                    continue
                activated.add(key)
                other = requirement["name"]
                constraints.setdefault(other, []).append((
                    requirement["specifier"], requirement["constraints"],
                    "{}@{}".format(pkg, candidate["version"])))
                extras.setdefault(other, set()).update(requirement["extras"])
                changed = True
        if not changed:
            return constraints, extras


def _witness(package, terms, available, unknown=False):
    return {"package": package,
            "requirements": [{"specifier": spec, "from": origin} for spec, _, origin in terms],
            "available_versions": [c["version"] for c in available][:MAX_VERSIONS_PER_PACKAGE],
            "witness_scope": "LOCAL_BRANCH_NOT_MINIMAL_UNSAT_CORE",
            "missing_candidate_catalog": unknown}


def resolve(catalog, roots, python_version=None, max_states=5000):
    """Backtrack explicit candidates to a fixed point, without side effects."""
    baseline = {"network_used": False, "installed_packages": False,
                "user_code_executed": False, "environment_installability_proven": False,
                "pep440_complete": False}
    if python_version is None:
        python_version = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
    try:
        versions, prepared_roots, target = _prepare(catalog, roots, python_version, max_states)
    except (UnsupportedCatalog, ValueError, TypeError) as exc:
        code = str(exc) if isinstance(exc, UnsupportedCatalog) else "invalid_catalog"
        return {**baseline, "status": "UNKNOWN_UNSUPPORTED_INPUT", "reason": code,
                "states_explored": 0}
    visited = [0]

    def candidates_for(pkg, terms):
        return [cand for cand in versions[pkg]
                if satisfies(target, cand["requires_python"]) and
                all(satisfies(cand["release"], clauseset) for _, clauseset, _ in terms)]

    def search(selected):
        visited[0] += 1
        if visited[0] > max_states:
            return "BUDGET", None
        constraints, extras = _propagate(selected, prepared_roots, target)
        options = {}
        for pkg in sorted(constraints):
            if pkg not in versions or not versions[pkg]:
                return "UNKNOWN_MISSING", _witness(pkg, constraints[pkg], [], True)
            valid = candidates_for(pkg, constraints[pkg])
            if not valid:
                return "CONFLICT", _witness(pkg, constraints[pkg], versions[pkg])
            if pkg in selected and selected[pkg] not in valid:
                return "CONFLICT", _witness(pkg, constraints[pkg], versions[pkg])
            if pkg not in selected:
                options[pkg] = valid
        if not options:
            return "SOLVED", {pkg: cand["version"] for pkg, cand in sorted(selected.items())}
        # Fail-first and stable tie-breaking keep search finite and reproducible.
        package = min(options, key=lambda name: (len(options[name]), name))
        first_conflict = None
        first_unknown = None
        for candidate in options[package]:
            attempt = dict(selected)
            attempt[package] = candidate
            status, payload = search(attempt)
            if status in ("SOLVED", "BUDGET"):
                return status, payload
            if status == "UNKNOWN_MISSING":
                first_unknown = first_unknown or payload
            if status == "CONFLICT":
                first_conflict = first_conflict or payload
        return ("UNKNOWN_MISSING", first_unknown) if first_unknown else ("CONFLICT", first_conflict)

    status, data = search({})
    if status == "SOLVED":
        return {**baseline, "status": "SATISFIABLE_IN_LOCAL_FINAL_RELEASE_CATALOG",
                "assignment": data, "selected_packages": len(data),
                "states_explored": visited[0], "supported_scope": "NUMERIC_FINAL_PEP440_SUBSET"}
    if status == "CONFLICT":
        return {**baseline, "status": "CONFLICT_PROVEN_IN_EXPLICIT_LOCAL_CATALOG",
                "conflict_witness": data, "states_explored": visited[0],
                "supported_scope": "NUMERIC_FINAL_PEP440_SUBSET"}
    if status == "UNKNOWN_MISSING":
        return {**baseline, "status": "UNKNOWN_MISSING_LOCAL_CANDIDATES",
                "conflict_witness": data, "states_explored": visited[0]}
    return {**baseline, "status": "NOT_RUN_BUDGET_EXHAUSTED",
            "states_explored": visited[0], "budget": max_states}


def _read_catalog_file(path):
    before = Path(path).lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_INPUT_BYTES:
        raise ValueError("unsafe_input_file")
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("input_file_changed")
        content = stream.read(MAX_INPUT_BYTES + 1)
        after = os.fstat(stream.fileno())
    if (len(content) > MAX_INPUT_BYTES or (before.st_size, before.st_mtime_ns, before.st_ino)
            != (after.st_size, after.st_mtime_ns, after.st_ino)):
        raise ValueError("input_file_changed")
    def unique_object(pairs):
        values = {}
        for name, value in pairs:
            if name in values:
                raise ValueError("ambiguous_duplicate_json_field")
            values[name] = value
        return values

    return json.loads(content.decode("utf-8"), object_pairs_hook=unique_object)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline bounded transitive final-release resolver")
    parser.add_argument("--input", required=True)
    parser.add_argument("--python-version", default=None)
    parser.add_argument("--max-states", type=int, default=5000)
    args = parser.parse_args(argv)
    try:
        doc = _read_catalog_file(args.input)
        if not isinstance(doc, dict):
            raise ValueError("invalid_catalog")
        report = resolve(doc.get("catalog"), doc.get("roots"), args.python_version, args.max_states)
    except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
        report = {"status": "UNKNOWN_UNSUPPORTED_INPUT", "reason": "unreadable_local_catalog",
                  "network_used": False, "installed_packages": False, "user_code_executed": False}
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
