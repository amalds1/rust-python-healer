"""Inspect installed distribution metadata without importing package modules.

This is intentionally a bounded, limited Requires-Python evaluator, not a
complete PEP 440 dependency solver. Unsupported specifiers are UNKNOWN.
"""

import argparse
import ast
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import sys
import sysconfig
from urllib.parse import urlsplit


PACKAGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
# Deliberate final-release-only subset of PEP 440. Prerelease, postrelease,
# development and local labels are not inferred from a CPython version tuple.
# The arbitrary equality escape hatch is handled as *text*, not as a version.
CLAUSE_RE = re.compile(r"\s*(~=|>=|<=|==|!=|<|>)\s*(?:(\d+)!)?(\d+(?:\.\d+){0,5})(\.\*)?\s*\Z")
ARBITRARY_RE = re.compile(r"\s*===\s*([\x21-\x7e]{1,64})\s*\Z")
MAX_DIRECT_URL_BYTES = 32_768
MARKER_VARS = frozenset((
    "python_version", "python_full_version", "os_name", "sys_platform",
    "platform_machine", "platform_python_implementation", "platform_release",
    "platform_system", "platform_version", "implementation_name",
    "implementation_version", "extra",
))
VERSION_MARKERS = frozenset(("python_version", "python_full_version", "implementation_version"))


def normalize(value):
    if not PACKAGE_RE.fullmatch(value):
        raise ValueError("ongeldige package-identificatie")
    return re.sub(r"[-_.]+", "-", value).lower()


def requires_python(spec, version):
    """Evaluate supported final CPython PEP 440 clauses; fail closed otherwise.

    Observing a running interpreter does not give a release-candidate search
    universe, so prerelease/postrelease/development/local clauses stay UNKNOWN.
    No packaging imports, target-code execution or dependency resolution.
    """
    if not isinstance(spec, str) or not spec or len(spec) > 1024:
        return "UNKNOWN"
    if len(version) < 5 or version[3] != "final":
        return "UNKNOWN"
    observed = tuple(int(n) for n in version[:3])
    canonical_observed = ".".join(str(n) for n in observed)
    clauses = spec.split(",")
    if len(clauses) > 16:
        return "UNKNOWN"
    parsed = []
    # Validate *every* clause first. A malformed tail cannot accidentally be
    # accepted (or rejected) simply because an earlier clause decided False.
    for clause in clauses:
        arbitrary = ARBITRARY_RE.fullmatch(clause)
        if arbitrary:
            parsed.append(("===", 0, (), False, arbitrary.group(1)))
            continue
        match = CLAUSE_RE.fullmatch(clause)
        if not match:
            return "UNKNOWN"
        operator, epoch_text, digits, wildcard = match.groups()
        parts = tuple(int(n) for n in digits.split("."))
        epoch = int(epoch_text) if epoch_text is not None else 0
        if wildcard:
            if operator not in ("==", "!="):
                return "UNKNOWN"
        if operator == "~=" and len(parts) < 2:
            return "UNKNOWN"
        parsed.append((operator, epoch, parts, bool(wildcard), None))

    for operator, epoch, parts, wildcard, arbitrary in parsed:
        if operator == "===":
            # Unlike '==', PEP 440 === is case-insensitive *raw* equality;
            # e.g. ===3.9 is not the same as ===3.9.0.
            ok = canonical_observed.casefold() == arbitrary.casefold()
        elif wildcard:
            found = epoch == 0 and observed[:len(parts)] == parts
            ok = found if operator == "==" else not found
        else:
            # PEP 440 comparisons pad release segments with trailing zeroes.
            width = max(len(parts), len(observed))
            target = parts + (0,) * (width - len(parts))
            current = observed + (0,) * (width - len(observed))
            lhs, rhs = (0, current), (epoch, target)
            if operator == "~=":
                # ~=V.N is >=V.N, ==V.* ; ~=V.N.P is >=V.N.P, ==V.N.*
                ok = lhs >= rhs and epoch == 0 and observed[:len(parts) - 1] == parts[:-1]
            elif operator == "==":
                ok = lhs == rhs
            elif operator == "!=":
                ok = lhs != rhs
            elif operator == ">=":
                ok = lhs >= rhs
            elif operator == "<=":
                ok = lhs <= rhs
            elif operator == ">":
                # PEP 440 only excludes postreleases/local versions of the
                # *specified* release. A maintenance patch is a later release:
                # >3.9 accepts 3.9.25 (verified against packaging.SpecifierSet).
                ok = lhs > rhs
            else:
                ok = lhs < rhs
        if not ok:
            return "UNSATISFIED"
    return "SATISFIED"


def marker_context():
    """Only current interpreter metadata, never import user or package code."""
    version = sys.version_info
    implementation = sys.implementation.version
    suffix = "" if implementation.releaselevel == "final" else (
        implementation.releaselevel[0] + str(implementation.serial))
    return {
        "python_version": "{}.{}".format(*version[:2]),
        "python_full_version": "{}.{}.{}".format(*version[:3]),
        "os_name": os.name,
        "sys_platform": sys.platform,
        "platform_machine": platform.machine(),
        "platform_python_implementation": platform.python_implementation(),
        "platform_release": platform.release(),
        "platform_system": platform.system(),
        "platform_version": platform.version(),
        "implementation_name": sys.implementation.name,
        "implementation_version": "{}.{}.{}{}".format(
            implementation.major, implementation.minor, implementation.micro, suffix),
    }


def marker_value(node, environment):
    if isinstance(node, ast.Name) and node.id in MARKER_VARS:
        return node.id, environment.get(node.id)
    if isinstance(node, ast.Constant) and type(node.value) is str:
        return None, node.value
    raise ValueError("unsupported_marker_operand")


def compare_marker(node, environment):
    if len(node.ops) != 1 or len(node.comparators) != 1:
        raise ValueError("chained_marker_comparison")
    left_name, left = marker_value(node.left, environment)
    right_name, right = marker_value(node.comparators[0], environment)
    if left is None or right is None:
        raise ValueError("marker_context_unavailable")
    operation = node.ops[0]
    if isinstance(operation, (ast.In, ast.NotIn)):
        if left_name in VERSION_MARKERS or right_name in VERSION_MARKERS:
            raise ValueError("ambiguous_version_membership")
        result = left in right
        return result if isinstance(operation, ast.In) else not result
    if left_name == "extra" or right_name == "extra":
        if not isinstance(operation, (ast.Eq, ast.NotEq)):
            raise ValueError("extra_operator_unsupported")
        left, right = re.sub(r"[-_.]+", "-", left).lower(), re.sub(r"[-_.]+", "-", right).lower()
    if left_name in VERSION_MARKERS or right_name in VERSION_MARKERS:
        # Incomplete PEP 440 subset: final numeric releases only. Unknown
        # prerelease, epoch, local and wildcard syntax cannot get a PASS.
        if not re.fullmatch(r"\d+(?:\.\d+){1,2}", left) or not re.fullmatch(r"\d+(?:\.\d+){1,2}", right):
            raise ValueError("unsupported_version_marker")
        lhs = tuple(map(int, left.split(".")))
        rhs = tuple(map(int, right.split(".")))
        left, right = lhs + (0,) * (3 - len(lhs)), rhs + (0,) * (3 - len(rhs))
    elif not isinstance(operation, (ast.Eq, ast.NotEq)):
        # The January 2026 specification discourages ordered string fields.
        raise ValueError("ordered_string_marker_unsupported")
    if isinstance(operation, ast.Eq):
        return left == right
    if isinstance(operation, ast.NotEq):
        return left != right
    if isinstance(operation, ast.Lt):
        return left < right
    if isinstance(operation, ast.LtE):
        return left <= right
    if isinstance(operation, ast.Gt):
        return left > right
    if isinstance(operation, ast.GtE):
        return left >= right
    raise ValueError("unsupported_marker_operator")


def marker_node(node, environment):
    if isinstance(node, ast.Compare):
        return "SATISFIED" if compare_marker(node, environment) else "UNSATISFIED"
    if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
        values = []
        for item in node.values:
            try:
                values.append(marker_node(item, environment))
            except (ValueError, TypeError, RecursionError, AttributeError):
                values.append("UNKNOWN")
        if isinstance(node.op, ast.And):
            return ("UNSATISFIED" if "UNSATISFIED" in values else
                    "UNKNOWN" if "UNKNOWN" in values else "SATISFIED")
        return ("SATISFIED" if "SATISFIED" in values else
                "UNKNOWN" if "UNKNOWN" in values else "UNSATISFIED")
    raise ValueError("unsupported_marker_expression")


def marker_ast_budget(root):
    pending = [(root, 0)]
    visited = 0
    while pending:
        node, depth = pending.pop()
        visited += 1
        if visited > 256 or depth > 16:
            raise ValueError("marker_ast_budget")
        pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))


def marker_grammar(node):
    """Validate every branch before applying three-valued Boolean semantics.

    Unknown metadata can be masked by a false conjunction. Executable or
    unsupported grammar must never be masked by any Boolean branch.
    """
    if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
        for child in node.values:
            marker_grammar(child)
    elif isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
        if not isinstance(node.ops[0], (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn)):
            raise ValueError("unsupported_marker_operator")
        for operand in (node.left, node.comparators[0]):
            if not (isinstance(operand, ast.Name) or
                    isinstance(operand, ast.Constant) and type(operand.value) is str):
                raise ValueError("unsupported_marker_operand")
    else:
        raise ValueError("unsupported_marker_expression")


def environment_marker(text, extras=None, environment=None):
    """Conservative PEP 508 subset; AST is *inspected*, never evaluated."""
    if not isinstance(text, str) or not text or len(text) > 2048:
        return "UNKNOWN"
    if extras is not None and (len(extras) > 20 or any(
            not PACKAGE_RE.fullmatch(name) for name in extras)):
        return "UNKNOWN"
    try:
        root = ast.parse(text, mode="eval")
        marker_ast_budget(root)
        marker_grammar(root.body)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return "UNKNOWN"
    context = marker_context() if environment is None else dict(environment)
    # 'extra' is only meaningful in a context that explicitly selected it.
    variants = [None] if extras is None else (extras or [""])
    results = []
    for extra in variants:
        context["extra"] = extra
        try:
            results.append(marker_node(root.body, context))
        except (ValueError, TypeError, RecursionError, AttributeError):
            results.append("UNKNOWN")
    if "SATISFIED" in results:
        return "SATISFIED"
    return "UNKNOWN" if "UNKNOWN" in results else "UNSATISFIED"


def direct_url_origin(dist):
    """Inspect bounded PEP 610 data; never expose credentials or full URLs."""
    base = getattr(dist, "_path", None)
    if base is None:
        return {"status": "UNKNOWN", "reason": "distribution_path_unavailable"}
    path = Path(base) / "direct_url.json"
    if path.is_symlink():
        return {"status": "INVALID", "reason": "symlink_refused"}
    if not path.exists():
        return {"status": "NOT_DECLARED"}
    if not path.is_file():
        return {"status": "INVALID", "reason": "not_regular_file"}
    try:
        with path.open("rb") as handle:
            content = handle.read(MAX_DIRECT_URL_BYTES + 1)
        if len(content) > MAX_DIRECT_URL_BYTES:
            return {"status": "INVALID", "reason": "size_limit"}
        data = json.loads(content.decode("utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("url"), str):
            return {"status": "INVALID", "reason": "bad_structure"}
        source = data["url"]
        parsed = urlsplit(source)
        if not parsed.scheme or len(source) > 8192:
            return {"status": "INVALID", "reason": "bad_url"}
        modes = [key for key in ("vcs_info", "dir_info", "archive_info") if key in data]
        if len(modes) != 1 or not isinstance(data[modes[0]], dict):
            return {"status": "INVALID", "reason": "origin_mode"}
        mode = modes[0]
        info = data[mode]
        if mode == "vcs_info" and not isinstance(info.get("vcs"), str):
            return {"status": "INVALID", "reason": "vcs_missing"}
        if mode == "dir_info" and "editable" in info and not isinstance(info["editable"], bool):
            return {"status": "INVALID", "reason": "editable_not_boolean"}
        return {
            "status": "RECORDED_NOT_VERIFIED",
            "kind": {"vcs_info": "VCS", "dir_info": "DIRECTORY", "archive_info": "ARCHIVE"}[mode],
            "scheme": parsed.scheme.lower(),
            "host": (parsed.hostname or "")[:253],
            "editable": info.get("editable", False) if mode == "dir_info" else False,
            "vcs": info.get("vcs") if mode == "vcs_info" else None,
            "commit_recorded": bool(info.get("commit_id")) if mode == "vcs_info" else False,
            "url_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        }
    except (OSError, UnicodeError, ValueError, TypeError):
        return {"status": "INVALID", "reason": "unreadable_metadata"}


def inspect(packages, extra_roots=None, extras=None):
    names = [normalize(p) for p in packages]
    if not names or len(names) > 50:
        raise ValueError("geef 1 tot 50 geldige packages op")
    if extras is not None and (len(extras) > 20 or
                               any(not PACKAGE_RE.fullmatch(e) for e in extras)):
        raise ValueError("maximaal 20 geldige extra-namen")
    roots = {str(Path(p).resolve()) for p in
             (sysconfig.get_path("purelib"), sysconfig.get_path("platlib")) if p}
    for root in extra_roots or []:
        path = Path(root).resolve()
        if not path.is_dir():
            raise ValueError("metadata-map ontbreekt: " + str(path))
        roots.add(str(path))
    if len(roots) > 12:
        raise ValueError("maximaal 12 metadata-mappen")

    found = {name: [] for name in names}
    for dist in metadata.distributions(path=sorted(roots)):
        try:
            canonical = normalize(dist.metadata.get("Name", ""))
            if canonical not in found:
                continue
            name = dist.metadata.get("Name", "")
            version = str(dist.version or "")
            constraint = dist.metadata.get("Requires-Python", "")
            requirements = dist.metadata.get_all("Requires-Dist") or []
            if not version:
                continue
            marker_rows = []
            for raw in requirements[:100]:
                # A semicolon inside a quoted direct URL has richer grammar;
                # mark it UNKNOWN rather than guessing a dependency edge.
                expression = raw.split(";", 1)[1].strip() if ";" in raw else None
                ambiguous = (raw.count(";") != 1 or "@" in raw.split(";", 1)[0]) if expression else False
                marker_rows.append({
                    "marker_status": "NOT_DECLARED" if expression is None else
                    "UNKNOWN" if ambiguous else environment_marker(expression, extras),
                    "specifier_parse": "NOT_RUN",
                })
            found[canonical].append({
                "name": name, "version": version,
                "requires_python": constraint,
                "python_constraint_status": requires_python(constraint, sys.version_info),
                "requires_dist": requirements[:100],
                "requirement_marker_results": marker_rows,
                "requirements_truncated": len(requirements) > 100,
                "direct_url": direct_url_origin(dist),
            })
        except (KeyError, ValueError, OSError):
            # A corrupt distribution never creates a false installed PASS.
            continue

    records = []
    for name in dict.fromkeys(names):
        versions = found[name]
        records.append({
            "package": name,
            "status": "MISSING" if not versions else ("AMBIGUOUS" if len(versions) > 1 else "FOUND"),
            "distributions": versions,
        })
    return {
        "status": "INSPECTED", "implementation": sys.implementation.name,
        "python": ".".join(str(x) for x in sys.version_info[:3]),
        "packages": records,
        "runtime_compatibility": "NOT_VERIFIED",
        "dependency_resolution": "NOT_RUN",
        "source_executed": False,
        "note": "Metadata zonder package-import; gedeeltelijke PEP 440/508-evaluatie, geen transitive dependency solver",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", action="append", required=True)
    parser.add_argument("--metadata-dir", action="append", default=[])
    parser.add_argument("--extra", action="append", default=None)
    args = parser.parse_args()
    print(json.dumps(inspect(args.package, args.metadata_dir, args.extra), ensure_ascii=False))


if __name__ == "__main__":
    main()
