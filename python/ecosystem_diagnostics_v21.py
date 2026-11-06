"""Conservative ecosystem-specific static diagnostics + declarative adapter SDK.

Supported Python 3.9+ via its own ast parser. NEVER imports user packages,
executes target source, resolves dependencies, opens model checkpoints, uses
CUDA, validates schemas/native ABI, contacts workers or accesses the network.
All reported diagnoses are observations/pattern candidates, not verified
runtime causes or independently qualified repairs.
"""

import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tokenize


MAX_SOURCE = 1_048_576
MAX_TRACE = 131_072
MAX_ADAPTER = 32_768
MAX_NODES = 25_000
MAX_FINDINGS = 500
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
RULE_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,95}\Z")
CALL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){1,6}\Z")
PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){1,3}\Z")
SDK_SCHEMA_VERSION = 1


ERROR_PATTERNS = (
    ("TORCH_CUDA_OOM", "pytorch", r"(?:CUDA out of memory|torch\.OutOfMemoryError)"),
    ("TORCH_DEVICE_MISMATCH", "pytorch", r"Expected all tensors to be on the same device"),
    ("JAX_TRACER_CONVERSION", "jax", r"(?:TracerArrayConversionError|ConcretizationTypeError)"),
    ("TENSORFLOW_GRAPH_ERROR", "tensorflow", r"(?:InvalidArgumentError|InaccessibleTensorError)"),
    ("CELERY_WORKER_TIMEOUT", "celery", r"(?:SoftTimeLimitExceeded|TimeLimitExceeded)"),
    ("REDIS_CONNECTION", "redis", r"(?:redis\.exceptions\.ConnectionError|RedisConnectionError)"),
    ("PYARROW_FORMAT_ERROR", "pyarrow", r"(?:pyarrow\.lib\.ArrowInvalid|ArrowInvalid:)"),
    ("PROTOBUF_DECODE", "protobuf", r"(?:google\.protobuf\.message\.DecodeError|DecodeError:)"),
    ("SQLALCHEMY_ASYNC_CONTEXT", "sqlalchemy", r"(?:MissingGreenlet|sqlalchemy\.exc\.AwaitRequired)"),
    ("DJANGO_CONFIG", "django", r"django\.core\.exceptions\.ImproperlyConfigured"),
    ("NATIVE_IMPORT_SYMBOL", "native-extensions", r"(?:undefined symbol:|Symbol not found:|dynamic module does not define module export function)"),
)


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def read_bounded(path, maximum):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("input_symlink_refused")
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise ValueError("input_not_unique_bounded_file")
        content = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if len(content) > maximum or (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) != (
            after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns):
        raise ValueError("input_changed_or_too_large")
    return content


def parse_source(content):
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(content).readline)
        text = content.decode(encoding)
        tree = ast.parse(text, filename="[STATIC_SOURCE]", mode="exec")
    except (SyntaxError, UnicodeError, LookupError, ValueError):
        return None
    if sum(1 for _ in ast.walk(tree)) > MAX_NODES:
        return None
    return tree


def dotted(node):
    """Read *syntax* only; never evaluate Python attribute access."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return base + "." + node.attr if base else None
    return None


def literal_shape(node):
    if isinstance(node, (ast.List, ast.Tuple)):
        child = [literal_shape(item) for item in node.elts]
        if any(value is None for value in child) or len(set(child)) > 1:
            return None
        return (len(child),) + (child[0] if child else ())
    if isinstance(node, ast.Constant) and type(node.value) in (int, float, bool, str, bytes):
        return ()
    return None


def static_shape_tuple(node):
    if isinstance(node, ast.Constant) and type(node.value) is int:
        dims = (node.value,)
    elif isinstance(node, (ast.Tuple, ast.List)):
        values = [x.value if isinstance(x, ast.Constant) and type(x.value) is int else None
                  for x in node.elts]
        if any(value is None for value in values):
            return None
        dims = tuple(values)
    else:
        return None
    if len(dims) > 8 or any(dim < -1 or dim > 1_000_000 for dim in dims):
        return None
    return dims


def shape_product(dims):
    total = 1
    for dimension in dims:
        if dimension < 0:
            return None
        total *= dimension
        if total > 100_000_000:
            return None
    return total


def shape_can_broadcast(source, target):
    """Pure NumPy broadcast dimension test for fully static integer shapes."""
    if any(x < 0 for x in source + target):
        return None
    for origin, dest in zip(reversed(source), reversed(target)):
        if origin not in (1, dest):
            return False
    if len(source) > len(target):
        return False
    return True


def make_finding(rule_id, ecosystem, node, confidence="STATIC_CANDIDATE", kind="AST"):
    return {"rule_id": rule_id, "ecosystem": ecosystem,
            "line": int(getattr(node, "lineno", 0)),
            "column": int(getattr(node, "col_offset", 0)),
            "confidence": confidence,
            "basis": kind,
            "behavioral_cause_verified": False,
            "autofix_permitted": False}


def analyze_static(tree, versions):
    imports, array_shapes, dataframes, routes, findings = {}, {}, {}, {}, []
    frameworks = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                if base in ("numpy", "pandas", "torch", "tensorflow", "jax", "django",
                            "fastapi", "flask", "sqlalchemy", "celery", "redis", "pyarrow"):
                    imports[alias.asname or base] = alias.name
                    frameworks.add(base)
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            if base in ("numpy", "pandas", "torch", "tensorflow", "jax", "django",
                        "fastapi", "flask", "sqlalchemy", "celery", "redis", "pyarrow"):
                frameworks.add(base)
                for alias in node.names:
                    if alias.name != "*":
                        imports[alias.asname or alias.name] = node.module + "." + alias.name

    def resolved_call(node):
        name = dotted(node)
        if not name:
            return None
        parts = name.split(".")
        mapped = imports.get(parts[0])
        return ".".join([mapped] + parts[1:]) if mapped else name

    # Conservative single-module assignments. Reassignments to unknown
    # values remove the previous shape/schema candidate, never keep it stale.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        name, expr = node.targets[0].id, node.value
        array_shapes.pop(name, None)
        dataframes.pop(name, None)
        if not isinstance(expr, ast.Call):
            continue
        callee = resolved_call(expr.func)
        if callee == "numpy.array" and expr.args:
            candidate = literal_shape(expr.args[0])
            if candidate is not None:
                array_shapes[name] = candidate
        elif callee == "pandas.DataFrame" and expr.args and isinstance(expr.args[0], ast.Dict):
            keys = expr.args[0].keys
            if all(isinstance(key, ast.Constant) and isinstance(key.value, str)
                   for key in keys):
                dataframes[name] = set(key.value for key in keys)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            direct = resolved_call(node.func)
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                variable = node.func.value.id
                if node.func.attr == "reshape" and variable in array_shapes:
                    target = (static_shape_tuple(node.args[0]) if len(node.args) == 1 else
                              static_shape_tuple(ast.Tuple(elts=node.args, ctx=ast.Load())))
                    if target is not None and -1 not in target:
                        initial = shape_product(array_shapes[variable])
                        requested = shape_product(target)
                        if initial is not None and requested is not None and initial != requested:
                            findings.append(make_finding("NUMPY_RESHAPE_COUNT_MISMATCH", "numpy", node,
                                                         "STATIC_LITERAL_SHAPE_CANDIDATE"))
            if direct == "numpy.reshape" and len(node.args) >= 2 and isinstance(node.args[0], ast.Name):
                source = array_shapes.get(node.args[0].id)
                target = static_shape_tuple(node.args[1])
                if source is not None and target is not None and -1 not in target and (
                        shape_product(source) != shape_product(target)):
                    findings.append(make_finding("NUMPY_RESHAPE_COUNT_MISMATCH", "numpy", node,
                                                 "STATIC_LITERAL_SHAPE_CANDIDATE"))
            if direct == "numpy.broadcast_to" and len(node.args) >= 2 and isinstance(node.args[0], ast.Name):
                source = array_shapes.get(node.args[0].id)
                target = static_shape_tuple(node.args[1])
                if source is not None and target is not None and shape_can_broadcast(source, target) is False:
                    findings.append(make_finding("NUMPY_BROADCAST_INCOMPATIBLE", "numpy", node,
                                                 "STATIC_LITERAL_SHAPE_CANDIDATE"))
            if "sqlalchemy" in frameworks and isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    # SA2 rejects literal string statements unless text()/exec_driver_sql used.
                    version = versions.get("sqlalchemy", "UNKNOWN")
                    confirmed_major = int(version.split(".")[0]) if VERSION.fullmatch(version) else None
                    confidence = "VERSION_BOUNDED_STATIC_POSSIBILITY_NOT_VERIFIED" if confirmed_major is not None and confirmed_major >= 2 else "VERSION_NOT_VERIFIED"
                    if confirmed_major is None or confirmed_major >= 2:
                        findings.append(make_finding("SQLALCHEMY_TEXT_EXECUTE_POSSIBLE", "sqlalchemy", node,
                                                     confidence))
            if direct in ("pyarrow.parquet.read_table", "pyarrow.parquet.ParquetFile") and node.args:
                path = node.args[0]
                if (isinstance(path, ast.Constant) and isinstance(path.value, str) and
                        len(path.value) <= 256 and not path.value.lower().endswith((".parquet", ".pq"))):
                    findings.append(make_finding("PARQUET_EXTENSION_SUSPECT", "pyarrow", node))
            if "django" in frameworks and direct == "django.urls.path" and node.args:
                route = node.args[0]
                if isinstance(route, ast.Constant) and isinstance(route.value, str):
                    key = ("django", route.value)
                    if key in routes:
                        findings.append(make_finding("WEB_DUPLICATE_ROUTE_CANDIDATE", "django", node))
                    routes[key] = node

        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and isinstance(node.ctx, ast.Load):
            schema = dataframes.get(node.value.id)
            key = node.slice
            if (schema is not None and isinstance(key, ast.Constant) and
                    isinstance(key.value, str) and key.value not in schema):
                findings.append(make_finding("PANDAS_MISSING_LITERAL_COLUMN", "pandas", node,
                                             "STATIC_SCHEMA_CANDIDATE_NOT_PROVEN"))

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and frameworks.intersection(("flask", "fastapi")):
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call) or not decorator.args:
                    continue
                name = dotted(decorator.func)
                if not name or name.split(".")[-1] not in ("get", "post", "put", "delete", "route", "patch"):
                    continue
                route = decorator.args[0]
                if not isinstance(route, ast.Constant) or not isinstance(route.value, str):
                    continue
                verb = name.split(".")[-1]
                ecosystem = "fastapi" if "fastapi" in frameworks else "flask"
                route_key = (ecosystem, verb, route.value)
                if route_key in routes:
                    findings.append(make_finding("WEB_DUPLICATE_ROUTE_CANDIDATE", ecosystem, decorator))
                routes[route_key] = decorator
    findings.sort(key=lambda item: (item["line"], item["column"], item["rule_id"]))
    if len(findings) > MAX_FINDINGS:
        raise ValueError("too_many_ecosystem_findings")
    return findings, sorted(frameworks)


def classify_error_trace(contents):
    """Only fixed pattern IDs; never return traceback paths, tokens or lines."""
    if not contents:
        return []
    if len(contents) > MAX_TRACE:
        raise ValueError("error_trace_too_large")
    try:
        text = contents.decode("utf-8", errors="replace")
    except (UnicodeError, ValueError):
        return []
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    # Use only the apparent final exception line to reduce arbitrary source-
    # string and prompt-injection matches in previous traceback frames.
    tail = lines[-1][:1024] if lines else ""
    findings = []
    for rule_id, ecosystem, pattern in ERROR_PATTERNS:
        if re.search(pattern, tail, flags=re.IGNORECASE):
            findings.append(make_finding(rule_id, ecosystem, None,
                                         "ERROR_TEXT_UNVERIFIED", "TRACEBACK_TEXT"))
    return findings


def version_parts(value):
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise ValueError("unsupported_adapter_version")
    return tuple(int(piece) for piece in value.split("."))


def compare_versions(a, b):
    left, right = version_parts(a), version_parts(b)
    length = max(len(left), len(right))
    left += (0,) * (length - len(left))
    right += (0,) * (length - len(right))
    return (left > right) - (left < right)


def strict_json(raw):
    """Reject conflicting duplicate adapter keys and non-finite numbers."""
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_adapter_json_key")
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                      parse_constant=lambda _:
                      (_ for _ in ()).throw(ValueError("invalid_adapter_json_number")))


def tokenize_call_matches(source, target):
    """Independent token-level oracle: skips Python comments/string tokens."""
    try:
        stream = tokenize.generate_tokens(io.StringIO(source).readline)
        tokens = [(type_id, text) for type_id, text, *_ in stream
                  if type_id not in (tokenize.NL, tokenize.NEWLINE, tokenize.INDENT,
                                     tokenize.DEDENT, tokenize.COMMENT, tokenize.ENDMARKER)]
    except (tokenize.TokenError, IndentationError, UnicodeError):
        return None
    names = target.split(".")
    pattern = []
    for index, name in enumerate(names):
        if index:
            pattern.append(".")
        pattern.append(name)
    pattern.append("(")
    return sum([text for _, text in tokens[i:i + len(pattern)]] == pattern
               for i in range(len(tokens) - len(pattern) + 1))


def ast_call_matches(source, target):
    tree = parse_source(source.encode("utf-8"))
    if tree is None:
        return None
    return sum(isinstance(node, ast.Call) and dotted(node.func) == target
               for node in ast.walk(tree))


def verify_adapter(adapter):
    """Verify schema, version binding and dual AST/token fixture oracles."""
    if not isinstance(adapter, dict) or set(adapter) != {
            "schema_version", "adapter_id", "package_name", "version_min",
            "version_max_exclusive", "rules"}:
        raise ValueError("invalid_adapter_schema")
    if adapter["schema_version"] != SDK_SCHEMA_VERSION:
        raise ValueError("unsupported_adapter_schema")
    if (not isinstance(adapter["adapter_id"], str) or not RULE_ID.fullmatch(adapter["adapter_id"]) or
            not isinstance(adapter["package_name"], str) or not PACKAGE.fullmatch(adapter["package_name"])):
        raise ValueError("invalid_adapter_identity")
    if compare_versions(adapter["version_min"], adapter["version_max_exclusive"]) >= 0:
        raise ValueError("invalid_adapter_version_window")
    rules = adapter["rules"]
    if not isinstance(rules, list) or not 1 <= len(rules) <= 32:
        raise ValueError("invalid_adapter_rule_count")
    seen, verified = set(), []
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {
                "rule_id", "kind", "call", "positive_fixture", "negative_fixture"}:
            raise ValueError("invalid_adapter_rule_schema")
        rid, call = rule["rule_id"], rule["call"]
        if (not isinstance(rid, str) or not RULE_ID.fullmatch(rid) or rid in seen or
                rule["kind"] != "EXACT_STATIC_CALL" or not isinstance(call, str) or
                not CALL_NAME.fullmatch(call)):
            raise ValueError("invalid_adapter_rule")
        seen.add(rid)
        positive, negative = rule["positive_fixture"], rule["negative_fixture"]
        if any(not isinstance(text, str) or not 0 < len(text.encode("utf-8")) <= 4096
               for text in (positive, negative)):
            raise ValueError("invalid_verification_fixture")
        ast_pos, ast_neg = ast_call_matches(positive, call), ast_call_matches(negative, call)
        lex_pos, lex_neg = tokenize_call_matches(positive, call), tokenize_call_matches(negative, call)
        if (ast_pos != 1 or ast_neg != 0 or lex_pos != 1 or lex_neg != 0):
            raise ValueError("adapter_positive_negative_oracles_disagree_or_fail")
        verified.append({"rule_id": rid,
                         "fixture_sha256": sha256(canonical([positive, negative])),
                         "verification": "TWO_STATIC_ORACLES_PASS_NOT_RUNTIME"})
    return {"adapter_id": adapter["adapter_id"],
            "package_name": adapter["package_name"],
            "schema_version": SDK_SCHEMA_VERSION,
            "version_min": adapter["version_min"],
            "version_max_exclusive": adapter["version_max_exclusive"],
            "rules_verified": verified,
            "adapter_sha256": sha256(canonical(adapter)),
            "status": "STATIC_FIXTURE_VERIFIED_NOT_BEHAVIORAL",
            "independent_behavioral_verification": False,
            "package_executed": False}


def inspect(source_bytes, trace_bytes=b"", versions=None, adapters=None):
    versions = versions or {}
    if not isinstance(versions, dict) or len(versions) > 32:
        raise ValueError("invalid_package_version_set")
    for name, value in versions.items():
        if not isinstance(name, str) or not PACKAGE.fullmatch(name) or not isinstance(value, str) or not VERSION.fullmatch(value):
            raise ValueError("invalid_untrusted_package_version")
    if len(source_bytes) > MAX_SOURCE or len(trace_bytes) > MAX_TRACE:
        raise ValueError("input_budget_exceeded")
    tree = parse_source(source_bytes)
    status = "STATIC_DIAGNOSIS_UNVERIFIED" if tree is not None else "SOURCE_NOT_PARSED"
    findings, imports = analyze_static(tree, versions) if tree is not None else ([], [])
    findings.extend(classify_error_trace(trace_bytes))
    sdk_reports = []
    if adapters:
        if not isinstance(adapters, list) or len(adapters) > 16:
            raise ValueError("too_many_untrusted_adapters")
        seen = set()
        for adapter in adapters:
            proof = verify_adapter(adapter)
            if proof["adapter_id"] in seen:
                raise ValueError("duplicate_adapter_id")
            seen.add(proof["adapter_id"])
            package_version = versions.get(proof["package_name"])
            active = (package_version is not None and
                      compare_versions(package_version, proof["version_min"]) >= 0 and
                      compare_versions(package_version, proof["version_max_exclusive"]) < 0)
            proof["package_version_status"] = (
                "BOUNDED_VERSION_REPORTED_NOT_AUTHENTICATED" if active else
                "VERSION_NOT_RECORDED_OR_OUT_OF_RANGE_NOT_RUN")
            sdk_reports.append(proof)
            if active and tree is not None:
                for rule in adapter["rules"]:
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call) and dotted(node.func) == rule["call"]:
                            finding = make_finding(rule["rule_id"], proof["package_name"], node,
                                                   "VERSION_BOUNDED_STATIC_CANDIDATE")
                            finding["adapter_id"] = proof["adapter_id"]
                            findings.append(finding)
    if len(findings) > MAX_FINDINGS:
        raise ValueError("too_many_ecosystem_findings")
    findings.sort(key=lambda x: (x["line"], x["column"], x["rule_id"]))
    return {"schema_version": 1, "status": status,
            "python_minor": "{}.{}".format(sys.version_info.major, sys.version_info.minor),
            "source_sha256": sha256(source_bytes),
            "trace_sha256": sha256(trace_bytes) if trace_bytes else None,
            "imports_seen": imports,
            "package_versions": {key: versions[key] for key in sorted(versions)},
            "package_version_provenance": "OPERATOR_REPORTED_NOT_AUTHENTICATED",
            "findings": findings, "adapters": sdk_reports,
            "source_executed": False, "packages_imported": False,
            "runtime_behavior_verified": False, "native_abi_verified": False,
            "cuda_device_verified": False, "database_connections_performed": False,
            "queue_workers_contacted": False, "behavioral_correctness": "NOT_VERIFIED",
            "note": "Static/captured-error candidates only; no runtime proof or automatic repair"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--traceback", type=Path)
    parser.add_argument("--adapter-json", type=Path, action="append", default=[])
    parser.add_argument("--package-version", action="append", default=[])
    args = parser.parse_args()
    versions = {}
    for raw in args.package_version:
        if "=" not in raw:
            raise ValueError("invalid_package_version_argument")
        name, version = raw.split("=", 1)
        if name in versions:
            raise ValueError("duplicate_package_version")
        versions[name] = version
    adapters = []
    for path in args.adapter_json:
        raw = read_bounded(path, MAX_ADAPTER)
        adapters.append(strict_json(raw))
    source = read_bounded(args.source, MAX_SOURCE)
    trace = read_bounded(args.traceback, MAX_TRACE) if args.traceback else b""
    print(json.dumps(inspect(source, trace, versions, adapters), ensure_ascii=False))


if __name__ == "__main__":
    main()
