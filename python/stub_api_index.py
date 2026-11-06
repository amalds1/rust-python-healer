"""Authenticated offline .pyi signature, overload and API rename observations.

Local, preauthorized stub snapshots are HMAC- and SHA256-checked before an
AST-only inspection.  No downloaded stub is imported, executed, evaluated or
installed.  Rename records are supported only by old/new symbol *presence*
in distinct snapshots, not by proof of behavior or semantic equivalence.
"""

import argparse
import ast
import hashlib
import hmac
import json
import re
import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

try:
    from python import example_compile as security
except ImportError:  # Direct invocation: python python/stub_api_index.py
    helper_spec = spec_from_file_location(
        "trusted_local_example_compile", Path(__file__).resolve().with_name("example_compile.py"))
    security = module_from_spec(helper_spec)
    helper_spec.loader.exec_module(security)

MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z")
PACKAGE_VERSION = re.compile(r"[0-9][A-Za-z0-9_.!+~-]{0,63}\Z")
MAX_STUBS = 32
MAX_RENAMES = 64
MAX_EXPORTED_SYMBOLS = 512


def validate_manifest(manifest, trust):
    security.validate_trust(trust)
    fields = {"schema_version", "manifest_id", "source_id", "stubs", "renames", "signature"}
    if (not isinstance(manifest, dict) or set(manifest) != fields or
            type(manifest["schema_version"]) is not int or
            manifest["schema_version"] != 1 or
            not isinstance(manifest["manifest_id"], str) or
            not security.ID.fullmatch(manifest["manifest_id"]) or
            manifest["source_id"] != trust["source_id"] or
            not isinstance(manifest["signature"], str) or
            not security.HEX64.fullmatch(manifest["signature"])):
        raise ValueError("invalid_stub_manifest")
    stubs, renames = manifest["stubs"], manifest["renames"]
    if (not isinstance(stubs, list) or not 0 < len(stubs) <= MAX_STUBS or
            not isinstance(renames, list) or len(renames) > MAX_RENAMES):
        raise ValueError("invalid_stub_count_or_rename_count")
    seen_ids, seen_versions, seen_blobs = set(), set(), set()
    row_fields = {"id", "blob", "module", "python_version", "package_version",
                  "uri", "license", "sha256", "ingest_authorized"}
    for row in stubs:
        if not isinstance(row, dict) or set(row) != row_fields:
            raise ValueError("invalid_stub_record")
        if not isinstance(row["id"], str) or not security.ID.fullmatch(row["id"]):
            raise ValueError("invalid_stub_id")
        security.validate_blob_path(row["blob"], ".pyi")
        if not isinstance(row["module"], str) or not MODULE.fullmatch(row["module"]):
            raise ValueError("invalid_stub_module")
        if (not isinstance(row["python_version"], str) or
                not security.VERSION.fullmatch(row["python_version"]) or
                not isinstance(row["package_version"], str) or
                not PACKAGE_VERSION.fullmatch(row["package_version"])):
            raise ValueError("invalid_exact_stub_version")
        key = (row["module"], row["python_version"], row["package_version"])
        if (row["id"] in seen_ids or row["blob"] in seen_blobs or
                key in seen_versions):
            raise ValueError("duplicate_stub_snapshot")
        seen_ids.add(row["id"])
        seen_blobs.add(row["blob"])
        seen_versions.add(key)
        if not isinstance(row["sha256"], str) or not security.HEX64.fullmatch(row["sha256"]):
            raise ValueError("invalid_stub_sha256")
        if type(row["ingest_authorized"]) is not bool or not row["ingest_authorized"]:
            raise ValueError("stub_ingestion_not_authorized")
        if (not isinstance(row["license"], str) or
                row["license"] not in trust["licenses"]):
            raise ValueError("stub_license_not_authorized")
        uri = row["uri"]
        if not isinstance(uri, str) or len(uri) > 2048 or any(c in uri for c in "\r\n\0"):
            raise ValueError("invalid_stub_uri")
        # Reuse the already validated provenance policy from the source module.
        from urllib.parse import urlsplit
        try:
            parts = urlsplit(uri)
            allowed = (parts.scheme == "https" and parts.hostname == trust["hostname"]
                       and parts.port in (None, 443) and not parts.username
                       and not parts.password and not parts.query and not parts.fragment)
        except ValueError:
            allowed = False
        if not allowed:
            raise ValueError("stub_provenance_host_not_authorized")

    rename_fields = {"module", "old_name", "new_name", "before_python",
                     "after_python", "package_version_before", "package_version_after"}
    seen_renames = set()
    for row in renames:
        if not isinstance(row, dict) or set(row) != rename_fields:
            raise ValueError("invalid_rename_record")
        if any(not isinstance(row[key], str) or not MODULE.fullmatch(row[key])
               for key in ("module", "old_name", "new_name")):
            raise ValueError("invalid_rename_symbol")
        if row["old_name"] == row["new_name"]:
            raise ValueError("rename_must_change_name")
        for key in ("before_python", "after_python"):
            if not isinstance(row[key], str) or not security.VERSION.fullmatch(row[key]):
                raise ValueError("invalid_rename_python_version")
        before = tuple(int(x) for x in row["before_python"].split("."))
        after = tuple(int(x) for x in row["after_python"].split("."))
        if before >= after:
            raise ValueError("rename_versions_not_monotonic")
        for key in ("package_version_before", "package_version_after"):
            if not isinstance(row[key], str) or not PACKAGE_VERSION.fullmatch(row[key]):
                raise ValueError("invalid_rename_package_version")
        key = (row["module"], row["old_name"], row["new_name"],
               row["before_python"], row["after_python"])
        if key in seen_renames:
            raise ValueError("duplicate_rename_record")
        seen_renames.add(key)
    signed = {key: value for key, value in manifest.items() if key != "signature"}
    expected = hmac.new(bytes.fromhex(trust["key_hex"]), security.canonical(signed),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, manifest["signature"]):
        raise ValueError("stub_manifest_hmac_invalid")
    return stubs, renames


def safe_annotation(node, depth=0):
    """Never expose arbitrary string literals, calls or complex expressions."""
    if node is None:
        return None
    if depth >= 12:
        return "[complex]"
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = safe_annotation(node.value, depth + 1)
        return left + "." + node.attr if left and left != "[complex]" else "[complex]"
    if isinstance(node, ast.Constant):
        return "None" if node.value is None else "[literal]"
    if isinstance(node, ast.Subscript):
        return (f"{safe_annotation(node.value, depth + 1)}"
                f"[{safe_annotation(node.slice, depth + 1)}]")
    if isinstance(node, ast.Tuple):
        return ", ".join(safe_annotation(item, depth + 1) for item in node.elts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return (f"{safe_annotation(node.left, depth + 1)} | "
                f"{safe_annotation(node.right, depth + 1)}")
    if isinstance(node, ast.Ellipsis):  # pragma: no cover: Python 3.9+ uses Constant
        return "..."
    return "[complex]"


def argument_text(argument, default=False, prefix=""):
    annotation = safe_annotation(argument.annotation)
    text = prefix + argument.arg
    if annotation is not None:
        text += ": " + annotation
    if default:
        text += " = ..."
    return text[:240]


def safe_signature(node):
    args = node.args
    positional = args.posonlyargs + args.args
    defaults_at = len(positional) - len(args.defaults)
    items = [argument_text(arg, index >= defaults_at)
             for index, arg in enumerate(positional)]
    if args.posonlyargs:
        items.insert(len(args.posonlyargs), "/")
    if args.vararg:
        items.append(argument_text(args.vararg, prefix="*"))
    elif args.kwonlyargs:
        items.append("*")
    items.extend(argument_text(arg, default is not None)
                 for arg, default in zip(args.kwonlyargs, args.kw_defaults))
    if args.kwarg:
        items.append(argument_text(args.kwarg, prefix="**"))
    returns = safe_annotation(node.returns)
    return "(" + ", ".join(items) + ")" + (" -> " + returns if returns else "")


def decorator_names(node):
    values = []
    for item in node.decorator_list:
        if isinstance(item, ast.Name):
            values.append(item.id)
        elif isinstance(item, ast.Attribute):
            values.append(item.attr)
    return values


def index_stub(source, module):
    """Parse-only, bounded static observations of top-level/class APIs."""
    try:
        tree = ast.parse(source, filename="<offline-stub>", mode="exec")
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        raise ValueError("stub_syntax_invalid_or_unsupported") from None
    symbols = []
    conditional_ignored = 0

    def collect(body, prefix=""):
        nonlocal conditional_ignored
        for item in body:
            if isinstance(item, ast.ClassDef):
                qualified = prefix + item.name
                symbols.append({"name": qualified, "kind": "class",
                                "bases": [safe_annotation(base) for base in item.bases[:16]]})
                if len(symbols) > MAX_EXPORTED_SYMBOLS:
                    raise ValueError("stub_symbol_limit")
                # Only class methods, not arbitrary nested function bodies.
                collect(item.body, qualified + ".")
            elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                decorated = decorator_names(item)
                symbols.append({
                    "name": prefix + item.name,
                    "kind": "async_function" if isinstance(item, ast.AsyncFunctionDef)
                            else "function",
                    "signature": safe_signature(item)[:1024],
                    "overload": "overload" in decorated,
                    "property": "property" in decorated,
                    "classmethod": "classmethod" in decorated,
                    "staticmethod": "staticmethod" in decorated,
                })
                if len(symbols) > MAX_EXPORTED_SYMBOLS:
                    raise ValueError("stub_symbol_limit")
            elif isinstance(item, (ast.If, ast.Try, ast.With, ast.For, ast.While)):
                conditional_ignored += 1

    collect(tree.body)
    overload_counts = {}
    for item in symbols:
        if item.get("overload"):
            overload_counts[item["name"]] = overload_counts.get(item["name"], 0) + 1
    for item in symbols:
        if item["kind"] != "class":
            item["overload_set_size"] = overload_counts.get(item["name"], 0)
    return {"module": module, "symbols": symbols,
            "overload_sets": dict(sorted(overload_counts.items())),
            "conditional_blocks_ignored": conditional_ignored,
            "source_executed": False}


def inspect_manifest(manifest_path, blob_root, trust_path):
    """Index authenticated snapshots; correlated renamed names stay unverified."""
    manifest = security.read_json(manifest_path, security.MAX_MANIFEST_BYTES)
    trust = security.read_json(trust_path, security.MAX_TRUST_BYTES, private=True)
    stubs, renames = validate_manifest(manifest, trust)
    snapshots, indexed = [], {}
    for row in stubs:
        raw = security.read_blob(blob_root, row["blob"], ".pyi")
        sha256 = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(sha256, row["sha256"]):
            raise ValueError("stub_sha256_mismatch")
        info = index_stub(raw.decode("utf-8"), row["module"])
        record = {"id": row["id"], "module": row["module"],
                  "python_version": row["python_version"],
                  "package_version": row["package_version"],
                  "sha256": sha256, **info}
        snapshots.append(record)
        indexed[(row["module"], row["python_version"], row["package_version"])] = record
    correlations = []
    for row in renames:
        before = indexed.get((row["module"], row["before_python"],
                              row["package_version_before"]))
        after = indexed.get((row["module"], row["after_python"],
                             row["package_version_after"]))
        if before is None or after is None:
            raise ValueError("rename_missing_versioned_stub_evidence")
        names_before = {item["name"] for item in before["symbols"]}
        names_after = {item["name"] for item in after["symbols"]}
        if (row["old_name"] not in names_before or
                row["new_name"] not in names_after or
                row["new_name"] in names_before or
                row["old_name"] in names_after):
            raise ValueError("rename_presence_or_removal_not_observed")
        correlations.append({"module": row["module"],
                             "old_name": row["old_name"],
                             "new_name": row["new_name"],
                             "before_python": row["before_python"],
                             "after_python": row["after_python"],
                             "status": "CORRELATED_NAMES_SEMANTICS_UNVERIFIED"})
    return {
        "schema_version": 1,
        "status": "PARTIAL_STATIC_STUB_EVIDENCE",
        "manifest_id": manifest["manifest_id"],
        "hmac_operator_verified": True,
        "publisher_authenticated": False,
        "package_runtime_api_verified": False,
        "rename_semantics_verified": False,
        "source_executed": False,
        "project_imported": False,
        "network_used": False,
        "stub_snapshots_indexed": len(snapshots),
        "rename_candidates_correlated": len(correlations),
        "snapshots": snapshots,
        "rename_correlations": correlations,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest")
    parser.add_argument("blob_root")
    parser.add_argument("trust_file")
    args = parser.parse_args()
    try:
        result = inspect_manifest(args.manifest, args.blob_root, args.trust_file)
    except ValueError as error:
        result = {"status": "NOT_RUN", "reason": str(error),
                  "source_executed": False, "network_used": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PARTIAL_STATIC_STUB_EVIDENCE" else 1


if __name__ == "__main__":
    sys.exit(main())
