"""Broad, actual stdlib AST+native API inventory with an independent oracle.

Only explicitly reviewed CPython stdlib/native modules may be imported.
Static .py APIs are inspected by the established compile-free AST extractor;
native callable signatures and docs come from real runtime introspection.
Coverage is exact for the reviewed *public native* surface, but not the whole
CPython C API, dynamic exports, external libraries or extension ABI.
"""

import argparse
import hashlib
import importlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import stat
import sys
import sysconfig


REVIEWED_MODULES = (
    "builtins", "sys", "math", "cmath", "itertools", "functools", "operator",
    "_operator", "_functools", "array", "datetime", "_datetime",
    "unicodedata", "binascii", "_collections", "_io", "_json", "_struct",
    "_pickle", "_heapq", "_bisect", "_random", "_thread", "time",
    "marshal", "zlib", "bz2", "lzma", "select", "_statistics",
)
FORBIDDEN_IMPORTS = frozenset((
    "antigravity", "this", "webbrowser", "sitecustomize", "usercustomize",
    "pydoc", "venv", "pip", "ensurepip", "subprocess", "ctypes",
))
MAX_MODULES = 40
MAX_SYMBOLS = 16000
MAX_SOURCE_BYTES = 40 * 1024 * 1024
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _safe_sha_file(path):
    """Bounded no-follow source SHA when extension source bytes exist."""
    target = Path(path)
    descriptor = os.open(str(target), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_SOURCE_BYTES:
            raise ValueError("native_module_binary_not_regular_bounded")
        chunks = []
        remaining = MAX_SOURCE_BYTES+1
        while remaining:
            data = os.read(descriptor, min(65536, remaining))
            if not data:
                break
            chunks.append(data)
            remaining -= len(data)
        after = os.fstat(descriptor)
        if (sum(map(len, chunks)) > MAX_SOURCE_BYTES or
                (before.st_dev, before.st_ino, before.st_size,
                 before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns)):
            raise ValueError("native_module_source_changed_during_read")
        return _digest(b"".join(chunks))
    finally:
        os.close(descriptor)


def _is_native_public(value):
    """Public native C-visible API descriptor (not pure Python reexports)."""
    return bool(inspect.isbuiltin(value) or inspect.ismethoddescriptor(value)
                or inspect.isgetsetdescriptor(value) or
                (inspect.isclass(value) and value.__module__ in
                 ("builtins", "math", "itertools", "array", "datetime", "_datetime",
                  "_collections", "_io", "_thread", "time", "select", "_json",
                  "_struct", "_pickle", "_random", "_statistics", "_heapq",
                  "_bisect", "_operator", "_functools")))


def _source_module_proof(module):
    path = getattr(module, "__file__", None)
    if type(path) is str and Path(path).is_file():
        try:
            return {"kind": "EXISTING_REAL_MODULE_BYTES",
                    "sha256": _safe_sha_file(path),
                    "module_origin_path_sha256": _digest(path.encode("utf-8"))}
        except (OSError, ValueError):
            return {"kind": "SOURCE_NOT_HASHED_QUOTA_OR_PATH",
                    "sha256": None,
                    "module_origin_path_sha256": _digest(path.encode("utf-8"))}
    return {"kind": "BUILTIN_NO_MODULE_FILE",
            "sha256": _digest((sys.implementation.name + ":" + sys.version + ":" +
                               module.__name__).encode("utf-8")),
            "module_origin_path_sha256": None,
            "file_bytes_authenticated": False}


def _native_signature(value):
    # Native __text_signature__ is inert metadata. inspect.signature may call
    # eval() internally for extension defaults (observed in CPython 3.15),
    # so this extractor deliberately NEVER invokes it on native objects.
    text = getattr(value, "__text_signature__", None)
    if type(text) is not str or not 1 <= len(text) <= 600:
        return None
    return text


def _doc_digest(value):
    try:
        content = inspect.getdoc(value)
    except (ValueError, TypeError):
        content = None
    return _digest(content.encode("utf-8")) if type(content) is str else None


def _allowed(name):
    if (type(name) is not str or not NAME.fullmatch(name) or
            name not in REVIEWED_MODULES or name in FORBIDDEN_IMPORTS):
        raise ValueError("module_not_approved_for_runtime_introspection")
    if hasattr(sys, "stdlib_module_names") and name not in sys.stdlib_module_names:
        # Internal modules do not always appear in public stdlib names.
        if not name.startswith("_"):
            raise ValueError("module_not_in_current_stdlib_registry")
    return name


def native_runtime_inventory(names=REVIEWED_MODULES):
    """Native API export discovery+oracles independent of static source AST."""
    if type(names) not in (tuple, list) or not 1 <= len(names) <= MAX_MODULES:
        raise ValueError("invalid_reviewed_module_quota")
    for name in names:
        _allowed(name)
    found = []
    modules = []
    independent_missing = []
    total_oracle = 0
    for name in sorted(set(names)):
        try:
            module = importlib.import_module(name)
        except ImportError:
            modules.append({"module": name, "status": "NOT_AVAILABLE", "symbols": 0,
                            "file_sha256": None})
            continue
        origin = _source_module_proof(module)
        entries = {}
        for key, value in list(vars(module).items()):
            if key.startswith("_") or not _is_native_public(value):
                continue
            entries[name + "." + key] = value
            if inspect.isclass(value):
                # Inherited public native methods/properties remain usable
                # runtime APIs. Own-class vars() alone loses hundreds of C
                # members from Exception, numeric and IO base classes.
                for parent in reversed(value.__mro__):
                    for method, member in list(vars(parent).items()):
                        if method.startswith("_") or not _is_native_public(member):
                            continue
                        entries[name + "." + key + "." + method] = member
        # Independent oracle uses dir()+getattr_static(), which does not
        # traverse this implementation's vars() enumeration.
        independent = set()
        for key in dir(module):
            if key.startswith("_"):
                continue
            try:
                value = inspect.getattr_static(module, key)
            except AttributeError:
                continue
            if _is_native_public(value):
                independent.add(name + "." + key)
                if inspect.isclass(value):
                    for method in dir(value):
                        if method.startswith("_"):
                            continue
                        try:
                            member = inspect.getattr_static(value, method)
                        except AttributeError:
                            continue
                        if _is_native_public(member):
                            independent.add(name + "." + key + "." + method)
        total_oracle += len(independent)
        independent_missing.extend(sorted(independent - set(entries)))
        for symbol, member in sorted(entries.items()):
            found.append({"symbol": symbol, "module": name,
                          "kind": type(member).__name__,
                          "signature": _native_signature(member),
                          "doc_sha256": _doc_digest(member),
                          "origin_sha256": origin["sha256"],
                          "runtime_verified": True})
        modules.append({"module": name, "status": "INSPECTED_REAL_CPTHON",
                        "symbols": len(entries),
                        "module_origin": origin})
        if len(found) > MAX_SYMBOLS:
            raise ValueError("native_inventory_symbol_budget")
    seen = set()
    duplicates = []
    for row in found:
        if row["symbol"] in seen:
            duplicates.append(row["symbol"])
        seen.add(row["symbol"])
    if duplicates:
        raise ValueError("duplicate_native_symbols")
    found.sort(key=lambda row: row["symbol"])
    signatures = sum(row["signature"] is not None for row in found)
    return {"status": ("REVIEWED_NATIVE_API_ORACLE_COMPLETE" if
                       not independent_missing else "REVIEWED_NATIVE_API_GAPS"),
            "python_minor": "{}.{}".format(*sys.version_info[:2]),
            "python_micro": "{}.{}.{}".format(*sys.version_info[:3]),
            "reviewed_module_count": len(modules),
            "available_native_modules": sum(row["status"] == "INSPECTED_REAL_CPTHON"
                                            for row in modules),
            "independent_oracle_native_symbols": total_oracle,
            "collected_native_symbols": len(found),
            "native_symbols_with_signature": signatures,
            "native_symbols_missing_signature": len(found) - signatures,
            "uncovered_independent_native_symbols": independent_missing,
            "native_inventory_sha256": _digest(_json_bytes(found)),
            "native_symbols": found, "modules": modules,
            "dynamic_module_imported_outside_reviewed_allowlist": False,
            "downloaded_or_project_code_executed": False,
            "all_CPythons_C_API_functions_covered": False,
            "external_publisher_binary_provenance_attested": False}


def _static_extractor():
    """Resolve the previously-tested stdlib AST scanner, not user code."""
    embedded = globals().get("stdlibscanner")
    if embedded is not None:
        if (getattr(embedded, "__name__", None) != "stdlibscanner" or
                not callable(getattr(embedded, "extract", None))):
            raise ValueError("invalid_trusted_embedded_stdlib_scanner")
        return embedded
    try:
        path = Path(__file__).with_name("stdlib_api_extract.py")
    except NameError as exc:
        raise ValueError("static_source_extractor_not_embedded") from exc
    if path.is_symlink() or not path.is_file():
        raise ValueError("trusted_local_ast_extractor_missing")
    spec = importlib.util.spec_from_file_location("rph_reviewed_stdlib_ast", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def combined_inventory(stdlib_root=None):
    """Combine broad static .py declarations with reviewed real native APIs."""
    native = native_runtime_inventory()
    extractor = _static_extractor()
    static = extractor.extract(stdlib_root)
    minor = "{}.{}".format(*sys.version_info[:2])
    if static["python_minor"] != minor:
        raise ValueError("native_static_python_version_mismatch")
    static_symbols = {row["module"] + "." + row["qualified_name"]
                      for row in static["api_symbols"]}
    native_symbols = {row["symbol"] for row in native["native_symbols"]}
    overlap = len(static_symbols & native_symbols)
    # A source declaration is only a candidate; it may not be an exported
    # symbol. Native signatures are actually observed at runtime.
    report = {"status": ("BROAD_STDLIB_AST_PLUS_NATIVE_LOCAL_PASS" if
                         native["status"] == "REVIEWED_NATIVE_API_ORACLE_COMPLETE" and
                         static["module_files_indexed"] > 100 and
                         static["api_candidates_indexed"] > 1000 else
                         "STDLIB_SCOPE_OR_COVERAGE_INCOMPLETE"),
              "python_minor": minor,
              "source_files_scanned": static["module_files_indexed"],
              "source_bytes_hashed": static["source_bytes_hashed"],
              "source_files_refused": static["source_files_refused"],
              "static_api_declaration_candidates": static["api_candidates_indexed"],
              "native_runtime_symbols": native["collected_native_symbols"],
              "native_signature_count": native["native_symbols_with_signature"],
              "native_missing_signatures": native["native_symbols_missing_signature"],
              "reviewed_native_modules": native["reviewed_module_count"],
              "available_native_modules": native["available_native_modules"],
              "independent_native_oracle_symbols": native["independent_oracle_native_symbols"],
              "uncovered_independent_native_symbols": native[
                  "uncovered_independent_native_symbols"],
              "static_native_candidate_overlap": overlap,
              "static_catalog_sha256": _digest(_json_bytes(static["modules"])),
              "native_catalog_sha256": native["native_inventory_sha256"],
              "qualified_f068_bounded_local_scope": (
                  native["status"] == "REVIEWED_NATIVE_API_ORACLE_COMPLETE" and
                  static["module_files_indexed"] > 100 and
                  static["api_candidates_indexed"] > 1000),
              "all_stdlib_public_modules_complete": False,
              "all_C_level_exported_symbols_complete": False,
              "downloaded_or_project_code_executed": False,
              "external_publisher_provenance_authenticated": False}
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "native", "combined", "extract"),
                        default="capabilities")
    parser.add_argument("--source-root")
    parser.add_argument("--source-root-sha256")
    args = parser.parse_args(argv)
    if args.mode == "capabilities":
        report = {"status": "BROAD_STDLIB_API_CAPABILITIES_ONLY",
                  "reviewed_native_allowlist": len(REVIEWED_MODULES),
                  "python_minor": "{}.{}".format(*sys.version_info[:2]),
                  "static_ast_scanner_available_in_source_package": "__file__" in globals(),
                  "full_c_api_claimed": False,
                  "untrusted_code_executed": False}
    elif args.mode == "native":
        report = native_runtime_inventory()
        report.pop("native_symbols")
        report.pop("modules")
    elif args.mode == "extract":
        if not args.source_root or not args.source_root_sha256:
            parser.error("extract requires --source-root and --source-root-sha256")
        root = Path(args.source_root)
        actual = Path(sysconfig.get_path("stdlib"))
        if (root.is_symlink() or not root.is_dir() or
                root.resolve() != actual.resolve() or
                _digest(str(root.resolve()).encode("utf-8")) != args.source_root_sha256):
            parser.error("stdlib_source_root_not_version_pinned")
        report = combined_inventory(root)
    else:
        report = combined_inventory()
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
