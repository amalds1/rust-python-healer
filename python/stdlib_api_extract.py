"""Bounded CPython stdlib .py AST API-candidate catalog, without module import.

Only static Python definitions are indexed. Dynamic exports, imported names,
C/native extension APIs, runtime decorators and actual call signatures are
NOT_VERIFIED. This is not complete standard-library API discovery, a code
executor, a filesystem sandbox or a signed provenance attestation.
"""

import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import sysconfig
import tokenize


MAX_FILES = 3500
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 1_048_576
MAX_AST_NODES = 40_000
MAX_SYMBOLS = 60_000
SKIP_DIRS = frozenset((
    "__pycache__", "site-packages", "dist-packages", ".git", ".venv",
    "venv", "build", "dist", "node_modules",
))
VALID_MODULE = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")


def read_regular(path):
    """No-follow bounded read; refuse hardlinks or replacement during read."""
    if path.is_symlink():
        raise ValueError("symlink_source_refused")
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE_BYTES:
            raise ValueError("not_unique_bounded_stdlib_source")
        source = stream.read(MAX_FILE_BYTES + 1)
        after = os.fstat(stream.fileno())
    if (len(source) > MAX_FILE_BYTES or
            (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) !=
            (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns)):
        raise ValueError("source_changed_or_oversized")
    return source


def module_name(root, filename):
    relative = filename.relative_to(root)
    parts = list(relative.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    if not parts or any(not VALID_MODULE.fullmatch(part) for part in parts):
        return None
    return ".".join(parts)


def signature(node):
    """Structural-only function signature, never evaluate defaults/annotations."""
    args = node.args
    positional = list(args.posonlyargs) + list(args.args)
    minimum = len(positional) - len(args.defaults)
    return {
        "positional_only": [arg.arg for arg in args.posonlyargs],
        "positional_or_keyword": [arg.arg for arg in args.args],
        "required_positional_count": minimum,
        "keyword_only": [arg.arg for arg in args.kwonlyargs],
        "required_keyword_only": [arg.arg for arg, default in
                                  zip(args.kwonlyargs, args.kw_defaults) if default is None],
        "varargs": args.vararg.arg if args.vararg is not None else None,
        "varkw": args.kwarg.arg if args.kwarg is not None else None,
        "default_expressions_executed": False,
        "annotations_evaluated": False,
        "return_annotation_present": node.returns is not None,
        "runtime_signature_verified": False,
    }


def inspect_ast(source, module, file_hash, minor):
    """Collect public/private source declarations, including nested methods."""
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(source).readline)
        decoded = source.decode(encoding)
        tree = ast.parse(decoded, filename="[STDLIB_SOURCE]", mode="exec")
    except (SyntaxError, UnicodeError, LookupError, ValueError):
        return None
    if sum(1 for _ in ast.walk(tree)) > MAX_AST_NODES:
        return None
    rows = []

    def walk(body, context=(), inside_function=False):
        for node in body:
            if isinstance(node, ast.ClassDef):
                qual = ".".join(context + (node.name,))
                rows.append({"qualified_name": qual, "kind": "CLASS",
                             "line": node.lineno, "column": node.col_offset,
                             "base_count": len(node.bases), "signature": None,
                             "source_sha256": file_hash, "python_minor": minor,
                             "module": module})
                walk(node.body, context + (node.name,), inside_function=False)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = ".".join(context + (node.name,))
                rows.append({"qualified_name": qual,
                             "kind": "ASYNC_FUNCTION" if isinstance(node, ast.AsyncFunctionDef)
                             else "FUNCTION", "line": node.lineno,
                             "column": node.col_offset, "base_count": None,
                             "signature": signature(node), "source_sha256": file_hash,
                             "python_minor": minor, "module": module,
                             "nested_function": inside_function})
                # Nested definitions are source declarations but may never
                # become runtime exports; retain the distinction in JSON.
                walk(node.body, context + (node.name,), inside_function=True)
            elif isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While,
                                   ast.With, ast.AsyncWith, ast.Try)):
                walk(node.body, context, inside_function=inside_function)
                walk(getattr(node, "orelse", []), context, inside_function=inside_function)
                walk(getattr(node, "finalbody", []), context, inside_function=inside_function)
                for handler in getattr(node, "handlers", []):
                    walk(handler.body, context, inside_function=inside_function)
            elif hasattr(ast, "TryStar") and isinstance(node, ast.TryStar):
                walk(node.body, context, inside_function=inside_function)
                walk(getattr(node, "orelse", []), context, inside_function=inside_function)
                walk(getattr(node, "finalbody", []), context, inside_function=inside_function)
                for handler in node.handlers:
                    walk(handler.body, context, inside_function=inside_function)
            elif hasattr(ast, "Match") and isinstance(node, ast.Match):
                for case in node.cases:
                    walk(case.body, context, inside_function=inside_function)

    walk(tree.body)
    rows.sort(key=lambda x: (x["qualified_name"], x["line"], x["column"], x["kind"]))
    return rows


def discover_sources(root):
    """Deterministic, no-follow walk; return names only from one fixed root."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("invalid_stdlib_root")
    found, refused = [], 0
    for current, dirs, files in os.walk(str(root), topdown=True, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS and
                         not (current_path / name).is_symlink())
        for name in sorted(files):
            if not name.endswith(".py"):
                continue
            path = current_path / name
            if path.is_symlink():
                refused += 1
                continue
            if module_name(root, path) is None:
                refused += 1
                continue
            found.append(path)
            if len(found) > MAX_FILES:
                raise ValueError("too_many_stdlib_sources")
    return sorted(found, key=lambda path: path.relative_to(root).as_posix()), refused


def extract(root=None):
    """Return deterministic source and structural API catalog (not proof)."""
    actual = Path(root) if root is not None else Path(sysconfig.get_path("stdlib"))
    sources, refused = discover_sources(actual)
    total_bytes, modules, symbols = 0, [], []
    minor = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
    for path in sources:
        try:
            content = read_regular(path)
        except (OSError, ValueError):
            refused += 1
            continue
        total_bytes += len(content)
        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError("stdlib_total_bytes_quota_exceeded")
        hashed = hashlib.sha256(content).hexdigest()
        module = module_name(actual, path)
        found = inspect_ast(content, module, hashed, minor)
        if found is None:
            refused += 1
            continue
        symbols.extend(found)
        if len(symbols) > MAX_SYMBOLS:
            raise ValueError("stdlib_symbol_quota_exceeded")
        modules.append({"module": module, "source_sha256": hashed,
                        "source_size": len(content), "python_minor": minor,
                        "symbols": len(found)})
    modules.sort(key=lambda x: (x["module"], x["source_sha256"]))
    symbols.sort(key=lambda x: (x["module"], x["qualified_name"], x["line"], x["column"]))
    status = "INDEXED_PARTIAL_UNVERIFIED" if refused else (
        "INDEXED_STATIC_PY_UNVERIFIED" if modules else "NO_FILES_INDEXED")
    return {"schema_version": 1, "status": status, "python_minor": minor,
            "modules": modules, "api_symbols": symbols,
            "module_files_indexed": len(modules), "api_candidates_indexed": len(symbols),
            "source_files_refused": refused, "source_bytes_hashed": total_bytes,
            "stdlib_root_path_sha256": hashlib.sha256(str(actual).encode()).hexdigest(),
            "source_executed": False, "modules_imported": False,
            "native_extension_apis_verified": False,
            "dynamic_api_exports_verified": False,
            "runtime_signature_verified": False,
            "path_protection": "BEST_EFFORT_NO_ROOT_SWAP_GUARANTEE",
            "note": "Only static .py declarations; C extensions, import aliases and runtime exports NOT_VERIFIED"}


def write_index(path, catalog):
    """Write a deterministic isolated SQLite index; never overwrite a DB."""
    target = Path(path)
    if target.exists() or target.is_symlink() or not target.parent.is_dir() or target.parent.is_symlink():
        raise ValueError("index_target_must_be_a_new_regular_filename")
    if catalog.get("status") == "NO_FILES_INDEXED":
        raise ValueError("no_stdlib_sources_to_index")
    connection = sqlite3.connect(str(target), isolation_level=None)
    try:
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("""CREATE TABLE modules (
            module TEXT NOT NULL, source_sha256 TEXT NOT NULL,
            source_size INTEGER NOT NULL, python_minor TEXT NOT NULL,
            symbol_count INTEGER NOT NULL,
            PRIMARY KEY (module, python_minor))""")
        connection.execute("""CREATE TABLE api_symbols (
            module TEXT NOT NULL, qualified_name TEXT NOT NULL,
            kind TEXT NOT NULL, line INTEGER NOT NULL, col INTEGER NOT NULL,
            python_minor TEXT NOT NULL, source_sha256 TEXT NOT NULL,
            signature_json TEXT,
            PRIMARY KEY (module, qualified_name, kind, line, col, python_minor))""")
        connection.executemany("INSERT INTO modules VALUES (?,?,?,?,?)", [
            (r["module"], r["source_sha256"], r["source_size"],
             r["python_minor"], r["symbols"]) for r in catalog["modules"]])
        connection.executemany("INSERT INTO api_symbols VALUES (?,?,?,?,?,?,?,?)", [
            (r["module"], r["qualified_name"], r["kind"], r["line"],
             r["column"], r["python_minor"], r["source_sha256"],
             json.dumps(r["signature"], sort_keys=True, separators=(",", ":"))
             if r["signature"] is not None else None)
            for r in catalog["api_symbols"]])
        connection.execute("COMMIT")
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("sqlite_index_integrity_check_failed")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    return {"status": "INDEX_WRITTEN_UNVERIFIED", "sqlite_path_sha256":
            hashlib.sha256(str(target).encode()).hexdigest(),
            "modules": len(catalog["modules"]), "api_candidates": len(catalog["api_symbols"]),
            "source_executed": False, "native_extension_apis_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stdlib-root", type=Path)
    parser.add_argument("--db", type=Path)
    args = parser.parse_args()
    result = extract(args.stdlib_root)
    summary = {key: value for key, value in result.items()
               if key not in ("modules", "api_symbols")}
    if args.db:
        summary["sqlite"] = write_index(args.db, result)
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
