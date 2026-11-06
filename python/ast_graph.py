"""Bounded static Python AST symbol and *possible* call-edge inspection.

This helper never executes the input source, imports target modules, or
evaluates expressions. It is not a compiler/typechecker or a security sandbox.
It runs under the selected CPython minor so syntax support remains versioned.
"""

import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tokenize


MAX_SOURCE_BYTES = 4_000_000
MAX_NODES = 100_000
MAX_SYMBOLS = 2_000
MAX_EDGES = 2_000


def read_source(path):
    """Open exactly one ordinary file; protect final path from symlinks."""
    path = Path(path)
    original = path.lstat()
    if not stat.S_ISREG(original.st_mode):
        raise ValueError("source_not_regular_file")
    if original.st_nlink != 1:
        raise ValueError("source_hardlink_refused")
    if original.st_size > MAX_SOURCE_BYTES:
        raise ValueError("source_size_limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(str(path), flags)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (original.st_dev, original.st_ino):
            raise ValueError("source_changed_during_open")
        content = handle.read(MAX_SOURCE_BYTES + 1)
        after = os.fstat(handle.fileno())
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
            raise ValueError("source_changed_during_read")
    if len(content) > MAX_SOURCE_BYTES:
        raise ValueError("source_size_limit")
    return content


def decode_source(content):
    """Respect PEP 263 coding cookies without importing the source module."""
    encoding, _ = tokenize.detect_encoding(io.BytesIO(content).readline)
    return content.decode(encoding)


def location(node):
    """CPython AST uses UTF-8 byte columns; end locations can be absent."""
    return {
        "line": getattr(node, "lineno", None),
        "column_utf8_bytes": getattr(node, "col_offset", None),
        "end_line": getattr(node, "end_lineno", None),
        "end_column_utf8_bytes": getattr(node, "end_col_offset", None),
    }


def inspect_tree(tree):
    """Record declarations and conservative candidate direct-name calls."""
    symbols = []
    imports = []
    potential_calls = []
    # Top-level functions can be called by bare names. Shadowing, closures,
    # monkeypatching and runtime dispatch make every edge UNVERIFIED.
    top_level_functions = {
        node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    counts = {"nodes": 0}

    class Inspector(ast.NodeVisitor):
        def __init__(self):
            self.scope = []

        def visit(self, node):
            counts["nodes"] += 1
            if counts["nodes"] > MAX_NODES:
                raise ValueError("ast_node_limit")
            super().visit(node)

        def collect_definition(self, node, kind):
            if len(symbols) >= MAX_SYMBOLS:
                raise ValueError("ast_symbol_limit")
            qualified = ".".join(self.scope + [node.name])
            if len(node.name) > 256 or len(qualified) > 512:
                raise ValueError("ast_symbol_limit")
            symbols.append({"qualified_name": qualified, "kind": kind, **location(node)})
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()

        def visit_FunctionDef(self, node):
            self.collect_definition(node, "FUNCTION")

        def visit_AsyncFunctionDef(self, node):
            self.collect_definition(node, "ASYNC_FUNCTION")

        def visit_ClassDef(self, node):
            self.collect_definition(node, "CLASS")

        def visit_Import(self, node):
            if (len(imports) >= MAX_SYMBOLS or len(node.names) > 100 or
                    any(len(item.name) > 256 for item in node.names)):
                raise ValueError("ast_import_limit")
            imports.append({"kind": "IMPORT", "modules": [item.name for item in node.names],
                            **location(node)})

        def visit_ImportFrom(self, node):
            if (len(imports) >= MAX_SYMBOLS or len(node.names) > 100 or
                    any(len(item.name) > 256 for item in node.names) or
                    len(node.module or "") > 256):
                raise ValueError("ast_import_limit")
            imports.append({"kind": "FROM", "module": node.module,
                            "relative_level": node.level,
                            "names": [item.name for item in node.names], **location(node)})

        def visit_Call(self, node):
            if isinstance(node.func, ast.Name) and node.func.id in top_level_functions:
                if len(potential_calls) >= MAX_EDGES:
                    raise ValueError("ast_edge_limit")
                potential_calls.append({
                    "from": ".".join(self.scope) if self.scope else "<module>",
                    "to": node.func.id,
                    "status": "POSSIBLE_STATIC_NAME_NOT_VERIFIED",
                    **location(node),
                })
            self.generic_visit(node)

    inspector = Inspector()
    inspector.visit(tree)
    return {
        "symbols": symbols,
        "imports": imports,
        "possible_calls": potential_calls,
        "visited_nodes": counts["nodes"],
        "call_graph_verified": False,
        "type_inference": "NOT_RUN",
        "control_flow_analysis": "NOT_RUN",
    }


def analyze_file(path):
    """Return structured, privacy-preserving parser diagnostics only."""
    try:
        content = read_source(path)
    except (OSError, ValueError) as exc:
        reason = str(exc)
        known = {"source_not_regular_file", "source_hardlink_refused", "source_size_limit",
                 "source_changed_during_open", "source_changed_during_read"}
        return {"status": "NOT_RUN", "reason": reason if reason in known else "file_unavailable",
                "source_executed": False, "compile_proven": False}

    common = {
        "source_sha256": hashlib.sha256(content).hexdigest(),
        "source_executed": False,
        "compile_proven": False,
        "path_protection": "BEST_EFFORT_NO_FINAL_SYMLINK_NOT_OS_SANDBOX",
    }
    try:
        text = decode_source(content)
    except (SyntaxError, UnicodeError, LookupError) as exc:
        return {**common, "status": "INVALID_ENCODING", "error_type": type(exc).__name__}
    try:
        tree = ast.parse(text, mode="exec", type_comments=True)
    except (SyntaxError, ValueError, TypeError, RecursionError, MemoryError) as exc:
        return {**common, "status": "SYNTAX_ERROR" if isinstance(exc, SyntaxError)
                else "NOT_RUN", "error_type": type(exc).__name__,
                "line": getattr(exc, "lineno", None),
                "column": getattr(exc, "offset", None)}
    try:
        details = inspect_tree(tree)
    except (ValueError, RecursionError, MemoryError) as exc:
        reason = str(exc)
        return {**common, "status": "NOT_RUN", "reason": reason if reason.startswith("ast_")
                else "ast_complexity_limit"}
    return {
        **common, **details,
        "status": "INSPECTED_PARTIAL",
        "syntax_parse": "PASS",
        "ast_positions": "CPYTHON_UTF8_BYTE_OFFSETS",
        "note": "No execution, compile guarantee, full CST, dynamic graph or behavior proof",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze_file(args.file), ensure_ascii=False))


if __name__ == "__main__":
    main()
