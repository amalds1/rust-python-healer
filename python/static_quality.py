"""Read-only, version-bound static security and code-smell classification.

F096: every declared rule ID is mapped to one fixed category/severity;
unknown identifiers fail closed. F098/F161: strictly bounded syntactic
candidates only, never a proof of dead code, vulnerability or task scheduling.
Target Python source is parsed, never executed, evaluated or imported.
"""

import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tokenize


MAX_SOURCE_BYTES = 1_048_576
MAX_NODES = 100_000
MAX_FINDINGS = 2000

# This is a fixed rule vocabulary, not a guess about arbitrary package APIs.
# A rule can classify a *possible* risk even where no runtime vulnerability
# has independently been established.
RULES = {
    "SEC001": ("SECURITY", "HIGH", "POSSIBLE_BUILTIN_EVAL_OR_EXEC"),
    "SEC002": ("SECURITY", "HIGH", "POSSIBLE_SHELL_EXECUTION"),
    "SEC003": ("SECURITY", "HIGH", "POSSIBLE_UNTRUSTED_DESERIALIZATION"),
    "SEC004": ("SECURITY", "MEDIUM", "POSSIBLE_UNSAFE_TEMP_FILENAME"),
    "SMELL001": ("CODE_SMELL", "MEDIUM", "BARE_EXCEPT_CLAUSE"),
    "SMELL002": ("CODE_SMELL", "LOW", "POSSIBLY_UNUSED_LOCAL_ASSIGNMENT"),
    "SMELL003": ("CODE_SMELL", "MEDIUM", "STATEMENT_AFTER_UNCONDITIONAL_TERMINATOR"),
    "SMELL004": ("CODE_SMELL", "LOW", "LITERAL_UNREACHABLE_IF_BRANCH"),
    "ASYNC001": ("ASYNC", "MEDIUM", "POSSIBLE_UNAWAITED_LOCAL_COROUTINE"),
}


def classify_rule(rule_id):
    """Classify the complete declared rule vocabulary, reject unknown IDs."""
    if type(rule_id) is not str or rule_id not in RULES:
        return {"status": "UNKNOWN_UNCLASSIFIED", "category": "UNKNOWN",
                "severity": "UNKNOWN", "rule_id": "UNKNOWN"}
    category, severity, reason = RULES[rule_id]
    return {"status": "CLASSIFIED", "rule_id": rule_id,
            "category": category, "severity": severity, "reason_code": reason}


def read_source(path):
    """Read one bounded unique ordinary file, no final-link traversal."""
    target = Path(path)
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("source_not_regular_file")
    if info.st_nlink != 1:
        raise ValueError("source_hardlink_refused")
    if info.st_size > MAX_SOURCE_BYTES:
        raise ValueError("source_size_limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(str(target), flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("source_changed_during_open")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ValueError("source_not_unique_regular_file")
        data = stream.read(MAX_SOURCE_BYTES + 1)
        after = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("source_changed_during_read")
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError("source_size_limit")
    return data


def decode_source(content):
    """Honor a source encoding cookie without importing the source."""
    encoding, _ = tokenize.detect_encoding(io.BytesIO(content).readline)
    return content.decode(encoding)


def direct_name(expr):
    """Return only syntactically direct names; no attribute evaluation."""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
        return expr.value.id + "." + expr.attr
    return None


def inspect_tree(tree):
    """Find bounded syntactic candidates, never execute or infer behavior."""
    findings = []
    counter = {"nodes": 0}
    async_declarations = {node.name for node in tree.body
                          if isinstance(node, ast.AsyncFunctionDef)}

    def emit(rule, node, certainty="STATIC_CANDIDATE_NOT_VERIFIED"):
        if len(findings) >= MAX_FINDINGS:
            raise ValueError("finding_limit")
        classified = classify_rule(rule)
        findings.append({**classified,
                         "line": getattr(node, "lineno", None),
                         "column_utf8_bytes": getattr(node, "col_offset", None),
                         "confidence": certainty})

    def scan_after_terminator(body):
        terminated = False
        for node in body:
            if terminated:
                emit("SMELL003", node, "SYNTACTICALLY_UNREACHABLE_SAME_BLOCK")
            if isinstance(node, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                terminated = True

    def local_unused(function):
        # Unknown dynamic scope operations invalidate any name-use inference.
        contents = list(ast.walk(function))
        for item in contents:
            if isinstance(item, (ast.Global, ast.Nonlocal)):
                return
            if isinstance(item, ast.Call) and direct_name(item.func) in (
                    "locals", "globals", "vars", "eval", "exec"):
                return
        loaded = {item.id for item in contents if isinstance(item, ast.Name)
                  and isinstance(item.ctx, ast.Load)}
        seen = set()
        for item in contents:
            if not isinstance(item, (ast.Assign, ast.AnnAssign)):
                continue
            targets = item.targets if isinstance(item, ast.Assign) else [item.target]
            for target in targets:
                if (isinstance(target, ast.Name) and target.id not in loaded and
                        target.id not in seen and not target.id.startswith("_")):
                    seen.add(target.id)
                    emit("SMELL002", target)

    class Inspector(ast.NodeVisitor):
        def visit(self, node):
            counter["nodes"] += 1
            if counter["nodes"] > MAX_NODES:
                raise ValueError("ast_node_limit")
            super().visit(node)

        def visit_FunctionDef(self, node):
            scan_after_terminator(node.body)
            local_unused(node)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node):
            scan_after_terminator(node.body)
            local_unused(node)
            self.generic_visit(node)

        def visit_If(self, node):
            if isinstance(node.test, ast.Constant) and type(node.test.value) is bool:
                unreachable = node.orelse if node.test.value else node.body
                for item in unreachable:
                    emit("SMELL004", item, "PROVEN_LITERAL_IF_BRANCH_UNREACHABLE")
            self.generic_visit(node)

        def visit_ExceptHandler(self, node):
            if node.type is None:
                emit("SMELL001", node, "PROVEN_SYNTAX_PATTERN")
            self.generic_visit(node)

        def visit_Call(self, node):
            name = direct_name(node.func)
            if name in ("eval", "exec"):
                emit("SEC001", node)
            elif name in ("os.system", "subprocess.call", "subprocess.Popen",
                          "subprocess.run"):
                if name == "os.system" or any(
                        arg.arg == "shell" and isinstance(arg.value, ast.Constant)
                        and arg.value.value is True for arg in node.keywords):
                    emit("SEC002", node)
            elif name in ("pickle.loads", "pickle.load"):
                emit("SEC003", node)
            elif name == "tempfile.mktemp":
                emit("SEC004", node)
            self.generic_visit(node)

        def visit_Expr(self, node):
            if (isinstance(node.value, ast.Call) and
                    isinstance(node.value.func, ast.Name) and
                    node.value.func.id in async_declarations):
                emit("ASYNC001", node)
            self.generic_visit(node)

    Inspector().visit(tree)
    findings.sort(key=lambda item: (item["line"] or 0, item["column_utf8_bytes"] or 0,
                                    item["rule_id"]))
    return {"findings": findings, "nodes_visited": counter["nodes"],
            "findings_count": len(findings), "all_declared_rules_classified": True,
            "code_behavior_verified": False,
            "unawaited_coroutines_verified": False,
            "unused_variables_verified": False,
            "security_vulnerabilities_verified": False}


def analyze_file(path):
    """Report only bounded static potential findings with no source leakage."""
    try:
        data = read_source(path)
    except (OSError, ValueError) as exc:
        known = {"source_not_regular_file", "source_not_unique_regular_file",
                 "source_hardlink_refused", "source_size_limit",
                 "source_changed_during_open", "source_changed_during_read"}
        reason = str(exc)
        return {"status": "NOT_RUN", "reason": reason if reason in known else "source_unavailable",
                "source_executed": False, "code_behavior_verified": False}
    common = {"source_sha256": hashlib.sha256(data).hexdigest(),
              "source_executed": False, "code_behavior_verified": False,
              "path_protection": "FINAL_NOFOLLOW_HARDLINK_REFUSAL_NOT_OS_SANDBOX",
              "scope": "STATIC_DECLARED_RULES_ONLY_NOT_FULL_SECURITY_AUDIT"}
    try:
        text = decode_source(data)
    except (UnicodeError, SyntaxError, LookupError) as exc:
        return {**common, "status": "INVALID_ENCODING", "error_type": type(exc).__name__}
    try:
        tree = ast.parse(text)
    except (SyntaxError, RecursionError, MemoryError, ValueError, TypeError) as exc:
        return {**common, "status": "SYNTAX_ERROR" if isinstance(exc, SyntaxError) else "NOT_RUN",
                "error_type": type(exc).__name__, "line": getattr(exc, "lineno", None)}
    try:
        result = inspect_tree(tree)
    except (ValueError, RecursionError, MemoryError) as exc:
        reason = str(exc)
        return {**common, "status": "NOT_RUN", "reason": reason if reason.endswith("_limit")
                else "ast_complexity_limit"}
    return {**common, **result, "status": "INSPECTED_PARTIAL",
            "python_minor": "{}.{}".format(sys.version_info.major, sys.version_info.minor)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, nargs="?")
    parser.add_argument("--classify")
    args = parser.parse_args()
    if bool(args.file) == bool(args.classify):
        parser.error("choose exactly one file or --classify")
    print(json.dumps(classify_rule(args.classify) if args.classify else
                     analyze_file(args.file), ensure_ascii=False))


if __name__ == "__main__":
    main()
