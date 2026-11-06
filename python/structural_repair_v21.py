"""F010/F027/F028/F091/F092/F097/F099/F193 bounded structural tools.

Only the fixed, hardcoded F193 test fixture is *executed*. Arbitrary Python
files are read without imports, execution, evaluation, installation or network.
Repairs are merely syntax-valid candidates; semantic behavior is unproven.
Native ``ast`` is not a full CST/type-checker/CFG or points-to analysis.
"""

import ast
import dis
import hashlib
import io
import os
from pathlib import Path
import re
import stat
import sys
import tokenize


MAX_SOURCE_BYTES = 1_000_000
MAX_AST_NODES = 8000
MAX_TOKENS = 16000
MAX_GRAPH_EDGES = 6000
MAX_MODULES = 24
_MODULE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]{0,80}\.py\Z", re.ASCII)
_HEADER = re.compile(r"^\s*(?:async\s+(?:def|for|with)|if|elif|else|for|while|def|class|try|except|finally|with)\b")
_VALID_TYPES = frozenset(("int", "str", "bool", "float", "bytes", "list", "dict", "tuple", "set", "None"))


class StaticLimit(Exception):
    pass


def _read_source(path):
    """Return PEP263-decoded source only after bounded regular-file checks."""
    try:
        before = Path(path).lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise StaticLimit("source_not_private_regular_file")
        if before.st_size > MAX_SOURCE_BYTES:
            raise StaticLimit("source_size_limit")
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as file:
            opened = os.fstat(file.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise StaticLimit("source_changed_during_open")
            data = file.read(MAX_SOURCE_BYTES + 1)
            after = os.fstat(file.fileno())
        if (len(data) > MAX_SOURCE_BYTES or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise StaticLimit("source_changed_during_read")
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        return data.decode(encoding)
    except StaticLimit:
        raise
    except (OSError, UnicodeError, SyntaxError, LookupError, ValueError, TypeError):
        raise StaticLimit("source_unreadable_or_bad_encoding") from None


def _parse(source):
    if not isinstance(source, str):
        raise StaticLimit("source_size_limit")
    try:
        encoded = source.encode("utf-8")
    except UnicodeError:
        raise StaticLimit("source_invalid_unicode") from None
    if len(encoded) > MAX_SOURCE_BYTES:
        raise StaticLimit("source_size_limit")
    try:
        tree = ast.parse(source, type_comments=True)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        raise StaticLimit("source_syntax_invalid") from None
    if sum(1 for _ in ast.walk(tree)) > MAX_AST_NODES:
        raise StaticLimit("ast_node_limit")
    return tree


def _tokens(source):
    try:
        result = list(tokenize.generate_tokens(io.StringIO(source).readline))
        if len(result) > MAX_TOKENS:
            raise StaticLimit("token_count_limit")
        return result
    except (tokenize.TokenError, IndentationError, SyntaxError):
        raise StaticLimit("tokenization_failed") from None


def _missing_colon_error(source):
    try:
        compile(source, "<untrusted-not-executed>", "exec", dont_inherit=True)
    except SyntaxError as error:
        return error.lineno
    except (ValueError, TypeError, RecursionError):
        return None
    return None


def _insert_at(source, line_number, column):
    lines = source.splitlines(keepends=True)
    if not 1 <= line_number <= len(lines):
        return None
    line = lines[line_number - 1]
    if not 0 <= column <= len(line):
        return None
    lines[line_number - 1] = line[:column] + ":" + line[column:]
    return "".join(lines)


def _lexical_colon_strategy(source, lineno):
    """Strategy A: position the colon by independently tokenized row edges."""
    if lineno is None:
        return None
    lines = source.splitlines(keepends=True)
    if not 1 <= lineno <= len(lines) or not _HEADER.match(lines[lineno - 1]):
        return None
    try:
        tokens = _tokens(source)
    except StaticLimit:
        return None
    row = [t for t in tokens if t.start[0] == lineno and t.type not in
           (tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
            tokenize.ENDMARKER, tokenize.COMMENT)]
    if not row or any(t.end[0] != lineno for t in row):
        return None
    # The last real token may not be from a multiline continuation.
    last = row[-1]
    if last.string in (":", "\\") or last.end[1] > len(lines[lineno - 1]):
        return None
    if last.string in ("(", "[", "{"):
        return None
    return _insert_at(source, lineno, last.end[1])


def _line_colon_strategy(source, lineno):
    """Strategy B: independently scan quotes/escapes to locate an inline #."""
    lines = source.splitlines(keepends=True)
    if lineno is None or not 1 <= lineno <= len(lines):
        return None
    line = lines[lineno - 1]
    if not _HEADER.match(line) or line.rstrip().endswith("\\"):
        return None
    quote = None
    escaped = False
    cutoff = len(line.rstrip("\r\n"))
    for index, ch in enumerate(line):
        if escaped:
            escaped = False
        elif ch == "\\" and quote:
            escaped = True
        elif ch in ("'", '"'):
            if quote is None:
                quote = ch
            elif quote == ch:
                quote = None
        elif ch == "#" and quote is None:
            cutoff = index
            break
    if quote is not None:
        return None
    trimmed = line[:cutoff].rstrip(" \t\r\n")
    if not trimmed or trimmed.endswith((":", "\\", "(", "[", "{")):
        return None
    return _insert_at(source, lineno, len(trimmed))


def validate_colon_advice(original, candidate):
    """Independent F010 gate: an exact single ':' insertion and lexical match.

    Compiles both sides without execution and verifies tokens/comments beyond
    the inserted colon are unchanged. Syntax is verified, semantics are not.
    """
    baseline = {"advice_valid": False, "user_code_executed": False,
                "semantics_verified": False}
    if not isinstance(original, str) or not isinstance(candidate, str):
        return {**baseline, "reason": "invalid_candidate_type"}
    try:
        candidate_size = len(candidate.encode("utf-8"))
    except UnicodeError:
        return {**baseline, "reason": "invalid_candidate_unicode"}
    if len(candidate) != len(original) + 1 or candidate_size > MAX_SOURCE_BYTES:
        return {**baseline, "reason": "not_exactly_one_character_inserted"}
    offset = next((i for i, (x, y) in enumerate(zip(original, candidate)) if x != y),
                  len(original))
    if candidate[offset:offset + 1] != ":" or candidate[:offset] + candidate[offset + 1:] != original:
        return {**baseline, "reason": "not_exactly_one_colon_inserted"}
    error_line = _missing_colon_error(original)
    if error_line is None:
        return {**baseline, "reason": "original_has_no_syntax_error"}
    source_lines = original.splitlines(keepends=True)
    affected_line = original[:offset].count("\n") + 1
    if (affected_line != error_line or not 1 <= affected_line <= len(source_lines)
            or not _HEADER.match(source_lines[affected_line - 1])):
        return {**baseline, "reason": "insertion_not_on_compound_header"}
    try:
        compile(candidate, "<candidate-not-executed>", "exec", dont_inherit=True)
        a = _tokens(original)
        b = _tokens(candidate)
    except (SyntaxError, ValueError, StaticLimit, RecursionError):
        return {**baseline, "reason": "candidate_did_not_compile_or_tokenize"}
    a_tokens = [(token.type, token.string) for token in a]
    b_tokens = [(token.type, token.string) for token in b]
    colon = (tokenize.OP, ":")
    if colon not in b_tokens:
        return {**baseline, "reason": "token_stream_changed"}
    # An existing ':' may occur elsewhere; try each possible inserted colon.
    if not any(b_tokens[:i] + b_tokens[i + 1:] == a_tokens for i, item in enumerate(b_tokens)
               if item == colon):
        return {**baseline, "reason": "token_stream_changed"}
    return {**baseline, "advice_valid": True,
            "reason": "ONE_COLON_COMPILE_AND_TOKEN_EQUIVALENT",
            "formatting_and_comments_preserved": True}


def propose_colon_repair(original):
    baseline = {"status": "NO_PATCH", "source_executed": False,
                "semantic_correctness_proven": False}
    if not isinstance(original, str):
        return {**baseline, "reason": "source_size_limit"}
    try:
        size = len(original.encode("utf-8"))
    except UnicodeError:
        return {**baseline, "reason": "source_invalid_unicode"}
    if size > MAX_SOURCE_BYTES:
        return {**baseline, "reason": "source_size_limit"}
    line = _missing_colon_error(original)
    first = _lexical_colon_strategy(original, line)
    second = _line_colon_strategy(original, line)
    if first is None or second is None or first != second:
        return {**baseline, "reason": "strategies_disagree_or_unsupported"}
    verdict = validate_colon_advice(original, first)
    if not verdict["advice_valid"]:
        return {**baseline, "reason": verdict["reason"]}
    return {**baseline, "status": "COMPILES_TWO_INDEPENDENT_STRATEGIES",
            "candidate": first, "validation": verdict,
            "original_sha256": hashlib.sha256(original.encode("utf-8")).hexdigest(),
            "candidate_sha256": hashlib.sha256(first.encode("utf-8")).hexdigest(),
            "changed_line": line, "strategy_count": 2}


def inspect_ast_and_tokens(source):
    """AST with byte columns + byte-lossless token/trivia overlay (not full CST)."""
    baseline = {"status": "NOT_RUN", "source_executed": False,
                "full_cst_built": False, "type_semantics_verified": False}
    try:
        tree = _parse(source)
        tokens = _tokens(source)
        reconstructed = tokenize.untokenize(tokens)
        if isinstance(reconstructed, bytes):
            reconstructed = reconstructed.decode("utf-8")
    except StaticLimit as error:
        return {**baseline, "reason": str(error)}
    except (UnicodeError, ValueError):
        return {**baseline, "reason": "token_roundtrip_failed"}
    entries = []
    queue = [(tree, None)]
    while queue:
        node, parent_index = queue.pop(0)
        index = len(entries)
        entries.append({"kind": type(node).__name__, "parent_index": parent_index,
                        "start_line": getattr(node, "lineno", None),
                        "start_utf8_byte_column": getattr(node, "col_offset", None),
                        "end_line": getattr(node, "end_lineno", None),
                        "end_utf8_byte_column": getattr(node, "end_col_offset", None)})
        for child in ast.iter_child_nodes(node):
            queue.append((child, index))
    token_spans = [{"kind": tokenize.tok_name[token.type],
                    "start_line": token.start[0], "start_character_column": token.start[1],
                    "end_line": token.end[0], "end_character_column": token.end[1]}
                   for token in tokens]
    return {**baseline, "status": "AST_PLUS_LOSSLESS_TOKEN_TRIVIA",
            "ast_nodes": entries, "tokens": token_spans,
            "ast_count": len(entries), "token_count": len(tokens),
            "comment_count": sum(t.type == tokenize.COMMENT for t in tokens),
            "exact_token_roundtrip": reconstructed == source,
            "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "cst_scope": "TOKEN_TRIVIA_OVERLAY_NOT_FULL_CST"}


def _annotation_type(annotation):
    if isinstance(annotation, ast.Name) and annotation.id in _VALID_TYPES:
        return annotation.id
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str) \
            and annotation.value in _VALID_TYPES:
        return annotation.value
    if isinstance(annotation, ast.Constant) and annotation.value is None:
        return "None"
    return None


def _literal_type(node):
    if isinstance(node, ast.Constant):
        if node.value is None:
            return "None"
        return type(node.value).__name__ if type(node.value).__name__ in _VALID_TYPES else None
    for kind, value in ((ast.List, "list"), (ast.Tuple, "tuple"),
                        (ast.Dict, "dict"), (ast.Set, "set")):
        if isinstance(node, kind):
            return value
    return None


def inspect_crossmodule_types(source_files):
    """Infer candidates for direct imported function calls; never import files.

    ``source_files`` is an operator-selected map module-basename -> local path.
    Inference is only declared annotations or literal-return candidates, not
    semantic safety/typing proof under monkeypatches, decorators or side effects.
    """
    baseline = {"status": "NOT_RUN", "user_code_executed": False,
                "modules_imported": False, "semantic_types_proven": False}
    if not isinstance(source_files, dict) or not 1 <= len(source_files) <= MAX_MODULES:
        return {**baseline, "reason": "invalid_module_inventory"}
    trees = {}
    total = 0
    try:
        for name, path in sorted(source_files.items()):
            if not isinstance(name, str) or not _MODULE.fullmatch(name):
                raise StaticLimit("invalid_module_name")
            source = _read_source(path)
            total += len(source.encode("utf-8"))
            if total > 4 * MAX_SOURCE_BYTES:
                raise StaticLimit("crossmodule_byte_budget")
            trees[name[:-3]] = _parse(source)
    except StaticLimit as error:
        return {**baseline, "reason": str(error)}
    signatures = {}
    for module, tree in trees.items():
        own = {}
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            declared = _annotation_type(node.returns)
            if declared:
                own[node.name] = (declared, "ANNOTATION_CANDIDATE_NOT_RUNTIME_VERIFIED")
                continue
            returns = [item for item in ast.walk(node) if isinstance(item, ast.Return)]
            types = {_literal_type(item.value) for item in returns}
            if len(types) == 1 and None not in types and types:
                own[node.name] = (next(iter(types)), "LITERAL_RETURN_CANDIDATE_NOT_PROVEN")
        signatures[module] = own
    inferred = []
    unresolved = 0
    for module, tree in trees.items():
        imported_funcs = {}
        imported_modules = {}
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    imported_funcs.pop(local_name, None)
                    imported_modules.pop(local_name, None)
                    if node.level == 0 and node.module in trees \
                            and alias.name in signatures[node.module]:
                        imported_funcs[local_name] = signatures[node.module][alias.name]
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    imported_funcs.pop(local_name, None)
                    imported_modules.pop(local_name, None)
                    if alias.name in trees:
                        imported_modules[local_name] = alias.name
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = (node.targets if isinstance(node, ast.Assign) else [node.target])
                target = targets[0] if len(targets) == 1 else None
                value = node.value
                if (isinstance(node, (ast.Assign, ast.AnnAssign))
                        and isinstance(target, ast.Name) and isinstance(value, ast.Call)):
                    candidate = None
                    if isinstance(value.func, ast.Name):
                        candidate = imported_funcs.get(value.func.id)
                    elif isinstance(value.func, ast.Attribute) and isinstance(value.func.value, ast.Name):
                        target_module = imported_modules.get(value.func.value.id)
                        candidate = signatures.get(target_module, {}).get(value.func.attr)
                    if candidate:
                        inferred.append({"module": module, "assignment_line": node.lineno,
                                         "variable": target.id, "candidate_type": candidate[0],
                                         "confidence": candidate[1]})
                    else:
                        unresolved += 1
                # Binding changes must invalidate stale import aliases.
                for part in targets:
                    for symbol in ast.walk(part):
                        if isinstance(symbol, ast.Name):
                            imported_funcs.pop(symbol.id, None)
                            imported_modules.pop(symbol.id, None)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                imported_funcs.pop(node.name, None)
                imported_modules.pop(node.name, None)
            elif isinstance(node, (ast.If, ast.For, ast.While, ast.Try, ast.With,
                                   ast.AsyncFor, ast.AsyncWith, ast.Delete)):
                # Conditional/dynamic rebinding requires real flow analysis.
                imported_funcs.clear()
                imported_modules.clear()
    return {**baseline, "status": "CROSSMODULE_STATIC_CANDIDATES",
            "module_count": len(trees), "inferred_assignments": inferred,
            "unresolved_calls": unresolved,
            "module_imports_executed": False}


def inspect_cfg_calls(source):
    """Build a bounded, syntactic CFG/call graph (exceptions remain unknown)."""
    baseline = {"status": "NOT_RUN", "user_code_executed": False,
                "runtime_call_targets_verified": False,
                "exceptional_control_flow_verified": False}
    try:
        tree = _parse(source)
        nodes = {}
        edges = []
        counter = [0]

        def add_edge(frm, to, condition):
            if len(edges) >= MAX_GRAPH_EDGES:
                raise StaticLimit("cfg_edge_budget")
            edges.append({"from": frm, "to": to, "edge": condition,
                          "confidence": "SYNTACTIC_ONLY"})

        def node_id(stmt, scope):
            key = id(stmt)
            if key not in nodes:
                counter[0] += 1
                nodes[key] = {"id": "n{}".format(counter[0]), "scope": scope,
                              "kind": type(stmt).__name__,
                              "line": getattr(stmt, "lineno", 0)}
            return nodes[key]["id"]

        def block(statements, next_id, scope):
            following = next_id
            for stmt in reversed(statements):
                current = node_id(stmt, scope)
                if isinstance(stmt, (ast.Return, ast.Raise)):
                    add_edge(current, "EXIT", "STOP")
                elif isinstance(stmt, ast.If):
                    true_dest = block(stmt.body, following, scope)
                    false_dest = block(stmt.orelse, following, scope)
                    add_edge(current, true_dest, "IF_TRUE")
                    add_edge(current, false_dest, "IF_FALSE")
                elif isinstance(stmt, (ast.For, ast.While, ast.AsyncFor)):
                    loop_head = block(stmt.body, current, scope)
                    after_loop = block(stmt.orelse, following, scope)
                    add_edge(current, loop_head, "LOOP_BODY_POSSIBLE")
                    add_edge(current, after_loop, "LOOP_EXIT_POSSIBLE")
                else:
                    add_edge(current, following, "SEQUENTIAL_CANDIDATE")
                following = current
            return following

        block(tree.body, "EXIT", "<module>")
        for item in tree.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                block(item.body, "EXIT", item.name)
        top_functions = {stmt.name for stmt in tree.body
                         if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))}
        possible_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id in top_functions:
                if len(possible_calls) >= MAX_GRAPH_EDGES:
                    raise StaticLimit("call_edge_budget")
                possible_calls.append({"to": node.func.id, "line": node.lineno,
                                       "confidence": "POSSIBLE_DIRECT_NAME_CALL_NOT_RESOLVED"})
    except StaticLimit as error:
        return {**baseline, "reason": str(error)}
    except RecursionError:
        return {**baseline, "reason": "control_flow_recursion_limit"}
    return {**baseline, "status": "PARTIAL_STATIC_CONTROL_FLOW_AND_CALL_GRAPH",
            "nodes": sorted(nodes.values(), key=lambda item: int(item["id"][1:])),
            "edges": edges, "possible_calls": possible_calls,
            "node_count": len(nodes), "edge_count": len(edges)}


def inspect_straightline_aliases(source):
    """Track exact-name binding identity only in straight-line function bodies."""
    baseline = {"status": "NOT_RUN", "user_code_executed": False,
                "heap_points_to_proven": False, "interprocedural_aliases_proven": False}
    try:
        tree = _parse(source)
    except StaticLimit as error:
        return {**baseline, "reason": str(error)}
    groups = []
    skipped = 0
    for func in tree.body:
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        unsupported = (ast.If, ast.For, ast.While, ast.AsyncFor, ast.Try,
                       ast.With, ast.AsyncWith, ast.FunctionDef, ast.AsyncFunctionDef,
                       ast.Delete, ast.Nonlocal, ast.Global)
        if hasattr(ast, "Match"):
            unsupported = unsupported + (ast.Match,)
        if any(isinstance(stmt, unsupported) for stmt in func.body) or any(
                isinstance(node, ast.NamedExpr) or
                (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id in ("exec", "eval", "locals", "globals", "vars"))
                for node in ast.walk(func)):
            skipped += 1
            continue
        bindings = {}
        serial = 0
        for stmt in func.body:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                    and isinstance(stmt.targets[0], ast.Name):
                target = stmt.targets[0].id
                if isinstance(stmt.value, ast.Name) and stmt.value.id in bindings:
                    bindings[target] = bindings[stmt.value.id]
                else:
                    serial += 1
                    bindings[target] = (func.name, serial)
            elif isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                # Unknown destructuring/rebinding makes final alias status
                # impossible to establish without full control/data flow.
                bindings = {}
                break
        by_object = {}
        for name, object_id in bindings.items():
            by_object.setdefault(object_id, []).append(name)
        for aliases in by_object.values():
            if len(aliases) >= 2:
                groups.append({"function": func.name, "bound_names": sorted(aliases),
                               "confidence": "SAME_BINDING_AFTER_STRAIGHTLINE_ASSIGNMENTS"})
    return {**baseline, "status": "STRAIGHTLINE_LOCAL_ALIAS_CANDIDATES",
            "alias_groups": groups, "skipped_control_or_dynamic_functions": skipped}


def measure_hardcoded_fixture_coverage():
    """F193: trusted fixed code only; trace line/branch and kill 4 mutants.

    Nothing in this function accepts Python source, file paths or callable
    objects from a caller. The hard-coded fixture is the only executed code.
    """
    baseline = {"status": "NOT_RUN", "user_code_executed": False,
                "arbitrary_code_executed": False, "coverage_of_user_code": False}
    fixture = (
        "def grade(n, branch):\n"
        "    if branch('negative', n < 0):\n"
        "        return 'negative'\n"
        "    if branch('zero', n == 0):\n"
        "        return 'zero'\n"
        "    if branch('even', n % 2 == 0):\n"
        "        return 'even'\n"
        "    return 'odd'\n"
    )
    variants = (
        fixture.replace("n < 0", "n <= 0"),
        fixture.replace("n == 0", "n != 0"),
        fixture.replace("n % 2 == 0", "n % 2 != 0"),
        fixture.replace("return 'odd'", "return 'even'"),
    )
    tests = (-5, 0, 2, 3)

    def expected(n):
        if n < 0:
            return "negative"
        if n == 0:
            return "zero"
        if n % 2 == 0:
            return "even"
        return "odd"

    def compile_fixture(text):
        scope = {"__builtins__": {}}
        exec(compile(text, "<trusted-hardcoded-f193>", "exec", dont_inherit=True), scope)
        return scope["grade"]

    func = compile_fixture(fixture)
    executed_lines = set()
    branch_outcomes = set()

    def branch(name, value):
        branch_outcomes.add((name, bool(value)))
        return value

    def tracer(frame, event, arg):
        if (frame.f_code.co_filename == "<trusted-hardcoded-f193>"
                and frame.f_code.co_name == "grade" and event == "line"):
            executed_lines.add(frame.f_lineno)
        return tracer

    previous_trace = sys.gettrace()
    try:
        sys.settrace(tracer)
        results = [func(value, branch) for value in tests]
    finally:
        sys.settrace(previous_trace)
    if results != [expected(value) for value in tests]:
        return {**baseline, "reason": "hardcoded_reference_mismatch"}
    executable_lines = {line for _, line in dis.findlinestarts(func.__code__)
                        if line > func.__code__.co_firstlineno}
    seen_lines = executable_lines.intersection(executed_lines)
    available_branches = {(key, outcome) for key in ("negative", "zero", "even")
                          for outcome in (False, True)}
    killed = 0
    for mutation in variants:
        mutant = compile_fixture(mutation)
        if any(mutant(value, lambda _name, condition: condition) != expected(value)
               for value in tests):
            killed += 1
    return {**baseline, "status": "TRUSTED_FIXTURE_COVERAGE_MEASURED",
            "line_covered": len(seen_lines), "line_total": len(executable_lines),
            "branch_covered": len(branch_outcomes.intersection(available_branches)),
            "branch_total": len(available_branches),
            "mutants_killed": killed, "mutants_total": len(variants),
            "inputs_tested": len(tests), "tracer_restored": sys.gettrace() is previous_trace}
