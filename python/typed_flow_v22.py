"""Bounded multi-module AST type, CFG, call and alias inference (F092/097/099).

Pure in-memory static analysis: no import, eval, exec, compilation or filesystem
scan of target source.  Any dynamic dispatch, branches in alias flow or
unsupported annotation is explicitly UNKNOWN, never a proven runtime edge.
"""

import argparse
import ast
import hashlib
import json
import re


MAX_MODULES = 32
MAX_SOURCE_BYTES = 1_000_000
MAX_NODES = 20_000
MAX_EDGES = 40_000
MODULE = re.compile(r"^[A-Za-z_][A-Za-z_0-9]{0,127}\.py$")
TYPES = frozenset(("str", "int", "bool", "float", "bytes", "list", "dict", "set"))
MUTATORS = frozenset(("append", "extend", "insert", "pop", "remove", "clear",
                      "update", "add", "discard", "setdefault"))


def primitive_type(node):
    """Types are intentionally exact builtins, not class hierarchy claims."""
    if isinstance(node, ast.Constant):
        return type(node.value).__name__ if type(node.value).__name__ in TYPES else None
    for kind, name in ((ast.List, "list"), (ast.Tuple, "tuple"),
                       (ast.Dict, "dict"), (ast.Set, "set")):
        if isinstance(node, kind):
            return name
    if isinstance(node, ast.Name) and node.id in TYPES:
        return node.id
    return None


def annotation_type(node):
    if isinstance(node, ast.Name) and node.id in TYPES:
        return node.id
    return None


def _modules(source_map):
    if type(source_map) is not dict or not 1 <= len(source_map) <= MAX_MODULES:
        raise ValueError("invalid_module_count")
    parsed = {}
    for name, value in source_map.items():
        if type(name) is not str or not MODULE.fullmatch(name):
            raise ValueError("invalid_module_name")
        if type(value) is not str or len(value.encode("utf-8")) > MAX_SOURCE_BYTES:
            raise ValueError("invalid_source_size")
        if "\x00" in value:
            raise ValueError("null_byte_in_source")
        try:
            tree = ast.parse(value, filename="<static-{}>".format(name),
                             mode="exec", type_comments=True)
        except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
            raise ValueError("invalid_python_syntax") from exc
        if sum(1 for _ in ast.walk(tree)) > MAX_NODES:
            raise ValueError("ast_node_budget")
        parsed[name[:-3]] = (tree, hashlib.sha256(value.encode("utf-8")).hexdigest())
    return parsed


def _symbols(parsed):
    signatures = {}
    imports = {}
    for module, (tree, _) in parsed.items():
        aliases = {}
        for stmt in tree.body:
            if isinstance(stmt, ast.Import):
                for item in stmt.names:
                    if item.name in parsed:
                        aliases[item.asname or item.name] = (item.name, None)
            elif isinstance(stmt, ast.ImportFrom):
                if stmt.level == 0 and stmt.module in parsed:
                    for item in stmt.names:
                        if item.name != "*":
                            aliases[item.asname or item.name] = (stmt.module, item.name)
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parameters = stmt.args.posonlyargs + stmt.args.args
                signatures[(module, stmt.name)] = {
                    "arguments": [(param.arg, annotation_type(param.annotation))
                                  for param in parameters],
                    "return": annotation_type(stmt.returns),
                }
        imports[module] = aliases
    return signatures, imports


class ControlFlow:
    """Statement-level conservative graph with true/false/loop edges."""

    def __init__(self, module, function):
        self.module = module
        self.function = function
        self.nodes = []
        self.edges = []

    def node(self, kind, line):
        if len(self.nodes) >= 4000:
            raise ValueError("control_flow_node_budget")
        identifier = len(self.nodes)
        self.nodes.append({"id": identifier, "kind": kind, "line": line})
        return identifier

    def connect(self, parents, target):
        for parent, label in parents:
            if len(self.edges) >= MAX_EDGES:
                raise ValueError("control_flow_edge_budget")
            self.edges.append({"from": parent, "to": target, "branch": label})

    def sequence(self, statements, parents):
        frontier = parents
        for stmt in statements:
            current = self.node(type(stmt).__name__, getattr(stmt, "lineno", None))
            self.connect(frontier, current)
            if isinstance(stmt, ast.If):
                yes = self.sequence(stmt.body, [(current, "true")])
                no = self.sequence(stmt.orelse, [(current, "false")]) if stmt.orelse else [
                    (current, "false")]
                frontier = yes + no
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                body = self.sequence(stmt.body, [(current, "iterate")])
                self.connect([(tail, "loop_back") for tail, _ in body], current)
                frontier = (self.sequence(stmt.orelse, [(current, "exhausted")])
                            if stmt.orelse else [(current, "exhausted")])
            elif isinstance(stmt, (ast.Return, ast.Raise)):
                frontier = []
            else:
                frontier = [(current, "next")]
        return frontier

    def build(self, body):
        start = self.node("ENTRY", None)
        leaves = self.sequence(body, [(start, "enter")])
        end = self.node("EXIT", None)
        self.connect(leaves, end)
        # Return and raise nodes also end a path; edges remain explicit.
        for node in self.nodes:
            if node["kind"] in ("Return", "Raise"):
                self.connect([(node["id"], "terminal")], end)
        return {"module": self.module, "function": self.function,
                "nodes": self.nodes, "edges": self.edges,
                "dynamic_control_flow_proven": False}


def _resolve_call(func, module, signatures, imports):
    if isinstance(func, ast.Name):
        if (module, func.id) in signatures:
            return (module, func.id)
        return imports[module].get(func.id)
    if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)):
        origin = imports[module].get(func.value.id)
        if origin and origin[1] is None:
            return origin[0], func.attr
    return None


def _alias_trace(body):
    """Track straight-line literal containers and name aliases only."""
    aliases = {}
    mutated = []
    allocated = 0
    uncertain = False
    for stmt in body:
        if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try,
                             ast.With, ast.AsyncWith)):
            uncertain = True
            continue
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            value = stmt.value
            if isinstance(value, (ast.List, ast.Dict, ast.Set)):
                allocated += 1
                token = "local-object-{}".format(allocated)
            elif isinstance(value, ast.Name) and value.id in aliases:
                token = aliases[value.id]
            else:
                token = None
            for target in targets:
                if isinstance(target, ast.Name):
                    if token is None:
                        aliases.pop(target.id, None)
                    else:
                        aliases[target.id] = token
        if (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) and
                isinstance(stmt.value.func, ast.Attribute) and
                isinstance(stmt.value.func.value, ast.Name) and
                stmt.value.func.attr in MUTATORS):
            variable = stmt.value.func.value.id
            token = aliases.get(variable)
            if token:
                mutated.append({"object": token, "method": stmt.value.func.attr,
                                "through": variable, "line": stmt.lineno,
                                "aliases_at_mutation": sorted(key for key, value in aliases.items()
                                                              if value == token)})
    return {"mutations": mutated, "final_local_aliases": dict(sorted(aliases.items())),
            "branch_sensitive": not uncertain,
            "dynamic_aliases_resolved": False}


def analyze_sources(source_map):
    """Return real finite AST graph/type/alias evidence with explicit gaps."""
    parsed = _modules(source_map)
    signatures, imports = _symbols(parsed)
    cfgs = []
    calls = []
    mismatches = []
    aliases = []
    unresolved = 0
    for module, (tree, digest) in parsed.items():
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                flow = ControlFlow(module, stmt.name).build(stmt.body)
                cfgs.append(flow)
                aliases.append({"module": module, "function": stmt.name,
                                **_alias_trace(stmt.body)})
                expected_return = signatures[(module, stmt.name)]["return"]
                for node in ast.walk(stmt):
                    if (isinstance(node, ast.Return) and node.value is not None and
                            expected_return and primitive_type(node.value) and
                            primitive_type(node.value) != expected_return):
                        mismatches.append({"kind": "RETURN_TYPE", "module": module,
                                           "function": stmt.name, "line": node.lineno,
                                           "expected": expected_return,
                                           "actual": primitive_type(node.value)})
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                resolved = _resolve_call(node.func, module, signatures, imports)
                if not resolved or resolved not in signatures:
                    unresolved += 1
                    continue
                calls.append({"from_module": module, "to_module": resolved[0],
                              "to_function": resolved[1], "line": node.lineno,
                              "status": "STATIC_NAME_RESOLUTION_ONLY"})
                signature = signatures[resolved]["arguments"]
                for index, arg in enumerate(node.args[:len(signature)]):
                    expected = signature[index][1]
                    actual = primitive_type(arg)
                    if expected and actual and actual != expected:
                        mismatches.append({"kind": "CALL_ARGUMENT_TYPE", "module": module,
                                           "to_module": resolved[0],
                                           "to_function": resolved[1],
                                           "line": node.lineno, "argument": signature[index][0],
                                           "expected": expected, "actual": actual})
            elif isinstance(node, ast.AnnAssign):
                expected = annotation_type(node.annotation)
                actual = primitive_type(node.value)
                if expected and actual and expected != actual:
                    mismatches.append({"kind": "ANNOTATION_TYPE", "module": module,
                                       "line": node.lineno, "expected": expected,
                                       "actual": actual})
    if sum(len(flow["nodes"]) for flow in cfgs) > MAX_NODES:
        raise ValueError("aggregate_graph_budget")
    return {"status": "BOUNDED_STATIC_TYPE_CALL_CFG_ALIAS_ANALYSIS",
            "versions": {mod: sha for mod, (_, sha) in parsed.items()},
            "control_flow_graphs": cfgs, "static_call_edges": calls,
            "type_mismatches": mismatches, "alias_dataflow": aliases,
            "unresolved_dynamic_call_count": unresolved,
            "supports_multi_module_static_resolution": True,
            "full_python_dynamic_semantics_proven": False,
            "project_source_executed": False, "target_modules_imported": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities",), default="capabilities")
    parser.parse_args(argv)
    print(json.dumps({"status": "BOUNDED_STATIC_ANALYSIS_CAPABILITIES",
                      "ast_types_cfg_aliases": True,
                      "unknown_source_execution": False,
                      "dynamic_semantics_proven": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
