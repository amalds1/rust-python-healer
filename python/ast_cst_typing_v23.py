"""F091/F092: bounded real LibCST+CPython AST and external type oracles.

Only explicitly reviewed, private, flat multi-module fixture projects are in
scope. LibCST is a pinned *native binary wheel*, loaded for the running CPython
minor. The source is parsed, NEVER imported or executed. Separate real mypy
and Pyright processes serve as independent but fallible static-type oracles.

This does not establish complete Python semantics, a sandbox, or arbitrary
third-party-project compatibility; malformed and unsupported input is refused.
"""

import argparse
import ast
from collections import Counter
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import re
import sys

if "typecheck" not in globals():
    _TYPECHECK_SPEC = importlib.util.spec_from_file_location(
        "typecheck_integration_v23", Path(__file__).with_name("typecheck_integration_v23.py"))
    typecheck = importlib.util.module_from_spec(_TYPECHECK_SPEC)
    _TYPECHECK_SPEC.loader.exec_module(typecheck)


PINNED_LIBCST = "1.9.0"
SUPPORTED_MINORS = frozenset("3.{}".format(i) for i in range(9, 16))
MAX_AST_NODES = 5_000
MAX_CST_NODES = 20_000


def _libcst_preflight(package_root):
    root = typecheck._validate_private_root(package_root).resolve()
    folders = list(root.glob("libcst-*.dist-info"))
    if len(folders) != 1:
        raise ValueError("pinned_native_libcst_wheel_metadata_required")
    metadata = typecheck._regular_bytes(folders[0] / "METADATA", 500_000)
    if (len(re.findall(rb"(?m)^Name: libcst\r?$", metadata, re.I)) != 1 or
            len(re.findall(rb"(?m)^Version: 1\.9\.0\r?$", metadata)) != 1):
        raise ValueError("pinned_libcst_version_required")
    minor = "3.{}.".format(sys.version_info.minor)
    if minor[:-1] not in SUPPORTED_MINORS or sys.version_info.major != 3:
        raise ValueError("unsupported_running_interpreter")
    wheel = typecheck._regular_bytes(folders[0] / "WHEEL", 10_000)
    python_tag = "cp3{}-".format(sys.version_info.minor).encode("ascii")
    if not any(line.startswith(b"Tag: " + python_tag) for line in wheel.splitlines()):
        raise ValueError("native_libcst_wheel_wrong_cpython_abi")
    # Import only the pinned installed third-party parser, never fixture code.
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    libcst = importlib.import_module("libcst")
    if not Path(libcst.__file__).resolve().is_relative_to(root):
        raise ValueError("untrusted_libcst_import_origin")
    return libcst


def _utf8_col_to_unicode(line, byte_column):
    if byte_column < 0 or byte_column > len(line.encode("utf-8")):
        raise ValueError("ast_column_out_of_range")
    try:
        return len(line.encode("utf-8")[:byte_column].decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("ast_column_mid_utf8_character") from exc


def _inspect_source(name, raw, libcst):
    try:
        source = raw.decode("utf-8")
        parsed = ast.parse(source, filename=name)
        cst_module = libcst.parse_module(source)
        from libcst.metadata import MetadataWrapper, PositionProvider

        wrapper = MetadataWrapper(cst_module)
        positions = wrapper.resolve(PositionProvider)
    except (UnicodeError, SyntaxError, ValueError) as exc:
        raise ValueError("source_rejected_by_real_ast_or_cst") from exc
    except Exception as exc:
        # LibCST native parser errors are not stable across upstream versions.
        raise ValueError("source_rejected_by_real_ast_or_cst") from exc

    ast_nodes = list(ast.walk(parsed))
    if len(ast_nodes) > MAX_AST_NODES or len(positions) > MAX_CST_NODES:
        raise ValueError("ast_or_cst_node_budget")
    roundtrip = cst_module.code.encode("utf-8")
    if roundtrip != raw:
        raise ValueError("libcst_byte_for_byte_roundtrip_mismatch")
    lines = source.splitlines(keepends=True)
    # LibCST accurately locates a final newline's end at the *next* empty
    # line (line=N+1, column=0), a valid EOF boundary rather than corruption.
    if source.endswith(("\n", "\r")):
        lines.append("")
    positioned_ast = 0
    for node in ast_nodes:
        if not hasattr(node, "lineno"):
            continue
        if not all(hasattr(node, key) for key in ("col_offset", "end_lineno", "end_col_offset")):
            raise ValueError("ast_node_without_complete_source_range")
        start_line, end_line = node.lineno, node.end_lineno
        if (not isinstance(start_line, int) or not isinstance(end_line, int) or
                not 1 <= start_line <= end_line <= len(lines)):
            raise ValueError("ast_node_line_range_invalid")
        start = _utf8_col_to_unicode(lines[start_line - 1], node.col_offset)
        end = _utf8_col_to_unicode(lines[end_line - 1], node.end_col_offset)
        if start_line == end_line and end < start:
            raise ValueError("ast_node_column_range_invalid")
        if ast.get_source_segment(source, node) is None:
            raise ValueError("ast_node_has_no_source_segment")
        positioned_ast += 1
    cst_names = Counter()
    for node, code_range in positions.items():
        start, end = code_range.start, code_range.end
        if (not 1 <= start.line <= end.line <= len(lines) or
                not 0 <= start.column <= len(lines[start.line - 1]) or
                not 0 <= end.column <= len(lines[end.line - 1]) or
                (start.line == end.line and end.column < start.column)):
            raise ValueError("libcst_node_source_range_invalid")
        if isinstance(node, libcst.Name):
            cst_names[(node.value, code_range.start.line,
                       code_range.start.column, code_range.end.column)] += 1
    ast_names = Counter()
    for node in ast_nodes:
        if isinstance(node, ast.Name):
            start = _utf8_col_to_unicode(lines[node.lineno - 1], node.col_offset)
            end = _utf8_col_to_unicode(lines[node.end_lineno - 1], node.end_col_offset)
            if node.lineno != node.end_lineno:
                raise ValueError("identifier_crosses_multiple_lines")
            ast_names[(node.id, node.lineno, start, end)] += 1
    missing = ast_names - cst_names
    if missing:
        raise ValueError("ast_and_libcst_name_source_positions_disagree")
    return {"source_sha256": hashlib.sha256(raw).hexdigest(),
            "roundtrip_sha256": hashlib.sha256(roundtrip).hexdigest(),
            "byte_identical_roundtrip": True,
            "cpython_ast_nodes": len(ast_nodes),
            "complete_cpython_ast_source_ranges": positioned_ast,
            "libcst_nodes_with_positions": len(positions),
            "matching_identifier_positions": sum(ast_names.values()),
            "all_ast_names_in_real_libcst": True,
            "source_has_non_ascii": any(b >= 128 for b in raw),
            "native_cst_parser_version": PINNED_LIBCST}


def analyze_reviewed_multimodule(project_root, target_python, checker_python,
                                 mypy_pyright_tool_root, libcst_tool_root,
                                 python39_checker_tool_root=None):
    """Reconcile CPython AST, real native CST and two real typing engines."""
    path, sources = typecheck._project_sources(project_root)
    if len(sources) < 2:
        raise ValueError("two_reviewed_source_modules_required")
    interpreter = typecheck._actual_interpreter_minor(target_python)
    running_minor = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
    if interpreter != running_minor or interpreter not in SUPPORTED_MINORS:
        raise ValueError("libcst_and_ast_interpreter_must_match_target")
    libcst = _libcst_preflight(libcst_tool_root)
    models = {name: _inspect_source(name, raw, libcst) for name, raw in sources}
    oracle = typecheck.check_trusted_project(
        path, target_python, checker_python, mypy_pyright_tool_root,
        python39_tool_root=python39_checker_tool_root)
    if oracle["status"] == "TYPECHECKER_DISAGREEMENT_NOT_QUALIFIED":
        status = "STATIC_TYPE_ORACLES_DISAGREE_PARTIAL"
    else:
        status = ("CST_AST_AND_TWO_CHECKERS_AGREE_CLEAN" if
                  oracle["status"] == "TWO_REAL_CHECKERS_AGREE_CLEAN" else
                  "CST_AST_AND_TWO_CHECKERS_AGREE_ERRORS")
    return {"status": status, "python_minor": interpreter,
            "module_count": len(models), "source_models": models,
            "external_typecheck": oracle,
            "real_cst_parser_executed": True,
            "real_mypy_executed": oracle["mypy"]["external_checker_process_executed"],
            "real_pyright_executed": oracle["pyright"]["external_checker_process_executed"],
            "user_code_imported_or_executed": False,
            "os_sandbox_proven": False,
            "universal_dynamic_type_inference_proven": False,
            "arbitrary_source_roundtrip_proven": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "inspect"), default="capabilities")
    parser.add_argument("--project")
    parser.add_argument("--target-python")
    parser.add_argument("--checker-python")
    parser.add_argument("--typechecker-tools")
    parser.add_argument("--libcst-tools")
    parser.add_argument("--typechecker-tools39")
    args = parser.parse_args(argv)
    try:
        if args.mode == "capabilities":
            result = {"status": "AST_LIBCST_TYPE_ORACLE_ADAPTER_AVAILABLE",
                      "external_checks_executed": False,
                      "project_code_executed": False}
        else:
            result = analyze_reviewed_multimodule(
                args.project, args.target_python, args.checker_python,
                args.typechecker_tools, args.libcst_tools,
                python39_checker_tool_root=args.typechecker_tools39)
    except (ValueError, TypeError, OSError, RuntimeError, ImportError):
        result = {"status": "REFUSED_UNTRUSTED_OR_UNSUPPORTED_AST_CST_TYPING",
                  "external_checks_qualified": False, "project_code_executed": False}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 2 if result["status"].startswith("REFUSED") else 0


if __name__ == "__main__":
    raise SystemExit(main())
