"""F029/F030/F093/F193 conservative migration and *trusted-only* promotion.

Arbitrary input source is never executed. Only two fixed, hardcoded trusted
functions and four fixed mutants are compiled/executed for finite regression
evidence. Coverage and equivalence on this fixture do not prove correctness
for unrelated projects. Ruff is linting, explicitly NOT mypy/Pyright typing.
"""

import ast
import dis
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tokenize


MAX_SOURCE_BYTES = 1_000_000
MAX_TOKENS = 12000
_MIGRATABLE = frozenset(("Mapping", "MutableMapping", "Sequence", "MutableSequence",
                         "Set", "MutableSet", "Iterable", "Iterator", "Callable",
                         "Container", "Collection"))
_FROM_COLLECTIONS = re.compile(r"(?m)^(\s*from[ \t]+)collections([ \t]+import[ \t]+)")
RUFF_TOOL = Path("/workspace/scratch/9961e39ca0a6/.uv-bin/ruff")
_TRUSTED_RUFF_TARGET = Path("/workspace/scratch/9961e39ca0a6/.uv-tools/ruff/bin/ruff")
# Existing project-local Ruff wheel identity, from its installed RECORD.
# This pin authenticates the selected local tool bytes, not its publisher.
_TRUSTED_WINDOWS_RUFF_SHA256 = "0e71094b51a4241cb725e76e6375c55c8433dd06ec380ab987c970edd1618565"
if os.name == "nt":
    RUFF_TOOL = Path(__file__).resolve().parents[2] / "ruff-tools/bin/ruff.exe"
    _TRUSTED_RUFF_TARGET = RUFF_TOOL



def _parser(source):
    if not isinstance(source, str):
        return None
    try:
        if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
            return None
        return ast.parse(source)
    except (SyntaxError, UnicodeError, ValueError, TypeError, RecursionError):
        return None


def _token_pairs(text):
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
        if len(tokens) > MAX_TOKENS:
            return None
        return [(item.type, item.string) for item in tokens]
    except (tokenize.TokenError, SyntaxError, IndentationError, UnicodeError):
        return None


def independently_validate_collections_migration(original, repaired):
    """Validate one API import migration using a separate token/AST oracle."""
    base = {"valid": False, "user_code_executed": False,
            "semantics_equivalent_proven": False}
    old_ast = _parser(original)
    new_ast = _parser(repaired)
    if old_ast is None or new_ast is None:
        return {**base, "reason": "parse_failed"}
    before = [node for node in ast.walk(old_ast) if isinstance(node, ast.ImportFrom)]
    after = [node for node in ast.walk(new_ast) if isinstance(node, ast.ImportFrom)]
    if len(before) != len(after):
        return {**base, "reason": "import_tree_shape_changed"}
    differences = []
    for old, new in zip(before, after):
        if old.module != new.module:
            differences.append((old, new))
    if len(differences) != 1:
        return {**base, "reason": "not_one_selected_api_migration"}
    old, new = differences[0]
    if (old.module != "collections" or new.module != "collections.abc"
            or old.level != 0 or new.level != 0 or len(old.names) != 1
            or old.names[0].name not in _MIGRATABLE
            or [(alias.name, alias.asname) for alias in old.names]
            != [(alias.name, alias.asname) for alias in new.names]):
        return {**base, "reason": "unsupported_import_migration"}
    # Independent AST structural oracle: changing exactly the module path is
    # the only permitted tree change. Attributes/positions are ignored.
    new.module = "collections"
    if ast.dump(old_ast, include_attributes=False) != ast.dump(new_ast, include_attributes=False):
        return {**base, "reason": "additional_ast_changes_detected"}
    a = _token_pairs(original)
    b = _token_pairs(repaired)
    if a is None or b is None or len(b) != len(a) + 2:
        return {**base, "reason": "token_stream_mismatch"}
    insertion = [(tokenize.OP, "."), (tokenize.NAME, "abc")]
    if not any(b[:index] + b[index + 2:] == a and b[index:index + 2] == insertion
               for index in range(len(b) - 1)):
        return {**base, "reason": "token_stream_mismatch"}
    # No comments, whitespace, or encodings changed: only one 4-character
    # insertion following a pre-existing 'collections'.
    if len(repaired) != len(original) + 4:
        return {**base, "reason": "not_exact_insert"}
    if not any(repaired[:index] + repaired[index + 4:] == original
               and repaired[index:index + 4] == ".abc"
               for index in range(len(repaired) - 3)):
        return {**base, "reason": "not_exact_insert"}
    return {**base, "valid": True, "reason": "AST_AND_TOKEN_ORACLES_AGREE",
            "comments_and_format_preserved": True}


def migrate_collections_abc(source):
    """One exact AST-targeted stdlib API import change, with independent gate."""
    base = {"status": "NO_PATCH", "source_executed": False,
            "behavior_equivalence_proven": False}
    tree = _parser(source)
    if tree is None:
        return {**base, "reason": "invalid_source_or_encoding"}
    imports = [node for node in ast.walk(tree)
               if isinstance(node, ast.ImportFrom) and node.module == "collections"
               and node.level == 0 and len(node.names) == 1
               and node.names[0].name in _MIGRATABLE]
    if len(imports) != 1:
        return {**base, "reason": "no_unique_supported_import"}
    node = imports[0]
    if node.lineno != getattr(node, "end_lineno", None):
        return {**base, "reason": "multiline_import_not_supported"}
    lines = source.splitlines(keepends=True)
    if not 1 <= node.lineno <= len(lines):
        return {**base, "reason": "import_line_not_found"}
    line = lines[node.lineno - 1]
    match = _FROM_COLLECTIONS.match(line)
    if match is None or not line[match.end():].lstrip().startswith(node.names[0].name):
        return {**base, "reason": "unsupported_import_format"}
    changed = match.group(1) + "collections.abc" + match.group(2) + line[match.end():]
    candidate = list(lines)
    candidate[node.lineno - 1] = changed
    repaired = "".join(candidate)
    independent = independently_validate_collections_migration(source, repaired)
    if not independent["valid"]:
        return {**base, "reason": independent["reason"]}
    return {**base, "status": "SINGLE_STDLIB_API_IMPORT_MIGRATED",
            "candidate": repaired, "line": node.lineno,
            "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "candidate_sha256": hashlib.sha256(repaired.encode("utf-8")).hexdigest(),
            "independent_validation": independent}


def _trusted_fixture_pair():
    original = (
        "def classify(n, branch):\n"
        "    if branch('negative', n < 0):\n"
        "        return 'negative'\n"
        "    if branch('zero', n == 0):\n"
        "        return 'zero'\n"
        "    return 'positive'\n"
    )
    # Deliberately real syntactic diff with the same return semantics.
    repaired = original.replace("    if branch('zero', n == 0):",
                                "    elif branch('zero', n == 0):")
    regression = repaired.replace("return 'zero'", "return 'positive'")
    return original, repaired, regression


def _fixed_mutations(source):
    return (
        source.replace("n < 0", "n <= 0"),
        source.replace("n == 0", "n != 0"),
        source.replace("\n        return 'negative'\n", "\n        return 'incorrect_negative'\n"),
        source.replace("\n    return 'positive'\n", "\n    return 'incorrect_positive'\n"),
    )


def _compile_trusted_fixture(source):
    original, repaired, regressive = _trusted_fixture_pair()
    trusted = {original, repaired, regressive}
    for fixed in (original, repaired, regressive):
        trusted.update(_fixed_mutations(fixed))
    if type(source) is not str or source not in trusted:
        raise ValueError("untrusted_python_source_execution_refused")
    scope = {"__builtins__": {}}
    exec(compile(source, "<fixed-trusted-f193-diff>", "exec", dont_inherit=True), scope)
    return scope["classify"]


def _fixture_expected(value):
    if value < 0:
        return "negative"
    if value == 0:
        return "zero"
    return "positive"


def _covered_fixture(source):
    function = _compile_trusted_fixture(source)
    touched_lines = set()
    branches = set()

    def branch(name, result):
        branches.add((name, bool(result)))
        return result

    def tracer(frame, event, arg):
        if (frame.f_code.co_filename == "<fixed-trusted-f193-diff>"
                and frame.f_code.co_name == "classify" and event == "line"):
            touched_lines.add(frame.f_lineno)
        return tracer

    previous_trace = sys.gettrace()
    try:
        sys.settrace(tracer)
        inputs = (-3, 0, 6)
        outputs = [function(value, branch) for value in inputs]
    finally:
        sys.settrace(previous_trace)
    possible_lines = {line for _, line in dis.findlinestarts(function.__code__)
                      if line > function.__code__.co_firstlineno}
    expected_branches = {(name, outcome) for name in ("negative", "zero")
                         for outcome in (False, True)}
    return {"line_covered": len(possible_lines.intersection(touched_lines)),
            "line_total": len(possible_lines),
            "branch_covered": len(expected_branches.intersection(branches)),
            "branch_total": len(expected_branches),
            "results": outputs, "tracer_restored": sys.gettrace() is previous_trace}


def _mutation_score(source):
    """Four fixed mutation operators, compared with independent expected outputs."""
    mutations = _fixed_mutations(source)
    if len(set(mutations)) != 4 or source in mutations:
        return None
    inputs = (-3, 0, 6)
    killed = 0
    for variant in mutations:
        tested = _compile_trusted_fixture(variant)
        if any(tested(value, lambda _label, outcome: outcome) != _fixture_expected(value)
               for value in inputs):
            killed += 1
    return {"killed": killed, "total": len(mutations)}


def assess_fixed_repair_promotion(case="equivalent"):
    """Actual before/after coverage and behavior gate for ONLY fixed snippets."""
    base = {"status": "NOT_PROMOTED", "arbitrary_user_source_executed": False,
            "full_behavior_equivalence_proven": False,
            "fixture_specific_proof_only": True, "network_used": False}
    if case not in ("equivalent", "regressive"):
        return {**base, "reason": "only_hardcoded_fixture_cases_supported"}
    original, repaired, regressive = _trusted_fixture_pair()
    candidate = repaired if case == "equivalent" else regressive
    before = _covered_fixture(original)
    after = _covered_fixture(candidate)
    before_mutants = _mutation_score(original)
    after_mutants = _mutation_score(candidate)
    if before_mutants is None or after_mutants is None:
        return {**base, "reason": "trusted_fixture_mutation_invalid"}
    equivalent_outputs = before["results"] == after["results"]
    reference_outputs = [_fixture_expected(v) for v in (-3, 0, 6)]
    trusted_tests_passed = after["results"] == reference_outputs
    all_cover = all(coverage["line_total"] and coverage["line_covered"] == coverage["line_total"]
                    and coverage["branch_covered"] == coverage["branch_total"]
                    for coverage in (before, after))
    all_mutants_killed = all(score["killed"] == score["total"] for score in
                             (before_mutants, after_mutants))
    promotable = equivalent_outputs and trusted_tests_passed and all_cover and all_mutants_killed
    return {**base, "status": "PROMOTED_ONLY_FOR_TRUSTED_FIXTURE" if promotable else
            "BLOCKED_BY_TRUSTED_FIXTURE_GATE",
            "original_sha256": hashlib.sha256(original.encode()).hexdigest(),
            "repaired_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
            "sources_differ": original != candidate,
            "original": {key: value for key, value in before.items() if key != "results"},
            "repaired": {key: value for key, value in after.items() if key != "results"},
            "original_mutation": before_mutants, "repaired_mutation": after_mutants,
            "behavior_equivalent_on_fixed_inputs": equivalent_outputs,
            "independent_expected_results_passed": trusted_tests_passed,
            "promotion_gate_passed": promotable}


def inspect_offline_typecheckers():
    """Only a capability check: Ruff must never be presented as mypy/Pyright."""
    base = {"status": "NOT_RUN_TYPECHECKERS_UNAVAILABLE",
            "mypy_typecheck_verified": False, "pyright_typecheck_verified": False,
            "ruff_is_typechecker": False, "network_used": False,
            "user_project_source_executed": False,
            "dependencies_installed": False}
    base["mypy_available"] = bool(shutil.which("mypy"))
    base["pyright_available"] = bool(shutil.which("pyright"))
    if base["mypy_available"] or base["pyright_available"]:
        # Availability is not proof that a real type-check completed.
        base["status"] = "NOT_RUN_TYPECHECKERS_NOT_EXECUTED"
    # Ruff lint is a real, separate offline check on a fixed trusted fixture,
    # not evidence of type inference or generic source safety.
    try:
        executable = RUFF_TOOL.resolve(strict=True)
        if executable != _TRUSTED_RUFF_TARGET or not stat.S_ISREG(executable.stat().st_mode):
            return {**base, "ruff_lint": "NOT_RUN"}
        if os.name == "nt" and hashlib.sha256(executable.read_bytes()).hexdigest() != _TRUSTED_WINDOWS_RUFF_SHA256:
            return {**base, "ruff_lint": "NOT_RUN"}
        source = "def answer() -> int:\n    return 42\n"
        run = subprocess.run([str(executable), "check", "--isolated", "--stdin-filename",
                              "trusted_fixture.py", "-"], input=source, text=True,
                             capture_output=True, timeout=10, check=False)
        base["ruff_lint"] = "TRUSTED_FIXTURE_PASS" if run.returncode == 0 else "TRUSTED_FIXTURE_FAIL"
    except (OSError, subprocess.TimeoutExpired, ValueError):
        base["ruff_lint"] = "NOT_RUN"
    return base
