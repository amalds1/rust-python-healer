"""Bounded offline knowledge expansion with explicit evidence limitations.

Native stdlib probing executes only a literal script importing an allowlisted
set of trusted interpreter modules in -I -S -B. Stub/API parsing uses AST only.
Semantic-quality validation consumes externally declared model vectors; it is
not a local semantic embedding model, provenance attestation or model trainer.
"""

import ast
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from urllib.parse import urlsplit


MAX_SOURCE = 512 * 1024
MAX_SYMBOLS = 512
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
PY_MINOR = re.compile(r"3\.(?:9|1[0-9]|[2-9][0-9])\Z")
MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z")
NATIVE_MODULES = ("math", "itertools", "collections", "json", "sys")


_NATIVE_PROBE = r'''
import inspect
import json
import sys
from importlib import import_module

WHITELIST = {
 "math": ("sin", "cos", "sqrt", "isfinite"),
 "itertools": ("chain", "repeat", "count", "product"),
 "collections": ("deque", "defaultdict", "Counter"),
 "json": ("dumps", "loads", "JSONDecoder"),
 "sys": ("getsizeof", "getrefcount", "intern"),
}
rows = []
for module_name, names in WHITELIST.items():
    module = import_module(module_name)
    for symbol in names:
        try:
            value = inspect.getattr_static(module, symbol)
            try:
                signature = str(inspect.signature(value))
            except (TypeError, ValueError):
                signature = None
            rows.append({"module": module_name, "symbol": symbol,
                         "type_name": type(value).__name__,
                         "callable": callable(value),
                         "signature": signature,
                         "origin": "TRUSTED_STDLIB_RUNTIME_SELECTED_SYMBOL"})
        except AttributeError:
            rows.append({"module": module_name, "symbol": symbol,
                         "missing": True, "origin": "TRUSTED_RUNTIME_ABSENT"})
print(json.dumps({"python_minor": "%s.%s" % sys.version_info[:2],
                  "rows": rows}, sort_keys=True))
'''


def native_stdlib_probe(timeout=8.0):
    """Restricted fixed official interpreter probe, no file or user imports."""
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 1 <= timeout <= 30:
        raise ValueError("invalid_native_probe_timeout")
    completed = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", _NATIVE_PROBE],
                               input=b"", capture_output=True, timeout=timeout,
                               check=True)
    if len(completed.stdout) > 64 * 1024 or completed.stderr:
        raise ValueError("native_probe_output_invalid")
    output = json.loads(completed.stdout)
    if (output.get("python_minor") != "{}.{}".format(*sys.version_info[:2]) or
            not isinstance(output.get("rows"), list) or
            len(output["rows"]) > 64):
        raise ValueError("native_probe_version_or_scope_mismatch")
    return {"status": "SELECTED_TRUSTED_RUNTIME_APIS_OBSERVED",
            "python_minor": output["python_minor"], "symbols": output["rows"],
            "observed": len(output["rows"]),
            "all_stdlib_apis_covered": False,
            "third_party_code_executed": False,
            "arbitrary_module_imports_allowed": False}


def _read_unique(path, extension):
    source = Path(path)
    if source.suffix != extension or source.is_symlink():
        raise ValueError("invalid_static_source_extension_or_symlink")
    fd = os.open(str(source), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_SOURCE:
            raise ValueError("static_source_not_unique_bounded_file")
        with os.fdopen(fd, "rb") as handle:
            fd = None
            data = handle.read(MAX_SOURCE + 1)
            after = os.fstat(handle.fileno())
        if (len(data) > MAX_SOURCE or (info.st_size, info.st_mtime_ns, info.st_ino) !=
                (after.st_size, after.st_mtime_ns, after.st_ino)):
            raise ValueError("static_source_modified")
        return data
    finally:
        if fd is not None:
            os.close(fd)


def _shape(node):
    args = node.args
    pos = list(args.posonlyargs) + list(args.args)
    required = len(pos) - len(args.defaults)
    return (len(args.posonlyargs), len(args.args), required,
            tuple(arg.arg for arg in args.kwonlyargs),
            tuple(x is None for x in args.kw_defaults),
            args.vararg is not None, args.kwarg is not None,
            isinstance(node, ast.AsyncFunctionDef))


def _declarations(source):
    try:
        tree = ast.parse(source.decode("utf-8-sig"), mode="exec")
    except (UnicodeError, SyntaxError, ValueError) as exc:
        raise ValueError("static_ast_parse_failed") from exc
    if sum(1 for _ in ast.walk(tree)) > 25_000:
        raise ValueError("too_many_static_ast_nodes")
    result = {}
    repeated = set()
    def visit(body, parent=""):
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit(node.body, parent + node.name + ".")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified = parent + node.name
                if qualified in result:
                    repeated.add(qualified)
                result[qualified] = {"qualified_name": qualified,
                                     "signature_shape": _shape(node),
                                     "line": node.lineno}
    visit(tree.body)
    # Multiple @overload or conditional definitions are ambiguous source
    # candidates: no silent last-definition-wins rename conclusions.
    for name in repeated:
        result.pop(name, None)
    if len(result) > MAX_SYMBOLS:
        raise ValueError("too_many_declarations")
    return result


def correlate_stub_renames(stub_path, implementation_path):
    """Static .pyi/.py rename candidates, never assert verified runtime rename."""
    stub = _read_unique(stub_path, ".pyi")
    implementation = _read_unique(implementation_path, ".py")
    stubs, impls = _declarations(stub), _declarations(implementation)
    unchanged = sorted(set(stubs) & set(impls))
    unmatched_stub = sorted(set(stubs) - set(impls))
    unmatched_impl = sorted(set(impls) - set(stubs))
    candidates = []
    for old in unmatched_stub:
        corresponding = [new for new in unmatched_impl
                         if stubs[old]["signature_shape"] == impls[new]["signature_shape"]
                         and old.rpartition(".")[0] == new.rpartition(".")[0]]
        if len(corresponding) == 1:
            candidates.append({"stub_symbol": old,
                               "implementation_symbol": corresponding[0],
                               "confidence": "POSSIBLE_RENAME_SHAPE_ONLY_NOT_VERIFIED"})
    reverse_counts = {}
    for candidate in candidates:
        name = candidate["implementation_symbol"]
        reverse_counts[name] = reverse_counts.get(name, 0) + 1
    candidates = [candidate for candidate in candidates
                  if reverse_counts[candidate["implementation_symbol"]] == 1]
    return {"status": "STATIC_SIGNATURE_CORRELATION_NOT_RUNTIME_RENAME_PROOF",
            "stub_sha256": hashlib.sha256(stub).hexdigest(),
            "implementation_sha256": hashlib.sha256(implementation).hexdigest(),
            "same_name_symbols": unchanged, "possible_renames": candidates,
            "ambiguous_or_missing_stub_symbols": [key for key in unmatched_stub
               if key not in {item["stub_symbol"] for item in candidates}],
            "source_executed": False,
            "runtime_renames_verified": False,
            "annotations_evaluated": False}


def _vector(values):
    if (not isinstance(values, (list, tuple)) or not 2 <= len(values) <= 1024 or
            any(type(x) not in (float, int) or not math.isfinite(x) for x in values)):
        raise ValueError("invalid_quality_vector")
    numbers = tuple(float(x) for x in values)
    norm = math.sqrt(math.fsum(x * x for x in numbers))
    if not 0 < norm < float("inf"):
        raise ValueError("invalid_quality_vector_norm")
    return numbers, norm


def validate_declared_semantic_quality(model_id, model_sha256, model_uri,
                                      documents, questions, top_k=3):
    """Objective retrieval recall@k; declared model is NOT independently trusted."""
    if not isinstance(model_id, str) or not MODEL.fullmatch(model_id):
        raise ValueError("invalid_quality_model_id")
    if not isinstance(model_sha256, str) or not HEX64.fullmatch(model_sha256):
        raise ValueError("invalid_quality_model_sha256")
    parsed = urlsplit(model_uri)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
            parsed.password or parsed.query or parsed.fragment):
        raise ValueError("invalid_quality_model_uri")
    if (type(top_k) is not int or not 1 <= top_k <= 10 or
            not isinstance(documents, list) or not 2 <= len(documents) <= 2000 or
            not isinstance(questions, list) or not 1 <= len(questions) <= 100):
        raise ValueError("invalid_quality_dataset")
    index = {}
    dimension = None
    for doc in documents:
        if type(doc) is not dict or type(doc.get("id")) is not str or not doc["id"]:
            raise ValueError("invalid_quality_document")
        coords, length = _vector(doc.get("vector"))
        dimension = dimension or len(coords)
        if len(coords) != dimension or doc["id"] in index:
            raise ValueError("duplicate_or_mismatched_quality_document")
        index[doc["id"]] = (coords, length)
    hits = 0
    rr = 0.0
    for question in questions:
        if type(question) is not dict:
            raise ValueError("invalid_quality_question")
        coords, norm = _vector(question.get("vector"))
        expected = question.get("relevant")
        if (len(coords) != dimension or type(expected) is not list or not expected or
                any(type(doc_id) is not str or doc_id not in index for doc_id in expected)):
            raise ValueError("invalid_quality_relevance_labels")
        ranked = sorted(index, key=lambda doc_id: (
            -math.fsum(x * y for x, y in zip(coords, index[doc_id][0])) /
            (norm * index[doc_id][1]), doc_id))
        matching = [idx + 1 for idx, doc_id in enumerate(ranked)
                    if doc_id in set(expected)]
        if matching and min(matching) <= top_k:
            hits += 1
        if matching:
            rr += 1.0 / min(matching)
    return {"status": "DECLARED_EMBEDDING_RETRIEVAL_QUALITY_MEASURED_NOT_MODEL_ATTESTED",
            "model_id": model_id, "model_sha256": model_sha256,
            "model_uri": model_uri, "questions": len(questions),
            "recall_at_k": hits / len(questions), "k": top_k,
            "mean_reciprocal_rank": rr / len(questions),
            "model_binary_loaded": False,
            "declared_model_publisher_verified": False,
            "embedding_generated_locally": False, "source_executed": False}


def generate_future_testschema(target_minor, observed_minor, known_features):
    """Draft new-version test matrix; never claim future grammar was tested."""
    if (not isinstance(target_minor, str) or not PY_MINOR.fullmatch(target_minor) or
            not isinstance(observed_minor, str) or not PY_MINOR.fullmatch(observed_minor)):
        raise ValueError("invalid_testschema_python_version")
    if (type(known_features) is not list or len(known_features) > 100 or
            any(type(value) is not str or not MODEL.fullmatch(value)
                for value in known_features)):
        raise ValueError("invalid_testschema_features")
    if len(set(known_features)) != len(known_features):
        raise ValueError("duplicate_testschema_features")
    return {"status": "FUTURE_VERSION_TESTSCHEMA_DRAFT_NOT_EXECUTED",
            "schema_version": 1, "target_python_minor": target_minor,
            "observed_runner_minor": observed_minor,
            "runner_same_version": target_minor == observed_minor,
            "required_suites": ["compile", "ast", "stdlib", "packages",
                                "patch", "updater", "regression", "security"],
            "known_feature_ids": known_features,
            "future_grammar_auto_learned": False,
            "tests_executed": False, "new_interpreter_authenticated": False}


def pep_official_sync_gate(snapshot, independent_publisher_authentication=False):
    """Official PEP ingestion must fail closed without publisher attestation."""
    if independent_publisher_authentication is not True:
        return {"status": "AUTHENTICATED_OFFICIAL_SOURCE_REQUIRED",
                "automatic_pep_sync": False,
                "publisher_verified": False,
                "status_index_verified": False}
    # No pinned PEP authority key or verification chain is configured here.
    # A boolean claim from a caller is never equivalent to real attestation.
    raise ValueError("official_pep_publisher_authentication_not_configured")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("native-probe")
    stub = actions.add_parser("correlate-stub")
    stub.add_argument("--pyi", type=Path, required=True)
    stub.add_argument("--py", type=Path, required=True)
    future = actions.add_parser("future-schema")
    future.add_argument("--target", required=True)
    future.add_argument("--observed", required=True)
    future.add_argument("--features-json", default="[]")
    actions.add_parser("pep-source-gate")
    args = parser.parse_args()
    if args.action == "native-probe":
        report = native_stdlib_probe()
    elif args.action == "correlate-stub":
        report = correlate_stub_renames(args.pyi, args.py)
    elif args.action == "future-schema":
        report = generate_future_testschema(args.target, args.observed,
                                            json.loads(args.features_json))
    else:
        report = pep_official_sync_gate({})
    print(json.dumps(report, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
