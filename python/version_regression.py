"""Version-bound CPython AST, bytecode and traceback regression observations.

Only embedded, fixed, reviewed fixtures are compiled or executed. A target
project is never loaded, imported or executed. Baselines are local and unsigned:
a comparison PASS proves a match to those fixtures, not source authenticity.
"""

import argparse
import ast
from collections import Counter
import dis
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import stat
import sys
import traceback
import types


MAX_MANIFEST_BYTES = 32_768
VERSION = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
VERSION_KEY = re.compile(r"3\.(?:[9]|[1-9][0-9]+)\Z")
SYNTAX = {
    "pattern_matching": "match value:\n    case 0:\n        pass\n",
    "exception_groups": "try:\n    pass\nexcept* ValueError:\n    pass\n",
    "type_parameters": "type Item[T] = list[T]\n",
    "template_strings": "value = t'hello {name}'\n",
}
CODE_SAMPLES = {
    "branch": "def f(number):\n    if number > 0:\n        return number + 1\n    return -1\n",
    "exception": "def f():\n    try:\n        return 42\n    except ValueError:\n        return None\n",
    "comprehension": "def f(values):\n    return [n * 2 for n in values if n % 2]\n",
}


def checked_manifest(path):
    """No-follow, bounded, unique regular JSON input with duplicate-key refusal."""
    target = Path(path)
    try:
        if target.is_symlink():
            return None, "manifest_symlink_refused"
        descriptor = os.open(str(target), os.O_RDONLY |
                             getattr(os, "O_NOFOLLOW", 0) |
                             getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as handle:
            original = os.fstat(handle.fileno())
            if not stat.S_ISREG(original.st_mode) or original.st_nlink != 1:
                return None, "manifest_not_unique_regular_file"
            if original.st_size > MAX_MANIFEST_BYTES:
                return None, "manifest_size_limit"
            content = handle.read(MAX_MANIFEST_BYTES + 1)
            if len(content) > MAX_MANIFEST_BYTES:
                return None, "manifest_size_limit"
            fresh = os.fstat(handle.fileno())
            if (original.st_dev, original.st_ino, original.st_size, original.st_mtime_ns) != (
                    fresh.st_dev, fresh.st_ino, fresh.st_size, fresh.st_mtime_ns):
                return None, "manifest_changed_during_read"
    except OSError:
        return None, "manifest_unreadable"

    def unique_keys(pairs):
        record = {}
        for key, value in pairs:
            if key in record:
                raise ValueError("duplicate_manifest_key")
            record[key] = value
        return record

    try:
        parsed = json.loads(content.decode("utf-8"), object_pairs_hook=unique_keys)
    except (ValueError, UnicodeError, TypeError, RecursionError):
        return None, "invalid_manifest_json"
    if (not isinstance(parsed, dict) or type(parsed.get("schema_version")) is not int or
            parsed["schema_version"] != 1 or
            not isinstance(parsed.get("versions"), dict) or
            len(parsed["versions"]) > 30 or
            not all(isinstance(name, str) and VERSION_KEY.fullmatch(name) and
                        isinstance(row, dict) and
                        set(row) == {"ast", "bytecode", "traceback"} and
                        all(isinstance(row[section], dict) for section in row)
                        for name, row in parsed["versions"].items())):
        return None, "invalid_manifest_schema"
    profiles = parsed.get("runtime_profiles", [])
    exact_minors = parsed.get("require_exact_profile_for_minors", [])
    if (type(profiles) is not list or len(profiles) > 30 or
            type(exact_minors) is not list or len(exact_minors) > 30 or
            any(type(value) is not str or VERSION_KEY.fullmatch(value) is None for value in exact_minors) or
            len(set(exact_minors)) != len(exact_minors)):
        return None, "invalid_runtime_profile_schema"
    identities = set()
    for profile in profiles:
        if (type(profile) is not dict or set(profile) != {"id", "python_minor", "version", "releaselevel", "serial", "platform", "machine", "executable_sha256", "reference"} or
                type(profile["id"]) is not str or re.fullmatch(r"[a-zA-Z0-9_.-]{1,100}", profile["id"]) is None or
                profile["id"] in identities or type(profile["python_minor"]) is not str or VERSION_KEY.fullmatch(profile["python_minor"]) is None or
                type(profile["version"]) is not list or len(profile["version"]) != 3 or
                any(type(n) is not int or not 0 <= n <= 999 for n in profile["version"]) or
                profile["python_minor"] != "{}.{}".format(*profile["version"][:2]) or
                profile["releaselevel"] not in ("alpha", "beta", "candidate", "final") or
                type(profile["serial"]) is not int or not 0 <= profile["serial"] <= 999 or
                type(profile["platform"]) is not str or type(profile["machine"]) is not str or
                type(profile["executable_sha256"]) is not str or re.fullmatch(r"[a-f0-9]{64}", profile["executable_sha256"]) is None or
                type(profile["reference"]) is not dict or set(profile["reference"]) != {"ast", "bytecode", "traceback"} or
                any(type(section) is not dict for section in profile["reference"].values())):
            return None, "invalid_runtime_profile_schema"
        identities.add(profile["id"])
    return (parsed, hashlib.sha256(content).hexdigest()), None


def exact_runtime_reference(manifest):
    """Select only a named locally reviewed exact build; never learn a golden."""
    candidates = [row for row in manifest.get("runtime_profiles", [])
                  if row["python_minor"] == VERSION and
                  row["version"] == list(sys.version_info[:3]) and
                  row["releaselevel"] == sys.version_info.releaselevel and
                  row["serial"] == sys.version_info.serial and
                  row["platform"] == sys.platform and row["machine"] == platform.machine()]
    if not candidates:
        return None, None, "exact_runtime_reference_missing"
    try:
        executable = Path(sys.executable)
        with executable.open("rb") as stream:
            raw = stream.read(64 * 1024 * 1024 + 1)
        if not raw or len(raw) > 64 * 1024 * 1024:
            return None, None, "runtime_executable_identity_unavailable"
        fingerprint = hashlib.sha256(raw).hexdigest()
    except OSError:
        return None, None, "runtime_executable_identity_unavailable"
    matches = [row for row in candidates if row["executable_sha256"] == fingerprint]
    if len(matches) != 1:
        return None, None, "exact_runtime_reference_identity_mismatch_or_ambiguous"
    return matches[0]["reference"], matches[0]["id"], None


def ast_observation():
    """Store syntax acceptance and exact normalized AST shapes per CPython."""
    syntax = {}
    for name, source in SYNTAX.items():
        try:
            ast.parse(source, filename="<trusted-syntax-probe>")
        except SyntaxError:
            syntax[name] = False
        else:
            syntax[name] = True

    body = ast.parse(CODE_SAMPLES["branch"], filename="<trusted-ast-probe>")
    counts = Counter(type(node).__name__ for node in ast.walk(body))
    function = body.body[0]
    return {
        "syntax_acceptance": syntax,
        "node_counts": {name: counts[name] for name in sorted(counts)},
        "function_fields": list(function._fields),
        "ast_dump_sha256": hashlib.sha256(
            ast.dump(body, include_attributes=False).encode("utf-8")).hexdigest(),
    }


def bytecode_observation():
    """Compile only known constants; never execute resulting code objects."""
    cases = {}
    for name, source in CODE_SAMPLES.items():
        module = compile(source, "<trusted-bytecode-probe>", "exec")
        functions = [item for item in module.co_consts if isinstance(item, types.CodeType)]
        if len(functions) != 1:
            raise RuntimeError("trusted fixed fixture must contain one function")
        code = functions[0]
        nested = [item for item in code.co_consts if isinstance(item, types.CodeType)]
        cases[name] = {
            "module_ops": [item.opname for item in dis.get_instructions(module)],
            "function_ops": [item.opname for item in dis.get_instructions(code)],
            "inner_ops": [[item.opname for item in dis.get_instructions(inner)]
                          for inner in nested],
            "co_flags": code.co_flags,
            "co_varnames": list(code.co_varnames),
            "co_exceptiontable_bytes": len(getattr(code, "co_exceptiontable", b"")),
        }
    return cases


def traceback_observation():
    """Execute only a hardcoded safe exception fixture, no project code."""
    def regression_frame_inner():
        raise RuntimeError("known-fixed-regression-marker")

    def regression_frame_outer():
        regression_frame_inner()

    try:
        regression_frame_outer()
    except RuntimeError as failure:
        supports_notes = hasattr(failure, "add_note")
        if supports_notes:
            failure.add_note("fixed-regression-note")
        frames = traceback.extract_tb(failure.__traceback__)
        compact = [frame.name for frame in frames
                   if frame.name in ("regression_frame_inner", "regression_frame_outer")]
        exception_lines = traceback.format_exception_only(type(failure), failure)
        return {
            "exception": type(failure).__name__,
            "frames": compact,
            "exception_notes_supported": supports_notes,
            "exception_only": exception_lines,
        }
    raise AssertionError("trusted traceback probe failed to raise")


def observations():
    """Readable deterministic AST/bytecode/traceback fixture results."""
    return {"ast": ast_observation(), "bytecode": bytecode_observation(),
            "traceback": traceback_observation()}


def reference(observed):
    """Compact, readable but full-content-hashed golden reference."""
    def digest(value):
        return hashlib.sha256(json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":")).encode("utf-8")).hexdigest()
    return {
        "ast": {"sha256": digest(observed["ast"]),
                "syntax_acceptance": observed["ast"]["syntax_acceptance"],
                "function_fields": observed["ast"]["function_fields"]},
        "bytecode": {"sha256": digest(observed["bytecode"]),
                     "branch_ops": observed["bytecode"]["branch"]["function_ops"],
                     "exception_table_bytes": observed["bytecode"]["exception"][
                         "co_exceptiontable_bytes"]},
        "traceback": {"sha256": digest(observed["traceback"]),
                      "frames": observed["traceback"]["frames"],
                      "exception_notes_supported": observed["traceback"][
                          "exception_notes_supported"]},
    }


def inspect(path):
    """Compare one installed CPython minor with its pinned local reference."""
    envelope = {
        "schema_version": 1, "python_minor": VERSION,
        "python_implementation": sys.implementation.name,
        "untrusted_source_executed": False,
        "trusted_embedded_probes_executed": False,
        "project_code_loaded": False,
        "reference_authenticity": "UNSIGNED_NOT_VERIFIED",
        "full_python_compatibility": "NOT_VERIFIED",
    }
    if sys.implementation.name != "cpython" or sys.version_info.major != 3:
        return dict(envelope, status="NOT_RUN", reason="not_cpython_3")
    manifest_data, failure = checked_manifest(path)
    if failure:
        return dict(envelope, status="NOT_RUN", reason=failure)
    manifest, fingerprint = manifest_data
    envelope["manifest_sha256"] = fingerprint
    expected = manifest["versions"].get(VERSION)
    if VERSION in manifest.get("require_exact_profile_for_minors", []):
        expected, profile_id, failure = exact_runtime_reference(manifest)
        if failure:
            return dict(envelope, status="NOT_RUN", reason=failure)
        envelope["runtime_reference_profile"] = profile_id
        envelope["runtime_reference_authentication"] = "LOCAL_UNSIGNED_BUILD_IDENTITY_ONLY"
    if expected is None:
        return dict(envelope, status="NOT_RUN", reason="missing_version_baseline")
    actual = reference(observations())
    envelope["trusted_embedded_probes_executed"] = True
    differences = {section: actual[section] == expected[section]
                   for section in ("ast", "bytecode", "traceback")}
    return dict(envelope,
                status="BASELINE_MATCH" if all(differences.values()) else "REGRESSION",
                checks=differences,
                baselines_compared=3,
                baselines_matching=sum(differences.values()),
                note="Fixed-fixture regression only; baseline unsigned and no external package or project tested")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--manifest")
    mode.add_argument("--candidate", action="store_true")
    args = parser.parse_args()
    if args.candidate:
        report = {"status": "CANDIDATE_UNVERIFIED", "python_minor": VERSION,
                  "reference": reference(observations()), "project_code_loaded": False,
                  "untrusted_source_executed": False,
                  "trusted_embedded_probes_executed": True}
    elif args.manifest:
        report = inspect(args.manifest)
    print(json.dumps(report, sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    main()
