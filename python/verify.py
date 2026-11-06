"""Compile a Python file without executing its code. Run by Rust using -I -S."""

import json
import pathlib
import sys
import tokenize


def compile_audit_counts():
    """Observe audit event *names* only; this is not a security sandbox."""
    counts = {"open": 0, "compile": 0, "exec": 0}

    def observer(event, _args):
        if event in counts:
            counts[event] += 1

    sys.addaudithook(observer)
    return counts


def main():
    path = pathlib.Path(sys.argv[1])
    audit = compile_audit_counts()
    try:
        # Respect PEP 263 encoding declarations; neither import nor run the module.
        with tokenize.open(path) as handle:
            source = handle.read()
        compile(source, str(path), "exec", dont_inherit=True)
    except (SyntaxError, UnicodeError, ValueError, OSError) as exc:
        result = {
            "compile": "FAIL",
            "error_type": type(exc).__name__,
            # Some Python exception strings contain source literals, absolute
            # paths or user data. Keep the structured location and type only.
            "message": "Diagnostic details withheld for privacy",
            "line": getattr(exc, "lineno", None),
            "column": getattr(exc, "offset", None),
        }
    else:
        result = {"compile": "PASS", "error_type": None, "message": None,
                  "line": None, "column": None}
    result["audit_observation"] = {
        "events": audit, "arguments_collected": False,
        "security_boundary": False, "scope": "compile_only_helper",
    }
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()

