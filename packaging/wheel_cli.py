"""Python wheel CLI: explicit, bounded entry points into shipped helpers."""

import argparse
import json


def main(argv=None):
    parser = argparse.ArgumentParser(prog="rph-python")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="List packaged helper names without importing them")
    abi = sub.add_parser("abi-tags", help="Read-only CPython wheel-tag compatibility")
    abi.add_argument("--wheel", required=True)
    static = sub.add_parser("static", help="Read-only Python AST source diagnostics")
    static.add_argument("--file", required=True)
    args = parser.parse_args(argv)
    if args.command == "list":
        from rust_python_healer_helpers import HELPER_MODULES
        output = {"status": "PACKAGED_HELPERS", "helpers": HELPER_MODULES,
                  "user_code_executed": False, "network_used": False}
    elif args.command == "abi-tags":
        from rust_python_healer_helpers.abi_tags import compare_wheel
        output = compare_wheel(args.wheel)
    else:
        from rust_python_healer_helpers.static_quality import analyze_file
        output = analyze_file(args.file)
    print(json.dumps(output, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
