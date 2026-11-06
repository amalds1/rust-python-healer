"""Audit documented feature IDs and every source-code function declaration.

Reads code without importing it or invoking the debugger. The committed
symbol snapshot is deliberate: a new implementation function must be reviewed
and added to the register instead of silently disappearing from the checklist.
"""

import argparse
import ast
from collections import Counter
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SYMBOL_SNAPSHOT = ROOT / "config" / "code_symbol_inventory.json"
CHECKLIST = ROOT / "docs" / "FUNCTION_CHECKLIST.md"
RUST_FUNCTION = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:(?:async|unsafe|const)\s+)*(?:extern\s+\"[^\"\r\n]+\"\s+)?fn\s+"
    r"([A-Za-z_][A-Za-z_0-9]*)\s*(?:<[^\r\n{};]*>)?\s*\(", re.MULTILINE
)
ITEM = re.compile(
    r"^- \[([ x])\] (F\d{3}) (.+?) — "
    r"(IMPLEMENTED_TESTED|PARTIAL|NOT_IMPLEMENTED|BLOCKED|NOT_RUN)\s*$"
)


def discover_cli_commands(root=ROOT):
    source = (root / "src" / "main.rs").read_text(encoding="utf-8")
    commands = {}
    for enum_name in ("Commands", "CatalogCommands"):
        enum_match = re.search(
            r"^enum " + enum_name + r" \{(.*?)^\}", source, flags=re.MULTILINE | re.DOTALL
        )
        if enum_match is None:
            raise ValueError("ontbrekende CLI-enum: " + enum_name)
        values = re.findall(r"^    ([A-Z][A-Za-z0-9_]*)\s*(?:\{|,)",
                            enum_match.group(1), flags=re.MULTILINE)
        if not values or len(values) != len(set(values)):
            raise ValueError("ongeldige CLI-commandodeclaraties: " + enum_name)
        commands[enum_name] = sorted(values)
    return commands


def python_names(source):
    tree = ast.parse(source)
    names = []

    def walk(node, parents):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qualified = parents + [child.name]
                if not isinstance(child, ast.ClassDef):
                    names.append(".".join(qualified))
                walk(child, qualified)
            else:
                walk(child, parents)

    walk(tree, [])
    return sorted(names)


def rust_names(source):
    names = []
    for match in RUST_FUNCTION.finditer(source):
        name = match.group(1)
        if name == "drop":
            # Different RAII destructors are distinct trait methods. Require
            # the actual immediately enclosing Drop impl; never waive a
            # duplicate merely because it has a common method name.
            owner = re.search(r"(?m)^impl\s+Drop\s+for\s+([A-Za-z_][A-Za-z_0-9]*)\s*\{\s*\Z",
                              source[:match.start()])
            if owner:
                name = "Drop<" + owner.group(1) + ">.drop"
        names.append(name)
    if len(names) != len(set(names)):
        raise ValueError("dubbele Rust-functie-identiteit")
    return sorted(names)


def discover(root=ROOT):
    paths = []
    for folder, extension in (("src", "*.rs"), ("python", "*.py"),
                              ("tools", "*.py"), ("tests", "*.py"),
                              ("tests", "*.rs"), ("windows_qa/src", "*.rs"),
                              ("tests/support", "*.rs"),
                              ("windows_qa", "*.py"),
                              ("windows_qa/tests", "*.py")):
        paths.extend((root / folder).glob(extension))
    result = {}
    for path in sorted(paths):
        relative = path.relative_to(root).as_posix()
        content = path.read_text(encoding="utf-8")
        if path.suffix == ".py":
            names = python_names(content)
        else:
            names = rust_names(content)
        if len(names) != len(set(names)):
            raise ValueError("dubbele functie-identiteit in " + relative)
        result[relative] = names
    return result


def parse_checklist(text):
    items = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not (line.startswith("- [x] ") or line.startswith("- [ ] ")):
            continue
        match = ITEM.fullmatch(line)
        if not match:
            raise ValueError("ongeldige checklistregel: " + line[:160])
        checked, feature_id, title, status = match.groups()
        if not title.strip():
            raise ValueError("lege functietitel")
        if (checked == "x") != (status == "IMPLEMENTED_TESTED"):
            raise ValueError("checkbox en status spreken elkaar tegen: " + feature_id)
        next_line = lines[index + 1] if index + 1 < len(lines) else ""
        has_reason = next_line.startswith("  - Reden: ")
        if status != "IMPLEMENTED_TESTED" and not has_reason:
            raise ValueError("open functie heeft geen reden: " + feature_id)
        if status == "IMPLEMENTED_TESTED" and has_reason:
            raise ValueError("afgevinkte functie mag geen openstaande reden hebben: " + feature_id)
        reason = next_line.removeprefix("  - Reden: ").strip() if has_reason else None
        if has_reason and (not reason or len(reason) < 25):
            raise ValueError("te korte of lege openstaande reden: " + feature_id)
        items.append({"id": feature_id, "status": status, "title": title,
                      "reason": reason})
    expected_ids = ["F{:03d}".format(i) for i in range(1, len(items) + 1)]
    if [x["id"] for x in items] != expected_ids:
        raise ValueError("functienummers zijn niet uniek, oplopend en aaneengesloten")
    if len(items) < 80:
        raise ValueError("onvolledige functielijst: minder dan 80 items")
    return items


def compare(actual, snapshot):
    missing = []
    stale = []
    for path in sorted(set(actual) | set(snapshot)):
        new = set(actual.get(path, [])) - set(snapshot.get(path, []))
        removed = set(snapshot.get(path, [])) - set(actual.get(path, []))
        missing.extend(path + "::" + name for name in sorted(new))
        stale.extend(path + "::" + name for name in sorted(removed))
    return missing, stale


def audit(root=ROOT):
    symbols = discover(root)
    saved = json.loads((root / "config" / "code_symbol_inventory.json").read_text(encoding="utf-8"))
    if saved.get("schema_version") != 1:
        raise ValueError("onbekende code-inventarisversie")
    missing, stale = compare(symbols, saved["symbols"])
    current_commands = discover_cli_commands(root)
    missing_commands, stale_commands = compare(current_commands, saved["cli_commands"])
    items = parse_checklist((root / "docs" / "FUNCTION_CHECKLIST.md").read_text(encoding="utf-8"))
    counts = dict(sorted(Counter(x["status"] for x in items).items()))
    return {"status": "PASS" if not missing and not stale and
            not missing_commands and not stale_commands else "FAIL",
            "features": len(items), "open_reasons": sum(x["reason"] is not None for x in items),
            "feature_statuses": counts,
            "code_files": len(symbols), "code_symbols": sum(map(len, symbols.values())),
            "unregistered_symbols": missing, "stale_registered_symbols": stale,
            "cli_commands": current_commands,
            "unregistered_cli_commands": missing_commands,
            "stale_registered_cli_commands": stale_commands,
            "note": "PASS betekent complete codefunctie-registratie, niet dat alle geplande productfuncties zijn gebouwd"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump-symbols", action="store_true",
                        help="print nieuwe inventaris; gewijzigde code vereist expliciete review")
    parser.add_argument("--check", action="store_true", help="faal bij nieuwe of verdwenen functies")
    args = parser.parse_args()
    try:
        if args.dump_symbols:
            data = {"schema_version": 1, "symbols": discover(),
                    "cli_commands": discover_cli_commands()}
        else:
            data = audit()
    except (ValueError, OSError, SyntaxError, KeyError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return 0 if data.get("status", "PASS") == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
