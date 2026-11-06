"""Exactly 100 deterministic CPython 3.9+ compatibility checks per interpreter.

All executable snippets are curated, local, network-free fixtures. This suite
does not execute arbitrary user source code and does not prove every package API.
The file itself deliberately uses only Python 3.9-compatible syntax.
"""

import json
import sys
import time


def build_cases():
    cases = []

    def add(name, category, source, kind="valid", min_minor=9):
        cases.append({"id": name, "category": category, "source": source,
                      "kind": kind, "min_minor": min_minor})

    valid = [
        ("assignment", "value = 7"),
        ("annotation", "value: int = 7"),
        ("walrus", "if (count := 2):\n    result = count"),
        ("positional_only", "def f(a, /, b):\n    return a + b"),
        ("keyword_only", "def f(*, a):\n    return a"),
        ("fstring", "name = 'x'\ntext = f'hi {name}'"),
        ("async_def", "async def task():\n    return 2"),
        ("async_for", "async def task(source):\n    async for item in source:\n        pass"),
        ("async_with", "async def task(context):\n    async with context:\n        pass"),
        ("generator", "def values():\n    yield 1"),
        ("generator_from", "def values():\n    yield from [1, 2]"),
        ("decorator", "def deco(f):\n    return f\n@deco\ndef f():\n    pass"),
        ("closure", "def outer():\n    x = 1\n    def inner():\n        return x"),
        ("nonlocal", "def outer():\n    x = 1\n    def inner():\n        nonlocal x\n        x += 1"),
        ("global", "x = 1\ndef bump():\n    global x\n    x += 1"),
        ("exception", "try:\n    1 / 0\nexcept ZeroDivisionError:\n    pass"),
        ("try_else_finally", "try:\n    value = 2\nexcept ValueError:\n    pass\nelse:\n    pass\nfinally:\n    pass"),
        ("with", "with open('file', 'w') as handle:\n    handle.write('x')"),
        ("list_comp", "x = [n*n for n in range(5)]"),
        ("dict_comp", "x = {n: n*n for n in range(5)}"),
        ("set_comp", "x = {n*n for n in range(5)}"),
        ("generator_expression", "x = sum(n for n in range(5))"),
        ("lambda", "f = lambda x, y=1: x + y"),
        ("class", "class Counter:\n    value = 0\n    def get(self):\n        return self.value"),
        ("property", "class C:\n    @property\n    def x(self):\n        return 1"),
        ("raise_from", "def f():\n    raise ValueError('x') from None"),
        ("unpacking", "a, *rest = [1, 2, 3]"),
        ("future_annotations", "from __future__ import annotations\ndef f(x: FutureType) -> FutureType:\n    return x"),
        ("multi_context", "with open('a') as one, open('b') as two:\n    pass"),
        ("matrix_operator", "def f(a, b):\n    return a @ b"),
    ]
    for name, source in valid:
        add("syntax_valid_" + name, "syntax_valid", source)

    invalid = [
        ("if_colon", "if True\n    pass"),
        ("def_colon", "def f()\n    pass"),
        ("class_colon", "class C\n    pass"),
        ("for_colon", "for x in []\n    pass"),
        ("while_colon", "while True\n    break"),
        ("unclosed_paren", "x = (1 + 2"),
        ("unclosed_bracket", "x = [1, 2"),
        ("unclosed_brace", "x = {1: 2"),
        ("unclosed_quote", "x = 'unterminated"),
        ("unclosed_triple", "x = '''unterminated"),
        ("indent", "  x = 1"),
        ("break", "break"),
        ("continue", "continue"),
        ("return", "return 42"),
        ("yield", "yield 42"),
        ("duplicate_argument", "def f(a, a):\n    return a"),
        ("argument_order", "f(a=1, 2)"),
        ("nonlocal", "nonlocal x"),
        ("literal_assignment", "42 = value"),
        ("await", "await thing()"),
    ]
    for name, source in invalid:
        add("syntax_invalid_" + name, "syntax_invalid", source, "invalid")

    gated = [
        ("match_literal", 10, "match x:\n    case 1: pass"),
        ("match_wildcard", 10, "match x:\n    case _: pass"),
        ("match_list", 10, "match x:\n    case [a, b]: pass"),
        ("match_mapping", 10, "match x:\n    case {'a': a}: pass"),
        ("match_guard", 10, "match x:\n    case n if n > 1: pass"),
        ("except_star_value", 11, "try:\n    pass\nexcept* ValueError:\n    pass"),
        ("except_star_type", 11, "try:\n    pass\nexcept* TypeError:\n    pass"),
        ("except_star_two", 11, "try:\n    pass\nexcept* ValueError:\n    pass\nexcept* TypeError:\n    pass"),
        ("except_star_named", 11, "try:\n    pass\nexcept* ValueError as error:\n    pass"),
        ("except_star_tuple", 11, "try:\n    pass\nexcept* (ValueError, TypeError):\n    pass"),
        ("type_alias", 12, "type Number = int | float"),
        ("type_alias_generic", 12, "type Items[T] = list[T]"),
        ("generic_class", 12, "class Box[T]:\n    pass"),
        ("generic_function", 12, "def identity[T](value: T) -> T:\n    return value"),
        ("generic_pair", 12, "class Pair[A, B]:\n    pass"),
        ("template_simple", 14, "value = t'Hello'"),
        ("template_interpolation", 14, "value = t'Hello {name}'"),
        ("template_triple", 14, "value = t'''Hello world'''"),
        ("template_number", 14, "value = t'{1 + 2}'"),
        ("template_repeated", 14, "value = t'prefix {x} suffix {y}'"),
    ]
    for name, minor, source in gated:
        add("version_gate_" + name, "version_syntax", source, "gated", minor)

    behavior = [
        ("integer_math", "assert 11 * 7 == 77"),
        ("floor_division", "assert -7 // 3 == -3"),
        ("modulo", "assert -7 % 3 == 2"),
        ("bitwise", "assert (7 & 3) == 3"),
        ("string_slice", "assert 'Python'[1:4] == 'yth'"),
        ("unicode", "assert len('é') == 1"),
        ("bytes", "assert bytes([65, 66]) == b'AB'"),
        ("list_slice", "assert [1, 2, 3][::-1] == [3, 2, 1]"),
        ("tuple_unpack", "a, b = (1, 2)\nassert a + b == 3"),
        ("dict_merge", "assert {**{'a': 1}, **{'b': 2}} == {'a': 1, 'b': 2}"),
        ("set_difference", "assert ({1, 2, 3} - {2}) == {1, 3}"),
        ("sorted_key", "assert sorted(['aaa', 'b'], key=len) == ['b', 'aaa']"),
        ("range", "assert list(range(2, 8, 2)) == [2, 4, 6]"),
        ("enumerate", "assert list(enumerate('ab')) == [(0, 'a'), (1, 'b')]"),
        ("zip", "assert list(zip([1, 2], 'ab')) == [(1, 'a'), (2, 'b')]"),
        ("any_all", "assert any([False, True]) and all([True, True])"),
        ("closure_value", "def f(x):\n    return lambda y: x+y\nassert f(3)(4) == 7"),
        ("generator_sum", "assert sum(i*i for i in range(4)) == 14"),
        ("decimal", "from decimal import Decimal\nassert Decimal('0.1') + Decimal('0.2') == Decimal('0.3')"),
        ("fractions", "from fractions import Fraction\nassert Fraction(1, 3) + Fraction(1, 6) == Fraction(1, 2)"),
    ]
    for name, source in behavior:
        add("runtime_" + name, "runtime_stdlib", source, "runtime")

    modules = [
        ("json", "import json\nassert json.loads('{\"x\": 2}')['x'] == 2"),
        ("ast", "import ast\nassert isinstance(ast.parse('x=1'), ast.Module)"),
        ("pathlib", "from pathlib import PurePosixPath\nassert PurePosixPath('/a') / 'b' == PurePosixPath('/a/b')"),
        ("collections", "from collections import Counter\nassert Counter('aba')['a'] == 2"),
        ("itertools", "from itertools import islice, count\nassert list(islice(count(), 3)) == [0, 1, 2]"),
        ("functools", "from functools import reduce\nassert reduce(lambda a,b:a+b, [1,2,3]) == 6"),
        ("statistics", "import statistics\nassert statistics.median([1, 3, 5]) == 3"),
        ("hashlib", "import hashlib\nassert hashlib.sha256(b'').hexdigest().startswith('e3b0c442')"),
        ("datetime", "from datetime import date\nassert date(2020, 2, 29).day == 29"),
        ("regex", "import re\nassert re.fullmatch(r'[a-z]+', 'abc') is not None"),
    ]
    for name, source in modules:
        add("module_" + name, "stdlib_modules", source, "runtime")

    if len(cases) != 100 or len(set(c["id"] for c in cases)) != 100:
        raise RuntimeError("de suite moet precies 100 unieke testgevallen bevatten")
    return cases


def run_suite():
    minor = sys.version_info.minor
    outcome = []
    start = time.perf_counter()
    for case in build_cases():
        expected_compile = case["kind"] != "invalid" and (
            case["kind"] != "gated" or minor >= case["min_minor"])
        error = None
        try:
            compiled = compile(case["source"], "<" + case["id"] + ">", "exec", dont_inherit=True)
        except (SyntaxError, ValueError) as exc:
            compiled = None
            error = str(exc)
        passed = (compiled is not None) == expected_compile
        if passed and case["kind"] == "runtime":
            try:
                exec(compiled, {"__builtins__": __builtins__})
            except Exception as exc:
                passed = False
                error = str(exc)
        outcome.append({"id": case["id"], "category": case["category"],
                        "status": "PASS" if passed else "FAIL", "error": None if passed else error})
    passed = sum(1 for item in outcome if item["status"] == "PASS")
    return {"python": sys.version.split()[0], "implementation": sys.implementation.name,
            "cases": 100, "pass": passed, "fail": 100 - passed,
            "status": "PASS" if passed == 100 else "FAIL",
            "duration_ms": round((time.perf_counter() - start) * 1000, 3),
            "results": outcome}


if __name__ == "__main__":
    print(json.dumps(run_suite(), ensure_ascii=False))
