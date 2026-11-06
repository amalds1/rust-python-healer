"""Suggest a missing-colon fix without executing input source.

Conservative rule: only on SyntaxError("expected ':'"), only for a
single-line compound header, and only if the proposed source compiles.
The input file is never modified; the output is a separate staging path.
"""

import io
import json
import re
import sys
import tokenize


HEADER = re.compile(
    r"^\s*(?:async\s+(?:def|for|with)|if|elif|else|for|while|def|class|"
    r"try|except|finally|with)\b"
)


def propose(source):
    try:
        compile(source, "<candidate>", "exec", dont_inherit=True)
    except SyntaxError as exc:
        if not exc.lineno:
            return None
        # CPython 3.9 reports a missing colon as 'invalid syntax' at
        # the end of the header; 3.10+ usually reports "expected ':'".
        # Keep the older fallback narrow and verify the patched source.
        if exc.msg != "expected ':'":
            if exc.msg != "invalid syntax" or not exc.text or not exc.offset:
                return None
            legacy_offset = exc.offset
        else:
            legacy_offset = None
        target_line = exc.lineno
    else:
        return None

    lines = source.splitlines(keepends=True)
    if target_line < 1 or target_line > len(lines):
        return None
    line = lines[target_line - 1]
    if not HEADER.match(line):
        return None
    comment_start = None
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT and token.start[0] == target_line:
                comment_start = token.start[1]
                break
    except (tokenize.TokenError, IndentationError):
        return None
    if legacy_offset is not None:
        meaningful_end = (comment_start if comment_start is not None
                          else len(line.rstrip("\r\n")))
        if legacy_offset < meaningful_end:
            return None
    before = line[:comment_start] if comment_start is not None else line
    after = line[comment_start:] if comment_start is not None else ""
    content = before.rstrip("\r\n \t")
    if not content or content.endswith(":"):
        return None
    whitespace = before[len(content):]
    candidate = lines[:]
    candidate[target_line - 1] = content + ":" + whitespace + after
    changed = "".join(candidate)
    try:
        compile(changed, "<candidate>", "exec", dont_inherit=True)
    except (SyntaxError, ValueError):
        return None
    return changed


def main():
    source_path, output_path = sys.argv[1:3]
    with tokenize.open(source_path) as handle:
        source = handle.read()
        encoding = handle.encoding
    candidate = propose(source)
    if candidate is None:
        print(json.dumps({"changed": False, "reason": "no conservative compilable patch"}))
        return
    with open(output_path, "wb") as handle:
        handle.write(candidate.encode(encoding))
    print(json.dumps({"changed": True, "reason": "missing colon on simple compound header"}))


if __name__ == "__main__":
    main()
