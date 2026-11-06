# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Blank Rust comments and string/char literals while preserving newlines."""
from __future__ import annotations

import re
from pathlib import Path


def is_test_path(path: Path) -> bool:
    """`path` must be relative to the repository, so its checkout location cannot match."""
    return path.name == "tests.rs" or "tests" in path.parts[:-1]


CHAR_LITERAL = re.compile(r"'(?:\\.|[^\\'])'")
RAW_PREFIX = re.compile(r'(?:br|cr|r)(#+)?"')


def blank_comments_and_strings(text: str) -> str:
    out = []
    i = 0
    while i < len(text):
        pair = text[i:i + 2]
        if pair == "//":
            end = text.find("\n", i)
            i = len(text) if end == -1 else end
        elif pair == "/*":
            depth = 1
            i += 2
            while i < len(text) and depth:
                if text[i] == "\n":
                    out.append("\n")
                    i += 1
                elif text[i:i + 2] == "/*":
                    depth += 1
                    i += 2
                elif text[i:i + 2] == "*/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
            out.append(" ")
        elif text[i] in "brc" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")) \
                and (opening := RAW_PREFIX.match(text, i)):
            closing = '"' + (opening.group(1) or "")
            end = text.find(closing, opening.end())
            end = len(text) if end == -1 else end + len(closing)
            out.append("\n" * text[i:end].count("\n") + '""')
            i = end
        elif text[i] == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            i += 1
            out.append('""')
        elif text[i] == "'" and (literal := CHAR_LITERAL.match(text, i)):
            out.append("'x'")
            i = literal.end()
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


TEST_ATTRIBUTE = re.compile(r"#\[cfg\((?:test|all\(\s*test)\b[^\]]*\)\]")


def _skip_literal(text: str, i: int) -> int:
    """Index just past the comment or literal starting at `i`, or `i` itself."""
    pair = text[i:i + 2]
    if pair == "//":
        end = text.find("\n", i)
        return len(text) if end == -1 else end
    if pair == "/*":
        depth = 1
        i += 2
        while i < len(text) and depth:
            if text[i:i + 2] == "/*":
                depth += 1
                i += 2
            elif text[i:i + 2] == "*/":
                depth -= 1
                i += 2
            else:
                i += 1
        return i
    if text[i] in "brc" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")) \
            and (opening := RAW_PREFIX.match(text, i)):
        closing = '"' + (opening.group(1) or "")
        end = text.find(closing, opening.end())
        return len(text) if end == -1 else end + len(closing)
    if text[i] == '"':
        i += 1
        while i < len(text) and text[i] != '"':
            i += 2 if text[i] == "\\" else 1
        return min(i + 1, len(text))
    if text[i] == "'" and (literal := CHAR_LITERAL.match(text, i)):
        return literal.end()
    return i


def blank_comments(text: str) -> str:
    """`text` with comment characters blanked; literals and offsets kept."""
    chars = list(text)
    i = 0
    while i < len(text):
        pair = text[i:i + 2]
        if pair in ("//", "/*"):
            end = _skip_literal(text, i)
            for j in range(i, end):
                if chars[j] != "\n":
                    chars[j] = " "
            i = end
        else:
            skipped = _skip_literal(text, i)
            i = skipped if skipped > i else i + 1
    return "".join(chars)


def _item_end(text: str, i: int) -> int:
    """End of the item starting at `i`, ignoring delimiters inside literals.

    A field or declaration ends at its `;` or `,` once every delimiter
    depth is zero; anything with a block ends at its balancing brace.
    """
    paren = bracket = brace = angle = 0
    while i < len(text):
        skipped = _skip_literal(text, i)
        if skipped > i:
            i = skipped
            continue
        char = text[i]
        if char == "(":
            paren += 1
        elif char == ")":
            paren -= 1
        elif char == "[":
            bracket += 1
        elif char == "]":
            bracket -= 1
        elif char == "{":
            brace += 1
        elif char == "}":
            if paren == bracket == brace == angle == 0:
                return i
            brace -= 1
            if brace == 0 and paren == bracket == angle == 0:
                return i + 1
        elif char == "<":
            angle += 1
        elif char == ">" and angle and text[i - 1] not in "-=":
            angle -= 1
        elif char in ",;" and paren == bracket == brace == angle == 0:
            return i + 1
        i += 1
    return i


def without_test_items(text: str) -> str:
    """`text` with every `#[cfg(test)]`-gated item removed."""
    out = []
    pos = 0
    while True:
        match = TEST_ATTRIBUTE.search(text, pos)
        if match is None:
            out.append(text[pos:])
            return "".join(out)
        out.append(text[pos:match.start()])
        pos = _item_end(text, match.end())
