# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Blank Rust comments and string/char literals while preserving newlines."""
from __future__ import annotations

import re

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
