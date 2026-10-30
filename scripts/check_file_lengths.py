#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Rank source files by code lines and fail on oversized non-test files."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

CLOSING_ONLY = {"}", ")", "]", "};", ");", "],", "},"}
SOURCE_GLOBS = ("crates/**/*.rs", "scripts/**/*.py", "examples/**/*.rs", "fuzz/**/*.rs")


def blank_rust_comments_and_strings(text: str) -> str:
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
                and (opening := re.match(r"(?:br|cr|r)(#+)?\"", text[i:])):
            closing = '"' + (opening.group(1) or "")
            end = text.find(closing, i + opening.end())
            end = len(text) if end == -1 else end + len(closing)
            out.append("\n" * text[i:end].count("\n") + '""')
            i = end
        elif text[i] == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            i += 1
            out.append('""')
        elif text[i] == "'" and (literal := re.match(r"'(?:\\.|[^\\'])'", text[i:])):
            out.append("'x'")
            i += literal.end()
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def rust_code_lines(text: str) -> int:
    text = blank_rust_comments_and_strings(text)
    return sum(
        1
        for line in text.splitlines()
        if (stripped := line.strip()) and stripped not in CLOSING_ONLY
    )


def python_code_lines(text: str) -> int:
    count = 0
    in_docstring = False
    for line in text.splitlines():
        stripped = line.strip()
        if in_docstring:
            if '"""' in stripped or "'''" in stripped:
                in_docstring = False
            continue
        if stripped.startswith('"""') or stripped.startswith("'''"):
            marker = stripped[:3]
            if stripped.count(marker) < 2:
                in_docstring = True
            continue
        code = line.split("#")[0].strip()
        if code and code not in CLOSING_ONLY:
            count += 1
    return count


def code_lines(path: Path) -> int:
    text = path.read_text(errors="replace")
    return rust_code_lines(text) if path.suffix == ".rs" else python_code_lines(text)


def is_test_path(path: Path) -> bool:
    return path.name == "tests.rs" or "tests" in path.parts


def rank_files(root: Path, globs=SOURCE_GLOBS) -> list[dict]:
    rows = []
    for pattern in globs:
        for path in sorted(root.glob(pattern)):
            relative = path.relative_to(root)
            if "target" in relative.parts and "src" not in relative.parts[
                : relative.parts.index("target")
            ]:
                continue
            rows.append({
                "path": str(path.relative_to(root)),
                "code_lines": code_lines(path),
                "is_test": is_test_path(path.relative_to(root)),
            })
    rows.sort(key=lambda row: (-row["code_lines"], row["path"]))
    return rows


def violations(rows: list[dict], limit: int) -> list[dict]:
    return [row for row in rows if row["code_lines"] > limit and not row["is_test"]]


def render(rows: list[dict], limit: int, top: int) -> list[str]:
    lines = [f"Top {top} files by code lines (comments, blanks, closing-only lines excluded):"]
    for row in rows[:top]:
        marker = "test" if row["is_test"] else "    "
        lines.append(f"{row['code_lines']:5d} {marker} {row['path']}")
    over = [row for row in rows if row["code_lines"] > limit]
    non_test = [row for row in over if not row["is_test"]]
    lines.append(
        f"files over {limit} code lines: {len(over)} total, {len(non_test)} non-test"
    )
    for row in over:
        if row not in rows[:top]:
            marker = "test" if row["is_test"] else "    "
            lines.append(f"{row['code_lines']:5d} {marker} {row['path']}")
    return lines


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--limit", type=int, default=800)
    parser.add_argument("--top", type=int, default=25)
    args = parser.parse_args(argv)
    rows = rank_files(args.root.resolve())
    for line in render(rows, args.limit, args.top):
        print(line)
    bad = violations(rows, args.limit)
    for row in bad:
        print(
            f"non-test file over {args.limit} code lines: {row['path']} ({row['code_lines']})",
            file=sys.stderr,
        )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
