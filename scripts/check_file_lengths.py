#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Rank source files by code lines and fail on oversized non-test files."""
from __future__ import annotations

import argparse
from collections.abc import Iterable
from pathlib import Path
import sys
from typing import TypedDict

from rust_source import blank_comments_and_strings, is_build_output, is_test_path

CLOSING_ONLY = {"}", ")", "]", "};", ");", "],", "},"}
SOURCE_GLOBS = ("crates/**/*.rs", "scripts/**/*.py", "examples/**/*.rs", "fuzz/**/*.rs")


class FileLength(TypedDict):
    path: str
    code_lines: int
    is_test: bool


def rust_code_lines(text: str) -> int:
    text = blank_comments_and_strings(text)
    return sum(
        1
        for line in text.splitlines()
        if (stripped := line.strip()) and stripped not in CLOSING_ONLY
    )


def python_code_lines(text: str) -> int:
    count = 0
    docstring_marker: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if docstring_marker is not None:
            if docstring_marker in stripped:
                docstring_marker = None
            continue
        if stripped.startswith('"""') or stripped.startswith("'''"):
            marker = stripped[:3]
            if stripped.count(marker) < 2:
                docstring_marker = marker
            continue
        code = line.split("#")[0].strip()
        if code and code not in CLOSING_ONLY:
            count += 1
    return count


def code_lines(path: Path) -> int:
    text = path.read_text(errors="replace")
    return rust_code_lines(text) if path.suffix == ".rs" else python_code_lines(text)


def rank_files(root: Path, globs: Iterable[str] = SOURCE_GLOBS) -> list[FileLength]:
    rows: list[FileLength] = []
    for pattern in globs:
        for path in sorted(root.glob(pattern)):
            relative = path.relative_to(root)
            if is_build_output(relative):
                continue
            rows.append({
                "path": relative.as_posix(),
                "code_lines": code_lines(path),
                "is_test": is_test_path(relative),
            })
    rows.sort(key=lambda row: (-row["code_lines"], row["path"]))
    return rows


def violations(rows: list[FileLength], limit: int) -> list[FileLength]:
    return [row for row in rows if row["code_lines"] > limit and not row["is_test"]]


def render(rows: list[FileLength], limit: int, top: int) -> list[str]:
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


def main(argv: list[str] | None = None) -> int:
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
