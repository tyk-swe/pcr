#!/usr/bin/env python3
"""Require a completed cargo-mutants report with at least 90% caught mutants."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def check_score(caught: int, missed: int, timeout: int, unviable: int) -> tuple[str, bool]:
    viable = caught + missed + timeout
    if viable == 0:
        return "No viable mutants were tested", False
    message = (
        f"Mutation score {caught}/{viable} = {caught / viable:.2%}, "
        f"{missed} missed, {timeout} timed out, {unviable} unviable"
    )
    return message, caught * 10 >= viable * 9


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    try:
        report = json.loads(args.report.read_text())
    except (OSError, ValueError) as error:
        print(f"Cannot read mutation report, {error}", file=sys.stderr)
        return 1
    if not isinstance(report, dict) or not report.get("end_time"):
        print("Mutation report is incomplete", file=sys.stderr)
        return 1
    counts = tuple(report.get(key) for key in ("caught", "missed", "timeout", "unviable"))
    if any(type(count) is not int or count < 0 for count in counts):
        print("Mutation report has invalid outcome counts", file=sys.stderr)
        return 1
    message, passed = check_score(*counts)
    print(message)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
