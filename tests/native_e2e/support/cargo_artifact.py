# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Resolve a built executable from Cargo's JSON message stream."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import TextIO


class ArtifactError(RuntimeError):
    """Cargo did not report exactly one usable executable."""


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("target_name")
    return parser.parse_args()


def resolve_executable(stream: TextIO, target_name: str) -> Path:
    executables: set[Path] = set()
    for line_number, raw_line in enumerate(stream, start=1):
        if not raw_line.strip():
            continue
        try:
            message = json.loads(raw_line)
        except json.JSONDecodeError as error:
            raise ArtifactError(
                f"invalid Cargo JSON on line {line_number}: {error}"
            ) from error

        if message.get("reason") == "compiler-message":
            rendered = message.get("message", {}).get("rendered")
            if isinstance(rendered, str):
                sys.stderr.write(rendered)

        target = message.get("target", {})
        executable = message.get("executable")
        if (
            message.get("reason") == "compiler-artifact"
            and target.get("name") == target_name
            and "bin" in target.get("kind", [])
            and isinstance(executable, str)
        ):
            executables.add(Path(executable))

    if len(executables) != 1:
        paths = ", ".join(sorted(str(path) for path in executables)) or "none"
        raise ArtifactError(
            f"Cargo reported {len(executables)} executable paths "
            f"for binary target {target_name!r}: {paths}"
        )

    executable = executables.pop()
    if not executable.is_absolute():
        executable = Path.cwd() / executable
    executable = executable.resolve()
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ArtifactError(f"Cargo executable is not runnable: {executable}")
    return executable


def main() -> int:
    arguments = parse_arguments()
    try:
        executable = resolve_executable(sys.stdin, arguments.target_name)
    except ArtifactError as error:
        print(f"cargo artifact error: {error}", file=sys.stderr)
        return 1
    print(executable)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
