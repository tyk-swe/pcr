#!/usr/bin/env python3
"""Execute the published CLI examples with the portable, no-native binary."""

# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "docs" / "cli-examples.md"
COMMANDS = (
    "build",
    "dissect",
    "read",
    "interfaces",
    "plan",
    "send",
    "exchange",
    "capture",
    "replay",
    "scan",
    "traceroute",
    "dns",
    "fuzz",
    "routes",
)
OFFLINE = {"build", "dissect", "read", "fuzz"}
EXAMPLE_BLOCK = re.compile(
    r"<!-- cli-example:([a-z]+) -->\s*```console\n(.*?)\n```", re.DOTALL
)


def default_binary() -> Path:
    name = "packetcraftr.exe" if os.name == "nt" else "packetcraftr"
    return ROOT / "target" / "debug" / name


def run(binary: Path, arguments: list[str], stdout_path: Path | None = None) -> subprocess.CompletedProcess[bytes]:
    if stdout_path is None:
        return subprocess.run(
            [str(binary), *arguments],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    with stdout_path.open("wb") as output:
        return subprocess.run(
            [str(binary), *arguments],
            cwd=ROOT,
            stdout=output,
            stderr=subprocess.PIPE,
            check=False,
        )


def parse_document() -> dict[str, list[str]]:
    text = DOCUMENT.read_text(encoding="utf-8")
    blocks: dict[str, list[str]] = {}
    for name, source in EXAMPLE_BLOCK.findall(text):
        if name in blocks:
            raise ValueError(f"duplicate cli-example marker for {name}")
        logical = source.replace("\\\r\n", " ").replace("\\\n", " ")
        blocks[name] = [
            line.strip()
            for line in logical.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    missing = sorted(set(COMMANDS) - set(blocks))
    extra = sorted(set(blocks) - set(COMMANDS))
    if missing or extra:
        raise ValueError(f"CLI example markers differ: missing={missing}, extra={extra}")
    return blocks


def structured_values(output: bytes) -> list[dict[str, object]]:
    text = output.decode("utf-8")
    try:
        aggregate = json.loads(text)
    except json.JSONDecodeError:
        values = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        values = [aggregate]
    if not values:
        raise ValueError("command emitted no structured output")
    for value in values:
        if value.get("schema") != "packetcraftr.output/v1":
            raise ValueError("command emitted a non-v1 output document")
    return values


def assert_portable_binary(binary: Path) -> None:
    probe = run(binary, ["--output", "json", "routes"])
    if probe.returncode != 4:
        raise ValueError(
            "documentation examples require a --no-default-features binary; "
            f"the passive routes probe returned {probe.returncode}"
        )
    values = structured_values(probe.stdout)
    if values[-1].get("error", {}).get("kind") != "capability":
        raise ValueError("portable routes probe did not return a capability error")


def assert_help(binary: Path) -> None:
    for arguments in (["--help"], *([command, "--help"] for command in COMMANDS)):
        result = run(binary, list(arguments))
        if result.returncode != 0 or result.stderr:
            raise ValueError(f"help failed for {' '.join(arguments)}")
        if b"Usage: packetcraftr" not in result.stdout:
            raise ValueError(f"help lacks canonical usage for {' '.join(arguments)}")


def execute_block(
    binary: Path,
    name: str,
    lines: list[str],
    temporary: Path,
) -> None:
    copy_name = "packetcraftr-example-copy.pcapng"
    copy_path = temporary / copy_name
    for line in lines:
        tokens = shlex.split(line)
        if not tokens or tokens[0] != "packetcraftr":
            raise ValueError(f"{name} example must invoke packetcraftr")
        tokens = [str(copy_path) if token == copy_name else token for token in tokens[1:]]
        stdout_path = None
        if ">" in tokens:
            redirect = tokens.index(">")
            if redirect + 2 != len(tokens):
                raise ValueError(f"unsupported redirection in {name} example")
            stdout_path = Path(tokens[redirect + 1])
            tokens = tokens[:redirect]

        result = run(binary, tokens, stdout_path)
        expected = 0 if name in OFFLINE else 4
        if result.returncode != expected:
            raise ValueError(
                f"{name} example returned {result.returncode}, expected {expected}: "
                f"{result.stderr.decode('utf-8', errors='replace')}"
            )

        if stdout_path is not None:
            if stdout_path.read_bytes()[:4] != bytes.fromhex("0a0d0d0a"):
                raise ValueError(f"{name} example did not write a PCAPNG stream")
            continue

        values = structured_values(result.stdout)
        if name in OFFLINE:
            if any(value.get("status") != "success" for value in values):
                raise ValueError(f"{name} example did not emit only success documents")
        elif values[-1].get("error", {}).get("kind") != "capability":
            raise ValueError(f"{name} example did not fail with a capability document")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binary",
        type=Path,
        default=default_binary(),
        help="path to a packetcraftr binary built with --no-default-features",
    )
    args = parser.parse_args()

    try:
        binary = args.binary.resolve(strict=True)
        blocks = parse_document()
        assert_portable_binary(binary)
        assert_help(binary)
        with tempfile.TemporaryDirectory(prefix="packetcraftr-doc-examples-") as path:
            temporary = Path(path)
            for command in COMMANDS:
                execute_block(binary, command, blocks[command], temporary)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"documentation example check failed: {error}", file=sys.stderr)
        return 1

    print("validated help and executable examples for all 14 CLI commands")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
