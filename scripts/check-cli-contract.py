#!/usr/bin/env python3
"""Compare CLI help/errors and schema files with the v0.2 beta contract."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMMANDS = [
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
]
HELP_GOLDEN = ROOT / "tests" / "golden" / "cli-help.txt"
PARSE_ERROR_GOLDEN = ROOT / "tests" / "golden" / "cli-parse-error.txt"
VERSION_GOLDEN = ROOT / "tests" / "golden" / "cli-version.txt"
CONTRACT_FILES = [
    HELP_GOLDEN,
    PARSE_ERROR_GOLDEN,
    VERSION_GOLDEN,
    ROOT / "schemas" / "packetcraftr.packet.v1.schema.json",
    ROOT / "schemas" / "packetcraftr.output.v1.schema.json",
    ROOT / "schemas" / "README.md",
    ROOT / "docs" / "cli-contract.md",
]


def normalized(data: bytes) -> str:
    text = data.decode("utf-8").replace("\r\n", "\n")
    return "\n".join(line.rstrip() for line in text.split("\n"))


def invoke(binary: Path, arguments: list[str], expected: int) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        [str(binary), *arguments],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != expected:
        raise RuntimeError(
            f"{' '.join(arguments)} exited {result.returncode}, expected {expected}: "
            f"{normalized(result.stderr)}"
        )
    return result


def current_goldens(binary: Path) -> dict[Path, str]:
    sections: list[str] = []
    invocations = [("packetcraftr --help", ["--help"])] + [
        (f"packetcraftr {command} --help", [command, "--help"])
        for command in COMMANDS
    ]
    for label, arguments in invocations:
        result = invoke(binary, arguments, 0)
        if result.stderr:
            raise RuntimeError(f"{label} unexpectedly wrote stderr")
        sections.append(f"===== {label} =====\n{normalized(result.stdout).rstrip()}\n")

    parse_error = invoke(binary, ["build", "--unknown-option"], 2)
    if parse_error.stdout:
        raise RuntimeError("text parse error unexpectedly wrote stdout")

    version = invoke(binary, ["--version"], 0)
    if version.stderr:
        raise RuntimeError("--version unexpectedly wrote stderr")

    return {
        HELP_GOLDEN: "\n".join(sections),
        PARSE_ERROR_GOLDEN: normalized(parse_error.stderr),
        VERSION_GOLDEN: normalized(version.stdout),
    }


def contract_digest() -> str:
    digest = hashlib.sha256()
    for path in CONTRACT_FILES:
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_text(encoding="utf-8").replace("\r\n", "\n").encode())
        digest.update(b"\0")
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binary",
        type=Path,
        default=ROOT / "target" / "debug" / "packetcraftr",
    )
    parser.add_argument(
        "--bless",
        action="store_true",
        help="replace CLI goldens after explicit compatibility review",
    )
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        print(f"CLI binary does not exist: {binary}", file=sys.stderr)
        return 2

    try:
        current = current_goldens(binary)
    except (RuntimeError, UnicodeDecodeError) as error:
        print(error, file=sys.stderr)
        return 2

    if args.bless:
        HELP_GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        for path, content in current.items():
            path.write_text(content, encoding="utf-8")
        checksum = contract_digest()
        print("updated frozen CLI goldens")
        print(f"CLI/schema baseline: `sha256:{checksum}`")
        return 0

    failed = False
    for path, content in current.items():
        if not path.is_file():
            print(f"missing CLI golden: {path.relative_to(ROOT)}", file=sys.stderr)
            failed = True
            continue
        expected = path.read_text(encoding="utf-8")
        if expected == content:
            continue
        failed = True
        print(f"CLI contract changed: {path.relative_to(ROOT)}", file=sys.stderr)
        for line in difflib.unified_diff(
            expected.splitlines(),
            content.splitlines(),
            fromfile="frozen beta golden",
            tofile="current CLI",
            lineterm="",
        ):
            print(line, file=sys.stderr)
    if failed:
        print(
            "review compatibility, update CHANGELOG.md, then rerun with --bless",
            file=sys.stderr,
        )
        return 1

    checksum = contract_digest()
    token = f"CLI/schema baseline: `sha256:{checksum}`"
    if token not in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"):
        print(f"CHANGELOG.md must record the reviewed contract digest: {token}", file=sys.stderr)
        return 1
    print(f"CLI and schema contracts match the beta baseline ({checksum})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
