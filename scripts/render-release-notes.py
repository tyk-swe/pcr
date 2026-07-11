#!/usr/bin/env python3
"""Render commit- and artifact-bound GitHub Release notes."""

# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(alpha|beta|rc)\.(?:0|[1-9][0-9]*))?"
)
CLI_BASELINE = re.compile(r"CLI/schema baseline: `sha256:([0-9a-f]{64})`")


def git(*arguments: str) -> str:
    return subprocess.check_output(
        ["git", *arguments], cwd=ROOT, text=True, stderr=subprocess.STDOUT
    ).strip()


def git_file(tree: str, path: str) -> str:
    return subprocess.check_output(
        ["git", "show", f"{tree}:{path}"],
        cwd=ROOT,
        text=True,
        stderr=subprocess.STDOUT,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument(
        "--smoke-evidence",
        default="pending the post-publication downloaded-artifact matrix",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tree", default="HEAD")
    args = parser.parse_args()

    try:
        if git("status", "--porcelain=v1"):
            raise ValueError("release notes require a clean checkout")
        commit = git("rev-parse", f"{args.tree}^{{commit}}").lower()
        if not COMMIT.fullmatch(commit):
            raise ValueError(f"invalid source commit: {commit}")
        digest = args.archive_sha256.lower()
        if not DIGEST.fullmatch(digest):
            raise ValueError(f"invalid archive digest: {args.archive_sha256}")

        cargo = tomllib.loads(git_file(args.tree, "Cargo.toml"))
        release = tomllib.loads(git_file(args.tree, "RELEASE-METADATA.toml"))
        version = cargo["workspace"]["package"]["version"]
        version_match = VERSION.fullmatch(version)
        if version_match is None:
            raise ValueError(f"Release version is not canonical SemVer: {version}")
        channel = version_match.group(1) or "stable"
        if release["version"] != version or release["tag"] != f"v{version}":
            raise ValueError("tracked Release metadata differs from Cargo version/tag")
        if release["channel"] != channel:
            raise ValueError("tracked Release channel differs from its version")

        tag = f"refs/tags/v{version}"
        try:
            tagged_commit = git("rev-parse", f"{tag}^{{commit}}").lower()
        except subprocess.CalledProcessError:
            tagged_commit = ""
        if tagged_commit and tagged_commit != commit:
            raise ValueError(f"{tag} does not resolve to {commit}")

        changelog = git_file(args.tree, "CHANGELOG.md")
        baseline = CLI_BASELINE.search(changelog)
        if baseline is None:
            raise ValueError("CHANGELOG.md does not record the CLI/schema baseline")

        notes = git_file(args.tree, f"docs/releases/{version}.md.in")
        replacements = {
            "{{SOURCE_COMMIT}}": commit,
            "{{ARCHIVE_SHA256}}": digest,
            "{{SMOKE_EVIDENCE}}": args.smoke_evidence,
            "{{CLI_SCHEMA_BASELINE}}": baseline.group(1),
        }
        for placeholder, value in replacements.items():
            if notes.count(placeholder) != 1:
                raise ValueError(f"release-note placeholder count differs: {placeholder}")
            notes = notes.replace(placeholder, value)
        if "{{" in notes or "}}" in notes:
            raise ValueError("unexpanded release-note placeholder remains")

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(notes, encoding="utf-8")
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError, tomllib.TOMLDecodeError) as error:
        print(f"release-note rendering failed: {error}", file=sys.stderr)
        return 1

    print(f"rendered {args.output} for {commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
