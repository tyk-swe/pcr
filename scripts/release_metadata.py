#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Print the release workflow outputs for a tag and `cargo metadata` document."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from script_support import read_json

RELEASED_PACKAGE = "packetcraftr-cli"


def released_version(metadata: object) -> str:
    packages = metadata.get("packages") if isinstance(metadata, dict) else None
    if not isinstance(packages, list):
        raise ValueError("cargo metadata has no package list")
    versions = [
        package.get("version")
        for package in packages
        if isinstance(package, dict) and package.get("name") == RELEASED_PACKAGE
    ]
    if len(versions) != 1 or not isinstance(versions[0], str):
        raise ValueError(f"could not identify exactly one {RELEASED_PACKAGE} package")
    return versions[0]


def is_prerelease(version: str) -> bool:
    return "-" in version.partition("+")[0]


def release_outputs(metadata: object, tag: str) -> dict[str, str]:
    version = released_version(metadata)
    if tag != f"v{version}":
        raise ValueError(f"tag '{tag}' does not match {RELEASED_PACKAGE} version 'v{version}'")
    return {"prerelease": str(is_prerelease(version)).lower(), "version": version}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    try:
        outputs = release_outputs(read_json(args.metadata), args.tag)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    for name, value in outputs.items():
        print(f"{name}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
