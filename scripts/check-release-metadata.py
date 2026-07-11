#!/usr/bin/env python3
"""Validate the identity and package metadata embedded in a Release archive."""

# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path


PACKAGE_NAMES = {
    "packetcraftr",
    "packetcraftr-core",
    "packetcraftr-io",
    "packetcraftr-protocols",
    "packetcraftr-session",
}
REPOSITORY = "https://github.com/tyk-swe/pcr"
LICENSE = "AGPL-3.0-only"
RUST_VERSION = "1.96"
COMMIT = re.compile(r"[0-9a-f]{40}")


def fail(message: str) -> None:
    raise ValueError(message)


def cargo_metadata(workspace: Path) -> dict[str, object]:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
        ],
        cwd=workspace,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        fail(f"cargo metadata failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-tag", required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()

    try:
        workspace = args.workspace.resolve(strict=True)
        expected_commit = args.expected_commit.lower()
        if not COMMIT.fullmatch(expected_commit):
            fail(f"invalid expected commit: {args.expected_commit}")

        release_path = workspace / "RELEASE-METADATA.toml"
        cargo_path = workspace / "Cargo.toml"
        release = tomllib.loads(release_path.read_text(encoding="utf-8"))
        cargo = tomllib.loads(cargo_path.read_text(encoding="utf-8"))

        expected_release = {
            "schema": "packetcraftr.release/v1",
            "version": args.expected_version,
            "tag": args.expected_tag,
            "commit": expected_commit,
            "channel": "beta",
            "repository": REPOSITORY,
            "rust_version": "1.96.0",
            "license": LICENSE,
        }
        if release != expected_release:
            fail(
                "release metadata mismatch:\n"
                f"expected {expected_release!r}\n"
                f"actual   {release!r}"
            )

        workspace_package = cargo["workspace"]["package"]
        if workspace_package["version"] != args.expected_version:
            fail("workspace package version differs from Release metadata")
        if workspace_package["repository"] != REPOSITORY:
            fail("workspace repository URL differs from Release metadata")
        if workspace_package["license"] != LICENSE:
            fail("workspace license differs from Release metadata")
        if workspace_package["rust-version"] != RUST_VERSION:
            fail("workspace MSRV differs from Release metadata")

        metadata = cargo_metadata(workspace)
        packages = {
            package["name"]: package
            for package in metadata["packages"]
            if package["name"] in PACKAGE_NAMES
        }
        if set(packages) != PACKAGE_NAMES:
            fail(
                "workspace package set differs: "
                f"expected={sorted(PACKAGE_NAMES)} actual={sorted(packages)}"
            )

        for name, package in packages.items():
            if package["version"] != args.expected_version:
                fail(f"{name} version differs from Release version")
            if package["license"] != LICENSE:
                fail(f"{name} license differs from Release license")
            if package["repository"] != REPOSITORY:
                fail(f"{name} repository differs from Release repository")
            if package["rust_version"] != RUST_VERSION:
                fail(f"{name} MSRV differs from Release MSRV")
            if package.get("publish") != []:
                fail(f"{name} must remain blocked from public registries")
            for dependency in package["dependencies"]:
                if dependency["name"] not in PACKAGE_NAMES:
                    continue
                if dependency["req"] != f"={args.expected_version}":
                    fail(
                        f"{name} dependency {dependency['name']} is not exact-version "
                        f"{args.expected_version}"
                    )

    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        print(f"Release metadata check failed: {error}", file=sys.stderr)
        return 1

    print(
        f"Release metadata binds {args.expected_tag} to {expected_commit} "
        f"across {len(PACKAGE_NAMES)} unpublished packages"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
