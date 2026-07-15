#!/usr/bin/env python3
"""Validate dated RustSec waivers and their exact locked dependency paths."""

from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
ADVISORY = "RUSTSEC-2024-0436"
WARNING_DATE = dt.date(2026, 9, 12)
EXPIRY_DATE = dt.date(2026, 10, 12)
ROOT_PACKAGE = ("packetcraftr", "0.3.0")
WAIVED_PACKAGE = ("paste", "1.0.15")
EXPECTED_PATHS = (
    (
        ROOT_PACKAGE,
        ("rtnetlink", "0.21.0"),
        ("netlink-packet-core", "0.8.1"),
        WAIVED_PACKAGE,
    ),
    (
        ROOT_PACKAGE,
        ("rtnetlink", "0.21.0"),
        ("netlink-packet-route", "0.30.0"),
        ("netlink-packet-core", "0.8.1"),
        WAIVED_PACKAGE,
    ),
    (
        ROOT_PACKAGE,
        ("rtnetlink", "0.21.0"),
        ("netlink-proto", "0.12.0"),
        ("netlink-packet-core", "0.8.1"),
        WAIVED_PACKAGE,
    ),
)


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"RustSec waiver check failed: {message}")


def package_key(package: dict[str, object]) -> tuple[str, str]:
    return str(package["name"]), str(package["version"])


def dependency_subgraph(
    nodes: dict[str, dict[str, object]], root_id: str, target_id: str
) -> tuple[set[str], set[tuple[str, str]]]:
    dependencies = {
        package_id: {str(dependency["pkg"]) for dependency in node["deps"]}
        for package_id, node in nodes.items()
    }

    reachable_from_root: set[str] = set()
    pending = [root_id]
    while pending:
        package_id = pending.pop()
        if package_id in reachable_from_root:
            continue
        reachable_from_root.add(package_id)
        pending.extend(dependencies.get(package_id, ()))

    reverse_dependencies: dict[str, set[str]] = {}
    for parent_id, dependency_ids in dependencies.items():
        for dependency_id in dependency_ids:
            reverse_dependencies.setdefault(dependency_id, set()).add(parent_id)

    reaches_target: set[str] = set()
    pending = [target_id]
    while pending:
        package_id = pending.pop()
        if package_id in reaches_target:
            continue
        reaches_target.add(package_id)
        pending.extend(reverse_dependencies.get(package_id, ()))

    path_nodes = reachable_from_root & reaches_target
    path_edges = {
        (parent_id, dependency_id)
        for parent_id in path_nodes
        for dependency_id in dependencies.get(parent_id, ())
        if dependency_id in path_nodes
    }
    return path_nodes, path_edges


def describe_package(package_id: str, packages: dict[str, dict[str, object]]) -> str:
    package = packages[package_id]
    return f"{package['name']} {package['version']}"


def validate_exact_dependency_paths(
    nodes: dict[str, dict[str, object]],
    packages: dict[str, dict[str, object]],
    root_id: str,
    target_id: str,
    expected_paths: tuple[tuple[str, ...], ...],
) -> None:
    expected_nodes = {package_id for path in expected_paths for package_id in path}
    expected_edges = {
        edge for path in expected_paths for edge in zip(path, path[1:])
    }
    actual_nodes, actual_edges = dependency_subgraph(nodes, root_id, target_id)
    if actual_nodes == expected_nodes and actual_edges == expected_edges:
        return

    differences: list[str] = []
    unexpected_nodes = actual_nodes - expected_nodes
    if unexpected_nodes:
        descriptions = sorted(
            describe_package(package_id, packages) for package_id in unexpected_nodes
        )
        differences.append(f"unexpected packages: {', '.join(descriptions)}")

    unexpected_edges = actual_edges - expected_edges
    if unexpected_edges:
        descriptions = sorted(
            f"{describe_package(parent_id, packages)} -> "
            f"{describe_package(child_id, packages)}"
            for parent_id, child_id in unexpected_edges
        )
        differences.append(f"unexpected edges: {', '.join(descriptions)}")

    missing_nodes = expected_nodes - actual_nodes
    if missing_nodes:
        descriptions = sorted(
            describe_package(package_id, packages) for package_id in missing_nodes
        )
        differences.append(f"missing packages: {', '.join(descriptions)}")

    missing_edges = expected_edges - actual_edges
    if missing_edges:
        descriptions = sorted(
            f"{describe_package(parent_id, packages)} -> "
            f"{describe_package(child_id, packages)}"
            for parent_id, child_id in missing_edges
        )
        differences.append(f"missing edges: {', '.join(descriptions)}")

    fail(
        f"locked root-to-{WAIVED_PACKAGE[0]} dependency paths no longer exactly "
        f"match the {ADVISORY} waiver ({'; '.join(differences)})"
    )


def main() -> None:
    deny_text = (ROOT / "deny.toml").read_text(encoding="utf-8")
    waiver_count = len(re.findall(rf'\bid\s*=\s*"{re.escape(ADVISORY)}"', deny_text))
    if waiver_count != 1:
        fail(f"expected exactly one {ADVISORY} waiver, found {waiver_count}")

    metadata = json.loads(
        subprocess.check_output(
            [
                "cargo",
                "metadata",
                "--locked",
                "--all-features",
                "--format-version",
                "1",
            ],
            cwd=ROOT,
            text=True,
        )
    )
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}

    matching_ids: dict[tuple[str, str], list[str]] = {}
    for package_id, package in packages.items():
        matching_ids.setdefault(package_key(package), []).append(package_id)

    paste_ids = matching_ids.get(WAIVED_PACKAGE, [])
    if not paste_ids:
        fail(
            f"{WAIVED_PACKAGE[0]} {WAIVED_PACKAGE[1]} disappeared while "
            f"the {ADVISORY} waiver remains; remove the waiver immediately"
        )

    expected_packages = {
        name_version for path in EXPECTED_PATHS for name_version in path
    }
    selected_ids: dict[tuple[str, str], str] = {}
    for name_version in sorted(expected_packages):
        ids = matching_ids.get(name_version, [])
        if len(ids) != 1:
            fail(
                f"expected exactly one locked {name_version[0]} {name_version[1]}, "
                f"found {len(ids)}"
            )
        selected_ids[name_version] = ids[0]

    root_id = metadata["resolve"]["root"]
    if root_id != selected_ids[ROOT_PACKAGE]:
        fail(
            f"expected workspace resolve root {ROOT_PACKAGE[0]} {ROOT_PACKAGE[1]}"
        )

    expected_path_ids = tuple(
        tuple(selected_ids[name_version] for name_version in path)
        for path in EXPECTED_PATHS
    )
    validate_exact_dependency_paths(
        nodes,
        packages,
        root_id,
        selected_ids[WAIVED_PACKAGE],
        expected_path_ids,
    )

    raw_today = os.environ.get("WAIVER_CHECK_DATE")
    try:
        today = dt.date.fromisoformat(raw_today) if raw_today else dt.datetime.now(dt.UTC).date()
    except ValueError as error:
        fail(f"WAIVER_CHECK_DATE is invalid: {error}")

    path = " -> ".join(
        f"{name} {version}"
        for name, version in (
            ROOT_PACKAGE,
            ("rtnetlink", "0.21.0"),
            ("netlink-packet-core", "0.8.1"),
            WAIVED_PACKAGE,
        )
    )
    if today >= EXPIRY_DATE:
        fail(
            f"{ADVISORY} expired on {EXPIRY_DATE.isoformat()} for locked path {path}"
        )
    if today >= WARNING_DATE:
        days = (EXPIRY_DATE - today).days
        print(
            f"::warning title=RustSec waiver expires soon::{ADVISORY} for {path} "
            f"expires on {EXPIRY_DATE.isoformat()} ({days} day(s) remaining)"
        )
    else:
        print(
            f"validated {ADVISORY} through {EXPIRY_DATE.isoformat()} for locked path {path}"
        )


if __name__ == "__main__":
    main()
