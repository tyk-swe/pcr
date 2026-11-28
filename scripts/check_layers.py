#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Check dependency direction and documented cycle groups at crate boundaries."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
from typing import NamedTuple

from rust_source import blank_comments_and_strings, is_test_path, without_test_items

Module = tuple[str, ...]
LayerTable = dict[Module, int]
Graph = dict[Module, set[Module]]
Cycle = tuple[Module, ...]
Allowlist = list[tuple[Module, Module]]

SEGMENT = r"[A-Za-z_][A-Za-z0-9_]*"
MODULE_PATH = rf"{SEGMENT}(?:::{SEGMENT})*"
PATH_START = re.compile(rf"\b(crate|super|self)((?:::{SEGMENT})*)(::\{{)?")


def balanced_end(text: str, opening: int) -> int:
    depth = 0
    for i in range(opening, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


def split_top_level(group: str) -> list[str]:
    parts = []
    depth = 0
    start = 0
    for i, char in enumerate(group):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(group[start:i])
            start = i + 1
    parts.append(group[start:])
    return [part.strip() for part in parts if part.strip()]


def resolve_relative(
    prefix: tuple[str, ...], segments: tuple[str, ...]
) -> tuple[str, ...]:
    supers = 0
    while supers < len(segments) and segments[supers] == "super":
        supers += 1
    if supers:
        return prefix[: max(0, len(prefix) - supers)] + segments[supers:]
    if segments and segments[0] == "crate":
        return segments[1:]
    if segments and segments[0] == "self":
        return prefix + segments[1:]
    return prefix + segments


def expand_group(prefix: tuple[str, ...], group: str) -> list[tuple[str, ...]]:
    paths = []
    for entry in split_top_level(group):
        entry = re.sub(rf"\s+as\s+{SEGMENT}$", "", entry)
        brace = entry.find("::{")
        if brace != -1 and entry.endswith("}"):
            head = tuple(entry[:brace].split("::"))
            resolved = resolve_relative(prefix, head)
            paths.extend(expand_group(resolved, entry[brace + 3:-1]))
        elif entry in ("self", "*"):
            if prefix:
                paths.append(prefix)
        else:
            segments = tuple(part for part in entry.split("::") if part != "*")
            resolved = resolve_relative(prefix, segments)
            if resolved:
                paths.append(resolved)
    return paths


def match_prefix(owner: tuple[str, ...], match) -> tuple[str, ...]:
    parts = (match.group(1),) + tuple(
        part for part in match.group(2).split("::") if part
    )
    if parts[0] == "self":
        return resolve_relative(owner, parts)
    return resolve_relative((), parts) if parts[0] == "crate" else resolve_relative(owner, parts)


INLINE_MOD = re.compile(rf"\bmod\s+({SEGMENT})\s*\{{")
VISIBILITY = re.compile(r"\bpub\s*\(\s*(?:crate|super|self)\s*\)|\bpub\s*\(\s*in\s+[^)]*\)")


def extract_paths(
    text: str, owner: tuple[str, ...]
) -> list[tuple[tuple[str, ...], tuple[str, ...]]]:
    paths = []
    spans = []
    for match in PATH_START.finditer(text):
        if not match.group(3):
            continue
        opening = match.end() - 1
        end = balanced_end(text, opening)
        paths.extend(
            (owner, target)
            for target in expand_group(match_prefix(owner, match), text[opening + 1:end - 1])
        )
        spans.append((match.start(), end))
    for start, end in reversed(spans):
        text = text[:start] + " " * (end - start) + text[end:]
    for match in PATH_START.finditer(text):
        if match.group(3):
            continue
        resolved = match_prefix(owner, match)
        if resolved:
            paths.append((owner, resolved))
    return paths


def scoped_paths(
    text: str, owner: tuple[str, ...]
) -> list[tuple[tuple[str, ...], tuple[str, ...]]]:
    paths = []
    pos = 0
    while True:
        match = INLINE_MOD.search(text, pos)
        if match is None:
            paths.extend(extract_paths(text[pos:], owner))
            return paths
        paths.extend(extract_paths(text[pos:match.start()], owner))
        opening = match.end() - 1
        end = balanced_end(text, opening)
        paths.extend(scoped_paths(text[opening + 1:end - 1], owner + (match.group(1),)))
        pos = end


def crate_paths(
    text: str, owner: tuple[str, ...] = ()
) -> list[tuple[tuple[str, ...], tuple[str, ...]]]:
    text = VISIBILITY.sub("pub", blank_comments_and_strings(without_test_items(text)))
    return scoped_paths(text, owner)


def test_only_paths(
    text: str, owner: tuple[str, ...], whole_file: bool
) -> list[tuple[tuple[str, ...], tuple[str, ...]]]:
    everything = scoped_paths(
        VISIBILITY.sub("pub", blank_comments_and_strings(text)), owner
    )
    if whole_file:
        return everything
    production = list(crate_paths(text, owner))
    test = []
    for pair in everything:
        if pair in production:
            production.remove(pair)
        else:
            test.append(pair)
    return test


def boundary(table: LayerTable, path: Module) -> Module | None:
    for length in range(len(path), 0, -1):
        if path[:length] in table:
            return path[:length]
    return None


def owner_path(src: Path, path: Path) -> tuple[str, ...] | None:
    rel = path.relative_to(src)
    if len(rel.parts) == 1 and rel.name in ("lib.rs", "main.rs"):
        return None
    parts = list(rel.parts)
    parts[-1] = parts[-1][:-3]
    return tuple(parts)


def allowlisted(
    allowlist: Allowlist, owner: Module, target: Module
) -> int | None:
    for index, (owner_prefix, target_prefix) in enumerate(allowlist):
        if (
            owner[: len(owner_prefix)] == owner_prefix
            and target[: len(target_prefix)] == target_prefix
        ):
            return index
    return None


def check_crate(
    crate: str, src: Path, table: LayerTable, allowlist: Allowlist,
    include_tests: bool,
) -> tuple[list[str], Graph]:
    problems = []
    used: set[int] = set()
    graph: Graph = {module: set() for module in table}
    for path in sorted(src.rglob("*.rs")):
        owner = owner_path(src, path)
        test_file = owner is not None and is_test_path(path.relative_to(src))
        if owner is None or (test_file and not include_tests):
            continue
        owner_boundary = boundary(table, owner)
        shown = "::".join(owner)
        if owner_boundary is None:
            if not include_tests:
                problems.append(f"{crate}: {path} module {shown} is not in the layer table")
            continue
        text = path.read_text(errors="replace")
        pairs = (
            test_only_paths(text, owner, test_file)
            if include_tests
            else crate_paths(text, owner)
        )
        for scoped_owner, target in pairs:
            source_module = boundary(table, scoped_owner) or owner_boundary
            target_module = boundary(table, target)
            if target_module is None or source_module == target_module:
                continue
            graph[source_module].add(target_module)
            scoped_layer, target_layer = table[source_module], table[target_module]
            if target_layer <= scoped_layer:
                continue
            index = allowlisted(allowlist, scoped_owner, target)
            if index is not None:
                used.add(index)
                continue
            problems.append(
                f"{crate}: {path} {'::'.join(scoped_owner)} (layer {scoped_layer}) depends on "
                f"{'::'.join(target)} (layer {target_layer})"
            )
    if not include_tests:
        problems.extend(
            f"{crate}: stale allowlist entry {'::'.join(owner)} -> {'::'.join(target)}"
            for index, (owner, target) in enumerate(allowlist)
            if index not in used
        )
    return problems, graph


def reachable(graph: Graph, source: Module) -> set[Module]:
    visited = {source}
    remaining = [source]
    while remaining:
        neighbors = graph[remaining.pop()] - visited
        visited.update(neighbors)
        remaining.extend(neighbors)
    return visited


def cycle_groups(graph: Graph) -> set[Cycle]:
    reach = {module: reachable(graph, module) for module in graph}
    groups = {
        tuple(sorted(other for other in neighbors if module in reach[other]))
        for module, neighbors in reach.items()
    }
    return {group for group in groups if len(group) > 1}


def check_cycles(crate: str, graph: Graph, allowed: set[Cycle]) -> list[str]:
    actual = cycle_groups(graph)
    return [
        f"{crate}: {label} {', '.join('::'.join(module) for module in group)}"
        for label, groups in (
            ("undocumented dependency cycle among", actual - allowed),
            ("stale allowed cycle among", allowed - actual),
        )
        for group in sorted(groups)
    ]


TABLE_ROW = re.compile(r"^//! \| (\d+)\. [^|]*\| ([^|]*)\|", re.M)
DEPENDENCY = re.compile(rf"`({MODULE_PATH})` -> `({MODULE_PATH})`\.")


def documented_layers(
    text: str,
) -> tuple[dict[tuple[str, ...], int], list[tuple[tuple[str, ...], list[int]]]]:
    layers = {}
    seen: dict[tuple[str, ...], list[int]] = {}
    for number, cell in TABLE_ROW.findall(text):
        listing = cell.split(": ", 1)[0]
        for token in re.findall(r"`([^`]+)`", listing):
            brace = token.find("::{")
            if brace != -1 and token.endswith("}"):
                head = tuple(token[:brace].split("::"))
                paths = expand_group(head, token[brace + 3:-1])
            elif re.fullmatch(MODULE_PATH, token):
                paths = [tuple(token.split("::"))]
            else:
                continue
            for path in paths:
                seen.setdefault(path, []).append(int(number))
                layers[path] = int(number)
    duplicates = [
        (path, sorted(set(numbers)))
        for path, numbers in sorted(seen.items())
        if len(set(numbers)) > 1
    ]
    return layers, duplicates


def crate_policy(crate: str, src: Path) -> tuple[LayerTable, set[Cycle], Allowlist, list[str]]:
    root = src / "lib.rs"
    text = root.read_text(errors="replace") if root.is_file() else ""
    documented, duplicates = documented_layers(text)
    if not documented:
        return {}, set(), [], [f"{crate}: lib.rs documents no layer table"]
    cycles = {
        tuple(sorted(tuple(token.split("::")) for token in re.findall(r"`([^`]+)`", group)))
        for group in re.findall(r"^//! Allowed cycle: (.*)$", text, re.M)
    }
    problems = [
        f"{crate}: lib.rs documents {'::'.join(path)} at layers "
        f"{' and '.join(str(number) for number in numbers)}"
        for path, numbers in duplicates
    ]
    allowlist = []
    for declaration in re.findall(r"^//! Allowed dependency:(.*)$", text, re.M):
        match = DEPENDENCY.fullmatch(declaration.strip())
        if match is None:
            problems.append(f"{crate}: malformed allowed dependency {declaration.strip()!r}")
            continue
        owner, target = match.groups()
        allowlist.append((tuple(owner.split("::")), tuple(target.split("::"))))
    return documented, cycles, allowlist, problems


class WorkspaceCheck(NamedTuple):
    problems: list[str]
    graphs: dict[str, Graph]


def check_workspace(
    root: Path,
    include_tests: bool = False,
) -> WorkspaceCheck:
    problems = []
    graphs = {}
    crates = tuple(path.parent for path in sorted((root / "crates").glob("*/Cargo.toml")))
    for directory in crates:
        crate = directory.name
        src = directory / "src"
        if not src.is_dir():
            problems.append(f"{crate}: missing source directory {src}")
            continue
        table, cycles, allowlist, invalid = crate_policy(crate, src)
        problems.extend(invalid)
        if not table:
            continue
        violations, graph = check_crate(crate, src, table, allowlist, include_tests)
        problems.extend(violations)
        graphs[crate] = graph
        if not include_tests:
            problems.extend(check_cycles(crate, graph, cycles))
    return WorkspaceCheck(problems, graphs)


def print_graph(graphs: dict[str, Graph]) -> None:
    print("digraph module_dependencies {")
    for crate, graph in sorted(graphs.items()):
        for source, targets in sorted(graph.items()):
            node = f'"{crate}::{"::".join(source)}"'
            print(f"  {node};")
            for target in sorted(targets):
                print(f'  {node} -> "{crate}::{"::".join(target)}";')
    print("}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    reports = parser.add_mutually_exclusive_group()
    reports.add_argument(
        "--report-tests",
        action="store_true",
        help="report upward dependencies from test code without failing; "
        "test code stays exempt from the check itself",
    )
    reports.add_argument(
        "--graph",
        action="store_true",
        help="print production module dependencies in Graphviz DOT format",
    )
    args = parser.parse_args(argv)
    checked = check_workspace(args.root.resolve(), include_tests=args.report_tests)
    if args.report_tests:
        for coupling in checked.problems:
            print(coupling)
        print(f"{len(checked.problems)} test layer coupling(s) (report only)")
        return 0
    if args.graph:
        print_graph(checked.graphs)
    for problem in checked.problems:
        print(problem, file=sys.stderr)
    if checked.problems:
        print(f"{len(checked.problems)} layer problem(s)", file=sys.stderr)
        return 1
    if not args.graph:
        print("production dependencies respect crate layers and documented cycle groups")
    return 0


if __name__ == "__main__":
    sys.exit(main())
