#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Count the implicit-coupling sites the decoupling plan ratchets to zero."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

from rust_source import is_test_path

ROOT = Path(__file__).resolve().parent.parent

BASELINE = {
    "make_layer_impls": 41,
    "field_layout_literals": 123,
    "hand_layout_fns": 31,
    "glob_imports": 104,
    "builtin_id_literals": 46,
    "instant_now": 38,
    "system_time_now": 19,
    "getrandom_sites": 6,
    "downcast_sites": 142,
    "error_downcast_sites": 0,
    "downcast_outside_allowlist": 142,
    "dynamic_field_sites": 84,
    "manual_cancellation_polls": 58,
    "message_protocol_rows": 36,
    "duplicate_constants": 27,
    "public_items_core": 25,
    "public_items_netio": 15,
    "public_items_packetcraftr": 26,
    "public_items_cli": 2,
    "catalog_public_items": 27,
}

CEILINGS = {
    "make_layer_impls": 0,
    "field_layout_literals": 0,
    "hand_layout_fns": 0,
    "glob_imports": 0,
    "builtin_id_literals": 0,
    "instant_now": 0,
    "system_time_now": 0,
    "getrandom_sites": 0,
    "downcast_sites": 25,
    "error_downcast_sites": 12,
    "downcast_outside_allowlist": 0,
    "dynamic_field_sites": 0,
    # Residual polls guard compute/input loops, side-effect commit
    # boundaries, and NDJSON emits whose deadline code (policy) the stream
    # encoder would report as an output code instead. The encoder already
    # enforces the same control deadline on every write, and every poll that
    # only duplicated an emit-internal check with an identical error is gone.
    "manual_cancellation_polls": 59,
    "message_protocol_rows": 0,
    "duplicate_constants": 0,
    "public_items_core": 25,
    "public_items_netio": 15,
    "public_items_packetcraftr": 26,
    "public_items_cli": 2,
    "catalog_public_items": 24,
}

# Layer downcasts live only in the identity extraction, the typed container
# and trait definitions, codec entries, and layer types casting to themselves.
LAYER_CAST_FILES = (
    "crates/packetcraftr-core/src/layer/model.rs",
    "crates/packetcraftr-core/src/layer/opaque.rs",
    "crates/packetcraftr-core/src/packet.rs",
    "crates/packetcraftr-core/src/protocol/catalog.rs",
    "crates/packetcraftr-core/src/protocol/common/errors.rs",
    "crates/packetcraftr-core/src/protocol/identity.rs",
    "crates/packetcraftr-core/src/protocol/application/modbus_tcp.rs",
    "crates/packetcraftr-core/src/protocol/application/tls/codec.rs",
)

# Standard error-chain introspection on boxed errors is a different family
# from layer identity casts and is counted separately.
ERROR_CAST_FILES = (
    "crates/packetcraftr-cli/src/commands/network/scan.rs",
    "crates/packetcraftr-core/src/capture_file/compression.rs",
    "crates/packetcraftr-core/src/capture_file/error.rs",
    "crates/packetcraftr-netio/src/tls/error.rs",
    "crates/packetcraftr/src/dns/engine/attempts.rs",
    "crates/packetcraftr/src/identify/io.rs",
    "crates/packetcraftr/src/replay/engine.rs",
)

CAST_PATTERN = re.compile(r"downcast_ref|downcast_mut|\.is::<")

# The whole workspace reads time and entropy through these seam modules.
CLOCK_SEAM = "crates/packetcraftr-core/src/clock.rs"
ENTROPY_SEAM = "crates/packetcraftr-netio/src/entropy.rs"


CONST_PATTERN = re.compile(
    r"^(?:pub(?:\([^)]*\))?\s+)?const ([A-Z][A-Z0-9_]{2,}):[^=]+=\s*([^;]+);",
    re.M,
)


def duplicate_constants(sources: list[Path]) -> int:
    """Module-level constants defined with the same literal in two files.

    Aliases (values naming another path) and scoped constants (associated
    or function-local) are single-sourced by construction and do not count.
    """
    seen: dict[tuple[str, str], set[Path]] = {}
    for path in sources:
        for name, value in CONST_PATTERN.findall(path.read_text()):
            value = " ".join(value.split())
            if "::" in value:
                continue
            seen.setdefault((name, value), set()).add(path)
    return sum(1 for paths in seen.values() if len(paths) > 1)


PUBLIC_ITEM_PATTERN = re.compile(
    r"^pub (?:use|mod|fn|struct|enum|trait|const|type|static) ", re.M)

CRATE_ROOTS = {
    "public_items_core": "crates/packetcraftr-core/src/lib.rs",
    "public_items_netio": "crates/packetcraftr-netio/src/lib.rs",
    "public_items_packetcraftr": "crates/packetcraftr/src/lib.rs",
    "public_items_cli": "crates/packetcraftr-cli/src/lib.rs",
}


def public_items(root: Path) -> dict[str, int]:
    return {
        name: len(PUBLIC_ITEM_PATTERN.findall((root / relative).read_text()))
        if (root / relative).is_file() else 0
        for name, relative in CRATE_ROOTS.items()
    }


def cast_counts(root: Path, sources: list[Path]) -> dict[str, int]:
    return {
        str(path.relative_to(root)): len(CAST_PATTERN.findall(path.read_text()))
        for path in sources
    }


def allowlist_problems(root: Path = ROOT) -> list[str]:
    counts = cast_counts(root, production_sources(root))
    problems = []
    for relative in LAYER_CAST_FILES + ERROR_CAST_FILES:
        if counts.get(relative, 0) == 0:
            problems.append(f"stale cast allowlist entry: {relative}")
    return problems


BOUNDARY_MODULES = (
    "examples/",
    "fuzz/",
    "document/",
    "expression",
    "filter/",
    "layer/model.rs",
    "layer/reflection.rs",
    "layer/selector.rs",
    "codec.rs",
    "build.rs",
    "input/",
    "rendering/",
    "output/",
    "template.rs",
)


def production_sources(root: Path = ROOT) -> list[Path]:
    sources = []
    for path in sorted((root / "crates").rglob("*.rs")):
        if is_test_path(path.relative_to(root)):
            continue
        sources.append(path)
    return sources


def count(pattern: str, sources: list[Path], flags: int = 0) -> int:
    regex = re.compile(pattern, flags)
    return sum(len(regex.findall(path.read_text())) for path in sources)


def inventory(root: Path = ROOT) -> dict[str, int]:
    sources = production_sources(root)
    catalog = root / "crates/packetcraftr-core/src/protocol/catalog.rs"
    builtin_names = set(re.findall(
        r'canonical: "([a-z0-9_]+)"',
        catalog.read_text() if catalog.exists() else "",
    ))
    id_literals = 0
    dynamic = 0
    for path in sources:
        text = path.read_text()
        if path.name != "catalog.rs" and "layer/opaque.rs" not in str(path):
            for literal in re.findall(r'Id::new\("([a-z0-9_]+)"\)', text):
                if literal in builtin_names:
                    id_literals += 1
        relative = str(path.relative_to(root))
        if not any(module in relative for module in BOUNDARY_MODULES):
            # Layer dynamic field access only: one-argument field reads by
            # name plus every path-based access. Two-argument DebugStruct
            # .field(name, value) calls are formatting, not layer access.
            dynamic += len(re.findall(
                r"layer\.field\(|\.field\(\"[a-z0-9_.]+\"\)|\.set_field\(|\.field_path\(|\.set_field_path\(",
                text))
    non_clock = [
        s for s in sources if str(s.relative_to(root)) != CLOCK_SEAM
    ]
    non_entropy = [
        s for s in sources if str(s.relative_to(root)) != ENTROPY_SEAM
    ]
    casts = cast_counts(root, sources)
    layer_casts = sum(casts.get(relative, 0) for relative in LAYER_CAST_FILES)
    error_casts = sum(casts.get(relative, 0) for relative in ERROR_CAST_FILES)
    outside = sum(
        value
        for relative, value in casts.items()
        if relative not in LAYER_CAST_FILES and relative not in ERROR_CAST_FILES
    )
    return {
        "make_layer_impls": count(r"fn make_layer", sources),
        "field_layout_literals": count(
            r"FieldLayout\s*\{[^}]*?name:",
            [s for s in sources if "packetcraftr-core" in str(s)],
            re.S,
        ),
        "hand_layout_fns": count(r"fn [a-z0-9_]+_layout_wire\(", sources),
        "glob_imports": count(r"^use [^;]+::\*;", sources, re.M),
        "builtin_id_literals": id_literals,
        "instant_now": count(r"Instant::now", non_clock),
        "system_time_now": count(r"SystemTime::now", non_clock),
        "getrandom_sites": count(r"getrandom", non_entropy),
        "downcast_sites": layer_casts,
        "error_downcast_sites": error_casts,
        "downcast_outside_allowlist": outside,
        "dynamic_field_sites": dynamic,
        "manual_cancellation_polls": count(r"invocation\.check", sources),
        "catalog_public_items": count(
            r"^\s*pub (?:const )?fn ",
            [root / "crates/packetcraftr-core/src/protocol/catalog.rs"],
            re.M,
        ),
        "duplicate_constants": duplicate_constants(sources),
        **public_items(root),
        "message_protocol_rows": count(
            r"MessageProtocol \{",
            [root / "crates/packetcraftr-core/src/protocol/capabilities.rs"]
            if (root / "crates/packetcraftr-core/src/protocol/capabilities.rs").exists()
            else [],
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", action="store_true", help="print counts without failing")
    args = parser.parse_args()
    measured = inventory()
    failures = allowlist_problems()
    print(f"{'metric':28} {'baseline':>8} {'measured':>8} {'ceiling':>8}")
    for name, value in measured.items():
        ceiling = CEILINGS[name]
        print(f"{name:28} {BASELINE[name]:>8} {value:>8} {ceiling:>8}")
        if value > ceiling:
            failures.append(f"{name}: {value} exceeds ceiling {ceiling}")
    if failures and not args.report:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
