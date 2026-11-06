#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Check input documents against their schemas and their embedded twins."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import sys

from script_support import read_json

ROOT = Path(__file__).resolve().parent.parent

IDENTITY = re.compile(r"^packetcraftr\.([a-z0-9-]+)/v(\d+)$")

DOCUMENT_TREES = ("examples/documents", "crates/packetcraftr/data")

TWIN_PAIRS = (
    ("examples/documents/service-probes.json", "crates/packetcraftr/data/service-probes.json"),
    ("examples/documents/service-exclusions.json", "crates/packetcraftr/data/service-exclusions.json"),
    ("examples/documents/os-fingerprints.json", "crates/packetcraftr/data/os-fingerprints.v1.json"),
)

HISTORICAL = (
    "schemas/historical/packetcraftr.output.v1-reset-4766fe78.schema.json",
    "2d1cc3bb26444a3a4c5dd40c818940369a53b1c6eda2eab1e618f438852581d4",
)

HISTORICAL_ADR = "docs/adr/0003-never-reuse-output-contract-identifiers.md"

YAML_COVERED_ELSEWHERE = {"examples/documents/packet-raw.yaml"}


def schema_path(root: Path, identity: str) -> Path | None:
    match = IDENTITY.match(identity)
    if match is None:
        return None
    return root / "schemas" / f"packetcraftr.{match.group(1)}.v{match.group(2)}.schema.json"


class CheckError(Exception):
    pass


def load_jsonschema():
    try:
        import jsonschema
    except ImportError as error:
        raise CheckError('document validation requires the jsonschema package; '
                         'install python3-jsonschema or `pip install jsonschema`') from error
    return jsonschema


def check_documents(root: Path = ROOT) -> list[str]:
    jsonschema = load_jsonschema()

    problems = []
    claimed: set[Path] = set()
    validators = {}
    checked = 0
    for tree in DOCUMENT_TREES:
        for path in sorted((root / tree).glob("*.json")):
            if path.name.startswith("output-"):
                continue
            document = read_json(path)
            identity = document.get("schema") if isinstance(document, dict) else None
            if not isinstance(identity, str):
                continue
            schema = schema_path(root, identity)
            shown = path.relative_to(root)
            if schema is None:
                problems.append(f"{shown}: unrecognised schema identity {identity!r}")
                continue
            if not schema.is_file():
                problems.append(f"{shown}: schema {identity} has no file at {schema.relative_to(root)}")
                continue
            claimed.add(schema)
            if schema not in validators:
                parsed = read_json(schema)
                validators[schema] = jsonschema.validators.validator_for(parsed)(parsed)
            validator = validators[schema]
            for error in sorted(validator.iter_errors(document), key=lambda error: list(error.path)):
                where = ".".join(str(part) for part in error.path) or "<root>"
                problems.append(f"{shown}: {where}: {error.message}")
            checked += 1
    cover_test = root / "crates/packetcraftr-core/src/protocol/builtin/tests.rs"
    cover_text = cover_test.read_text() if cover_test.is_file() else ""
    for covered in sorted(YAML_COVERED_ELSEWHERE):
        if (root / covered).is_file() and Path(covered).name not in cover_text:
            problems.append(
                f"{covered}: listed as covered elsewhere but no core test names it"
            )
    for tree in DOCUMENT_TREES:
        for path in sorted((root / tree).glob("*.yaml")) + sorted((root / tree).glob("*.yml")):
            if not re.search(r"^schema:\s*packetcraftr\.", path.read_text(), re.M):
                continue
            shown = str(path.relative_to(root))
            if shown not in YAML_COVERED_ELSEWHERE:
                problems.append(
                    f"{shown}: claims a schema but no check validates YAML documents"
                )
    if checked == 0:
        problems.append("no input documents were checked against a schema")
    for schema in sorted((root / "schemas").glob("*.schema.json")):
        if ".output." not in schema.name and schema not in claimed:
            problems.append(f"{schema.relative_to(root)}: no document claims this schema")
    for first, second in TWIN_PAIRS:
        if (root / first).read_bytes() != (root / second).read_bytes():
            problems.append(f"{first} and {second} must stay byte-identical")

    forwarding = (root / "examples/consumers/forwarding.py").read_text()
    consumer = re.search(r'^SCHEMA = "([^"]+)"', forwarding, re.M)
    security = (root / "crates/packetcraftr-core/src/security.rs").read_text()
    emitted = re.search(r'pub const OUTPUT_SCHEMA: &str = "([^"]+)";', security)
    if consumer is None or emitted is None or consumer.group(1) != emitted.group(1):
        problems.append("examples/consumers/forwarding.py SCHEMA disagrees with OUTPUT_SCHEMA")

    historical, digest = HISTORICAL
    actual = hashlib.sha256((root / historical).read_bytes()).hexdigest()
    if actual != digest:
        problems.append(f"{historical}: frozen schema changed (sha256 {actual})")
    adr = (root / HISTORICAL_ADR).read_text()
    if not any(historical in line and digest in line for line in adr.splitlines()):
        problems.append(f"{HISTORICAL_ADR}: no row ties {historical} to sha256 {digest}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        problems = check_documents(args.root.resolve())
    except CheckError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print(f"{len(problems)} document problem(s)", file=sys.stderr)
        return 1
    print("all input documents validate against their schemas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
