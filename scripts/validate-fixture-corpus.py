#!/usr/bin/env python3
"""Validate PacketcraftR fixture provenance without rewriting the corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA_ID = "packetcraftr.fixture-provenance/v1"
PROVENANCE_SUFFIX = ".provenance.json"
MAX_FIXTURE_BYTES = 16 * 1024 * 1024
MAX_PROVENANCE_BYTES = 1024 * 1024
TOP_LEVEL_KEYS = {
    "schema",
    "fixture",
    "sha256",
    "kind",
    "authority",
    "created_utc",
    "protocols",
    "capture",
    "source",
    "license",
    "expected",
    "review",
}
KINDS = {
    "frame",
    "pcap",
    "pcapng",
    "document",
    "expected_result",
    "malformed_input",
}
AUTHORITIES = {"authoritative", "derived", "malformed_seed"}
SOURCE_TYPES = {"rfc_vector", "generated", "tool_output", "captured", "derived"}
PROTOCOL_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
FIXTURE_PATH_RE = re.compile(r"^(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SPDX_RE = re.compile(r"^[A-Za-z0-9.+()-]+(?: (?:AND|OR|WITH) [A-Za-z0-9.+()-]+)*$")


class DuplicateKeyError(ValueError):
    pass


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def is_uint32(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFFFF_FFFF


def nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def valid_utc(value: Any) -> bool:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def exact_keys(
    value: Any, required: set[str], optional: set[str] | None = None
) -> str | None:
    if not isinstance(value, dict):
        return "must be an object"
    optional = optional or set()
    missing = required - value.keys()
    extra = value.keys() - required - optional
    if missing:
        return f"is missing fields: {', '.join(sorted(missing))}"
    if extra:
        return f"has unknown fields: {', '.join(sorted(extra))}"
    return None


def validate_tool(value: Any, location: str, errors: list[str]) -> None:
    if value is None:
        return
    problem = exact_keys(value, {"name", "version", "invocation"}, {"summary"})
    if problem:
        errors.append(f"{location} {problem}")
        return
    for field in ("name", "version", "invocation"):
        if not nonempty_string(value[field]):
            errors.append(f"{location}.{field} must be a non-empty string")
    if "summary" in value and not nonempty_string(value["summary"]):
        errors.append(f"{location}.summary must be a non-empty string when present")


def validate_capture(value: Any, location: str, errors: list[str]) -> None:
    problem = exact_keys(value, {"link_types", "interfaces"})
    if problem:
        errors.append(f"{location} {problem}")
        return
    link_types = value["link_types"]
    if (
        not isinstance(link_types, list)
        or not link_types
        or any(not is_uint32(item) for item in link_types)
        or len(set(link_types)) != len(link_types)
    ):
        errors.append(f"{location}.link_types must be a non-empty unique uint32 array")
        link_type_set: set[int] = set()
    else:
        link_type_set = set(link_types)
    interfaces = value["interfaces"]
    if not isinstance(interfaces, list):
        errors.append(f"{location}.interfaces must be an array")
        return
    interface_ids: set[int] = set()
    for index, interface in enumerate(interfaces):
        entry = f"{location}.interfaces[{index}]"
        problem = exact_keys(interface, {"id", "link_type"})
        if problem:
            errors.append(f"{entry} {problem}")
            continue
        if not is_uint32(interface["id"]):
            errors.append(f"{entry}.id must be uint32")
        elif interface["id"] in interface_ids:
            errors.append(f"{entry}.id duplicates interface {interface['id']}")
        else:
            interface_ids.add(interface["id"])
        if not is_uint32(interface["link_type"]):
            errors.append(f"{entry}.link_type must be uint32")
        elif interface["link_type"] not in link_type_set:
            errors.append(f"{entry}.link_type is absent from capture.link_types")


def validate_provenance(root: Path, sidecar: Path, errors: list[str]) -> None:
    display = sidecar.relative_to(root).as_posix()
    if sidecar.is_symlink():
        errors.append(f"{display}: provenance sidecar must not be a symbolic link")
        return
    try:
        sidecar_size = sidecar.stat().st_size
    except OSError as error:
        errors.append(f"{display}: cannot inspect provenance sidecar: {error}")
        return
    if sidecar_size > MAX_PROVENANCE_BYTES:
        errors.append(
            f"{display}: provenance sidecar is {sidecar_size} bytes; "
            f"maximum is {MAX_PROVENANCE_BYTES}"
        )
        return
    try:
        document = load_json(sidecar)
    except (OSError, UnicodeError, json.JSONDecodeError, DuplicateKeyError) as error:
        errors.append(f"{display}: invalid provenance JSON: {error}")
        return
    problem = exact_keys(document, TOP_LEVEL_KEYS)
    if problem:
        errors.append(f"{display}: provenance {problem}")
        return

    fixture_name = document["fixture"]
    expected_name = display.removesuffix(PROVENANCE_SUFFIX)
    if expected_name.endswith(PROVENANCE_SUFFIX):
        errors.append(f"{display}: provenance sidecars cannot describe other sidecars")
    if not nonempty_string(fixture_name):
        errors.append(f"{display}: fixture must be a non-empty path")
        return
    pure_path = PurePosixPath(fixture_name)
    if (
        not FIXTURE_PATH_RE.fullmatch(fixture_name)
        or pure_path.is_absolute()
        or any(part in {"", ".", ".."} for part in pure_path.parts)
    ):
        errors.append(f"{display}: fixture path must be normalized and relative")
        return
    if fixture_name != expected_name:
        errors.append(
            f"{display}: fixture field {fixture_name!r} does not match sidecar path {expected_name!r}"
        )
    fixture = root / fixture_name
    if fixture.is_symlink():
        errors.append(f"{display}: fixture must not be a symbolic link")
    if not fixture.is_file():
        errors.append(f"{display}: referenced fixture does not exist: {fixture_name}")
        return
    size = fixture.stat().st_size
    if size > MAX_FIXTURE_BYTES:
        errors.append(f"{display}: fixture is {size} bytes; maximum is {MAX_FIXTURE_BYTES}")
        return
    actual_sha = sha256_file(fixture)
    declared_sha = document["sha256"]
    if not isinstance(declared_sha, str) or not SHA256_RE.fullmatch(declared_sha):
        errors.append(f"{display}: sha256 must be 64 lowercase hexadecimal characters")
    elif declared_sha != actual_sha:
        errors.append(
            f"{display}: sha256 mismatch for {fixture_name}: declared {declared_sha}, actual {actual_sha}"
        )

    if document["schema"] != SCHEMA_ID:
        errors.append(f"{display}: schema must be {SCHEMA_ID!r}")
    kind = document["kind"]
    if not isinstance(kind, str) or kind not in KINDS:
        errors.append(f"{display}: kind must be one of {', '.join(sorted(KINDS))}")
    authority = document["authority"]
    if not isinstance(authority, str) or authority not in AUTHORITIES:
        errors.append(
            f"{display}: authority must be one of {', '.join(sorted(AUTHORITIES))}"
        )
    if not valid_utc(document["created_utc"]):
        errors.append(f"{display}: created_utc must use YYYY-MM-DDTHH:MM:SSZ")

    suffix = fixture.suffix.lower()
    allowed_suffixes = {
        "frame": {".bin"},
        "pcap": {".pcap"},
        "pcapng": {".pcapng"},
        "document": {".json", ".yaml", ".yml"},
        "expected_result": {".json"},
        "malformed_input": {".bin", ".json", ".pcap", ".pcapng", ".yaml", ".yml"},
    }
    if (
        isinstance(kind, str)
        and kind in allowed_suffixes
        and suffix not in allowed_suffixes[kind]
    ):
        errors.append(f"{display}: kind {kind!r} is inconsistent with extension {suffix!r}")

    protocols = document["protocols"]
    if (
        not isinstance(protocols, list)
        or not protocols
        or any(not isinstance(item, str) or not PROTOCOL_RE.fullmatch(item) for item in protocols)
        or len(set(protocols)) != len(protocols)
    ):
        errors.append(f"{display}: protocols must be a non-empty unique protocol-id array")

    capture = document["capture"]
    if isinstance(kind, str) and kind in {"pcap", "pcapng"} and capture is None:
        errors.append(f"{display}: {kind} provenance requires capture metadata")
    if capture is not None:
        validate_capture(capture, f"{display}: capture", errors)

    source = document["source"]
    problem = exact_keys(source, {"type", "description", "reference", "generator", "oracle"})
    if problem:
        errors.append(f"{display}: source {problem}")
    else:
        if not isinstance(source["type"], str) or source["type"] not in SOURCE_TYPES:
            errors.append(f"{display}: source.type is unsupported")
        if not nonempty_string(source["description"]):
            errors.append(f"{display}: source.description must be non-empty")
        reference = source["reference"]
        if reference is not None and (
            not nonempty_string(reference)
            or not re.match(r"^https://", reference)
        ):
            errors.append(f"{display}: source.reference must be null or an HTTPS URL")
        validate_tool(source["generator"], f"{display}: source.generator", errors)
        validate_tool(source["oracle"], f"{display}: source.oracle", errors)
        if reference is None and source["generator"] is None and source["oracle"] is None:
            errors.append(f"{display}: source must identify a reference, generator, or oracle")
        if authority == "authoritative" and reference is None and source["oracle"] is None:
            errors.append(
                f"{display}: authoritative fixtures require an independent reference or oracle"
            )

    license_value = document["license"]
    problem = exact_keys(license_value, {"spdx", "evidence"})
    if problem:
        errors.append(f"{display}: license {problem}")
    else:
        if not isinstance(license_value["spdx"], str) or not SPDX_RE.fullmatch(
            license_value["spdx"]
        ):
            errors.append(f"{display}: license.spdx is not an SPDX expression")
        if not nonempty_string(license_value["evidence"]):
            errors.append(f"{display}: license.evidence must be non-empty")

    expected = document["expected"]
    problem = exact_keys(
        expected,
        {"link_type", "layers", "diagnostic_codes", "exact_rebuild", "valid", "notes"},
    )
    if problem:
        errors.append(f"{display}: expected {problem}")
    else:
        if expected["link_type"] is not None and not is_uint32(expected["link_type"]):
            errors.append(f"{display}: expected.link_type must be null or uint32")
        for field in ("layers", "diagnostic_codes"):
            values = expected[field]
            if not isinstance(values, list) or any(
                not isinstance(item, str) or not PROTOCOL_RE.fullmatch(item) for item in values
            ):
                errors.append(f"{display}: expected.{field} must be a protocol/code array")
            elif len(set(values)) != len(values):
                errors.append(f"{display}: expected.{field} must not contain duplicates")
        if expected["exact_rebuild"] is not None and not isinstance(
            expected["exact_rebuild"], bool
        ):
            errors.append(f"{display}: expected.exact_rebuild must be null or boolean")
        if not isinstance(expected["valid"], bool):
            errors.append(f"{display}: expected.valid must be boolean")
        if not nonempty_string(expected["notes"]):
            errors.append(f"{display}: expected.notes must be non-empty")
        expected_layers = expected["layers"]
        if (
            isinstance(protocols, list)
            and isinstance(expected_layers, list)
            and any(layer not in protocols for layer in expected_layers)
        ):
            errors.append(f"{display}: every expected layer must appear in protocols")
        if isinstance(capture, dict):
            expected_link_type = expected["link_type"]
            capture_link_types = capture.get("link_types")
            if (
                expected_link_type is not None
                and isinstance(capture_link_types, list)
                and expected_link_type not in capture_link_types
            ):
                errors.append(
                    f"{display}: expected.link_type is absent from capture.link_types"
                )
            if kind == "pcap" and (
                capture.get("link_types") != [expected_link_type]
                or capture.get("interfaces")
                != [{"id": 0, "link_type": expected_link_type}]
            ):
                errors.append(
                    f"{display}: classic PCAP requires one interface zero and one link type"
                )
            if kind == "pcapng" and expected["valid"] and not capture.get("interfaces"):
                errors.append(f"{display}: valid PCAPNG requires interface metadata")

    review = document["review"]
    problem = exact_keys(review, {"reviewer", "reviewed_utc", "evidence"})
    if problem:
        errors.append(f"{display}: review {problem}")
    else:
        if not nonempty_string(review["reviewer"]):
            errors.append(f"{display}: review.reviewer must be non-empty")
        if not valid_utc(review["reviewed_utc"]):
            errors.append(f"{display}: review.reviewed_utc must use YYYY-MM-DDTHH:MM:SSZ")
        if not nonempty_string(review["evidence"]) or not review["evidence"].startswith(
            "https://"
        ):
            errors.append(f"{display}: review.evidence must be an HTTPS URL")

    if suffix == ".json":
        try:
            load_json(fixture)
        except (OSError, UnicodeError, json.JSONDecodeError, DuplicateKeyError) as error:
            errors.append(f"{display}: JSON fixture is malformed: {error}")
    elif suffix in {".yaml", ".yml"}:
        try:
            if not fixture.read_text(encoding="utf-8").strip():
                errors.append(f"{display}: YAML fixture is empty")
        except (OSError, UnicodeError) as error:
            errors.append(f"{display}: YAML fixture is not UTF-8: {error}")


def excluded_fixture(path: Path, root: Path) -> bool:
    relative = path.relative_to(root).as_posix()
    return relative == "README.md" or path.name.endswith(".example.json")


def validate_corpus(root: Path) -> tuple[int, list[str]]:
    errors: list[str] = []
    sidecars = sorted(root.rglob(f"*{PROVENANCE_SUFFIX}"))
    fixture_files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and not path.name.endswith(PROVENANCE_SUFFIX)
        and not excluded_fixture(path, root)
    )
    for fixture in fixture_files:
        sidecar = Path(f"{fixture}{PROVENANCE_SUFFIX}")
        if not sidecar.is_file():
            errors.append(
                f"{fixture.relative_to(root).as_posix()}: missing provenance sidecar "
                f"{sidecar.relative_to(root).as_posix()}"
            )
    for sidecar in sidecars:
        validate_provenance(root, sidecar, errors)
    return len(sidecars), errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("tests/fixtures"))
    parser.add_argument("--quiet", action="store_true")
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    if not root.is_dir():
        print(f"fixture root does not exist: {root}", file=sys.stderr)
        return 2
    count, errors = validate_corpus(root)
    if errors:
        for error in errors:
            print(f"fixture provenance error: {error}", file=sys.stderr)
        print(f"fixture corpus validation failed with {len(errors)} error(s)", file=sys.stderr)
        return 1
    if not arguments.quiet:
        print(f"validated {count} fixture provenance sidecar(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
