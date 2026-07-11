#!/usr/bin/env python3
"""Generate deterministic offline parity evidence from an exact candidate archive."""

# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA = "packetcraftr.parity-evidence/v1"
CORPUS_SCHEMA = "packetcraftr.parity-corpus/v1"
PLATFORMS = {
    "linux-x86_64": ("Linux", "x86_64"),
    "macos-arm64": ("Darwin", "arm64"),
    "macos-x86_64": ("Darwin", "x86_64"),
    "windows-x86_64": ("Windows", "x86_64"),
}
REQUIRED_CAPTURE_ROOTS = {0, 1, 12, 101, 108, 113, 147, 228, 229, 276}


class ParityError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def normalize_architecture(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"amd64", "x64", "x86-64", "x86_64"}:
        return "x86_64"
    if normalized in {"aarch64", "arm64"}:
        return "arm64"
    return normalized


def verify_host(platform_id: str) -> None:
    expected_system, expected_architecture = PLATFORMS[platform_id]
    actual_system = platform.system()
    actual_architecture = normalize_architecture(platform.machine())
    if (actual_system, actual_architecture) != (
        expected_system,
        expected_architecture,
    ):
        raise ParityError(
            f"platform {platform_id} requires {expected_system}/{expected_architecture}, "
            f"got {actual_system}/{actual_architecture}"
        )
    if sys.maxsize <= 2**32:
        raise ParityError("parity qualification requires a native 64-bit Python process")


def locate_candidate(directory: Path) -> tuple[Path, Path]:
    directory = directory.resolve(strict=True)
    archives = sorted(directory.glob("packetcraftr-workspace-*.tar.gz"))
    if len(archives) != 1:
        raise ParityError(
            f"expected one candidate archive in {directory}, found {len(archives)}"
        )
    checksums = directory / "SHA256SUMS"
    if not checksums.is_file():
        raise ParityError(f"candidate checksum manifest is missing: {checksums}")
    return archives[0], checksums


def verify_archive(archive: Path, checksums: Path) -> str:
    rows: dict[str, str] = {}
    for row in checksums.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", row)
        if match:
            rows[match.group(2)] = match.group(1)
    actual = digest_file(archive)
    if rows.get(archive.name) != actual:
        raise ParityError("candidate archive checksum does not match SHA256SUMS")
    return actual


def extract_candidate(archive: Path, destination: Path) -> Path:
    destination_resolved = destination.resolve()
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        if not members:
            raise ParityError("candidate archive is empty")
        for member in members:
            name = PurePosixPath(member.name)
            if (
                name.is_absolute()
                or ".." in name.parts
                or member.issym()
                or member.islnk()
                or not (member.isfile() or member.isdir())
            ):
                raise ParityError(f"candidate archive has unsafe member {member.name!r}")
            target = (destination / Path(*name.parts)).resolve()
            if target != destination_resolved and destination_resolved not in target.parents:
                raise ParityError(
                    f"candidate archive escapes extraction root: {member.name!r}"
                )
        source.extractall(destination, members=members, filter="data")
    roots = [item for item in destination.iterdir() if item.is_dir()]
    if len(roots) != 1:
        raise ParityError("candidate archive must contain exactly one workspace root")
    return roots[0]


def run(
    command: list[str],
    *,
    cwd: Path,
    expected: tuple[int, ...] = (0,),
    timeout: int = 1800,
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment["CARGO_TERM_COLOR"] = "never"
    result = subprocess.run(
        command,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
        env=environment,
    )
    if result.returncode not in expected:
        diagnostic = result.stderr.decode("utf-8", errors="replace")[-4000:]
        raise ParityError(
            f"command exited {result.returncode}, expected {expected}: {command!r}\n"
            f"{diagnostic}"
        )
    return result


def run_logged(command: list[str], *, cwd: Path, log: Path) -> None:
    result = run(command, cwd=cwd)
    log.write_bytes(result.stdout + result.stderr)


def parse_json_output(result: subprocess.CompletedProcess[bytes], command: str) -> dict[str, Any]:
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ParityError(f"{command} did not emit one UTF-8 JSON document") from error
    if not isinstance(value, dict) or value.get("schema") != "packetcraftr.output/v1":
        raise ParityError(f"{command} emitted an invalid output envelope")
    if value.get("command") != command:
        raise ParityError(f"{command} output identified another command")
    return value


def parse_ndjson_output(result: subprocess.CompletedProcess[bytes], command: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in result.stdout.decode("utf-8").splitlines():
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ParityError(f"{command} emitted invalid NDJSON") from error
        if (
            not isinstance(value, dict)
            or value.get("schema") != "packetcraftr.output/v1"
            or value.get("command") != command
            or value.get("sequence") != len(records)
        ):
            raise ParityError(f"{command} emitted an invalid stream envelope")
        records.append(value)
    if not records:
        raise ParityError(f"{command} emitted no stream records")
    return records


def normalized_envelope(value: dict[str, Any]) -> dict[str, Any]:
    status = value.get("status")
    diagnostics = value.get("diagnostics", [])
    if status == "success" and isinstance(value.get("result"), dict):
        return {
            "status": "success",
            "result": value["result"],
            "diagnostics": diagnostics,
        }
    error = value.get("error")
    if status == "error" and isinstance(error, dict):
        return {
            "status": "error",
            "error": {
                "code": error.get("code"),
                "kind": error.get("kind"),
            },
            "diagnostics": [
                item.get("code") for item in diagnostics if isinstance(item, dict)
            ],
        }
    raise ParityError("output envelope has neither a typed success nor typed error")


def successful_build(
    binary: Path,
    workspace: Path,
    *,
    expression: str | None = None,
    document: Path | None = None,
    mode: str = "strict",
) -> dict[str, Any]:
    arguments = [str(binary), "--output", "json", "build", "--mode", mode]
    if expression is not None and document is None:
        arguments += ["--packet", expression]
    elif document is not None and expression is None:
        arguments += ["--packet-file", str(document)]
    else:
        raise ParityError("a build case must supply exactly one packet source")
    envelope = parse_json_output(run(arguments, cwd=workspace), "build")
    if envelope.get("status") != "success":
        raise ParityError(f"parity build failed: {envelope.get('error')!r}")
    return normalized_envelope(envelope)


def add_case(
    cases: list[dict[str, Any]],
    coverage: set[str],
    *,
    case_id: str,
    kind: str,
    tags: list[str],
    value: Any,
) -> None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", case_id):
        raise ParityError(f"invalid parity case id {case_id!r}")
    if any(existing["id"] == case_id for existing in cases):
        raise ParityError(f"duplicate parity case id {case_id!r}")
    tags = sorted(set(tags))
    coverage.update(tags)
    comparable = {"kind": kind, "coverage": tags, "value": value}
    cases.append(
        {
            "id": case_id,
            **comparable,
            "sha256": digest_bytes(canonical(comparable)),
        }
    )


def fixture_path(sidecar: Path) -> Path:
    suffix = ".provenance.json"
    if not sidecar.name.endswith(suffix):
        raise ParityError(f"invalid provenance filename {sidecar}")
    return sidecar.with_name(sidecar.name[: -len(suffix)])


def verify_fixture(sidecar: Path, workspace: Path) -> tuple[Path, dict[str, Any]]:
    provenance = json.loads(sidecar.read_text(encoding="utf-8"))
    if not isinstance(provenance, dict):
        raise ParityError(f"invalid provenance document {sidecar}")
    fixture = fixture_path(sidecar)
    if not fixture.is_file() or digest_file(fixture) != provenance.get("sha256"):
        raise ParityError(f"fixture hash differs from provenance: {fixture}")
    relative = fixture.relative_to(workspace / "tests" / "fixtures").as_posix()
    if provenance.get("fixture") != relative:
        raise ParityError(f"fixture path differs from provenance: {fixture}")
    return fixture, provenance


def record_packet_cases(
    binary: Path,
    workspace: Path,
    manifest: dict[str, Any],
    cases: list[dict[str, Any]],
    coverage: set[str],
) -> dict[str, str]:
    expressions: dict[str, str] = {}
    for item in manifest.get("packet_cases", []):
        if not isinstance(item, dict):
            raise ParityError("packet case must be an object")
        case_id = item.get("id")
        expression = item.get("expression")
        tags = item.get("coverage")
        if not isinstance(case_id, str) or not isinstance(expression, str) or not isinstance(tags, list):
            raise ParityError("packet case has invalid id, expression, or coverage")
        value = successful_build(binary, workspace, expression=expression)
        add_case(cases, coverage, case_id=case_id, kind="packet", tags=tags, value=value)
        expressions[case_id] = expression
    return expressions


def record_document_cases(
    binary: Path,
    workspace: Path,
    manifest: dict[str, Any],
    cases: list[dict[str, Any]],
    coverage: set[str],
) -> None:
    for item in manifest.get("document_cases", []):
        if not isinstance(item, dict):
            raise ParityError("document case must be an object")
        case_id = item.get("id")
        relative = item.get("path")
        tags = item.get("coverage")
        mode = item.get("mode", "strict")
        if (
            not isinstance(case_id, str)
            or not isinstance(relative, str)
            or not isinstance(tags, list)
            or mode not in {"strict", "permissive"}
        ):
            raise ParityError("document case has invalid fields")
        document = (workspace / relative).resolve(strict=True)
        if workspace.resolve() not in document.parents:
            raise ParityError(f"document case escapes the workspace: {relative}")
        value = successful_build(binary, workspace, document=document, mode=mode)
        add_case(cases, coverage, case_id=case_id, kind="document", tags=tags, value=value)


def record_frame_fixtures(
    binary: Path,
    workspace: Path,
    cases: list[dict[str, Any]],
    coverage: set[str],
) -> None:
    roots: set[int] = set()
    sidecars = sorted((workspace / "tests" / "fixtures" / "frames").glob("**/*.bin.provenance.json"))
    if not sidecars:
        raise ParityError("authoritative frame corpus is empty")
    for sidecar in sidecars:
        fixture, provenance = verify_fixture(sidecar, workspace)
        expected = provenance.get("expected")
        if not isinstance(expected, dict) or not isinstance(expected.get("link_type"), int):
            raise ParityError(f"frame provenance lacks a numeric link type: {sidecar}")
        link_type = expected["link_type"]
        roots.add(link_type)
        result = run(
            [
                str(binary),
                "--output",
                "json",
                "dissect",
                "--file",
                str(fixture),
                "--link-type",
                str(link_type),
            ],
            cwd=workspace,
        )
        envelope = parse_json_output(result, "dissect")
        if envelope.get("status") != "success":
            raise ParityError(f"frame fixture did not dissect: {fixture}")
        relative = fixture.relative_to(workspace / "tests" / "fixtures").as_posix()
        tags = [str(value) for value in provenance.get("protocols", [])]
        if expected.get("valid") is False:
            tags.append("malformed")
        add_case(
            cases,
            coverage,
            case_id="frame-" + relative.removesuffix(".bin").replace("/", "-"),
            kind="frame_fixture",
            tags=tags,
            value={
                "fixture_sha256": provenance["sha256"],
                "link_type": link_type,
                "output": normalized_envelope(envelope),
            },
        )
    if roots != REQUIRED_CAPTURE_ROOTS:
        raise ParityError(
            f"capture root corpus differs from the stable set: {sorted(roots)}"
        )
    coverage.add("all_capture_roots")


def read_capture(binary: Path, workspace: Path, path: Path) -> tuple[int, list[dict[str, Any]]]:
    result = run(
        [str(binary), "--output", "ndjson", "read", str(path)],
        cwd=workspace,
        expected=(0, 3, 6),
    )
    return result.returncode, parse_ndjson_output(result, "read")


def normalized_stream(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [normalized_envelope(record) for record in records]


def record_capture_fixtures(
    binary: Path,
    workspace: Path,
    temporary: Path,
    cases: list[dict[str, Any]],
    coverage: set[str],
) -> None:
    capture_root = workspace / "tests" / "fixtures" / "captures"
    sidecars = sorted(capture_root.glob("**/*.provenance.json"))
    if not sidecars:
        raise ParityError("capture corpus is empty")
    formats = temporary / "capture-formats"
    formats.mkdir()
    for sidecar in sidecars:
        fixture, provenance = verify_fixture(sidecar, workspace)
        expected = provenance.get("expected")
        if not isinstance(expected, dict) or not isinstance(expected.get("valid"), bool):
            raise ParityError(f"capture provenance lacks validity: {sidecar}")
        relative = fixture.relative_to(capture_root).as_posix()
        returncode, records = read_capture(binary, workspace, fixture)
        value: dict[str, Any] = {
            "fixture_sha256": provenance["sha256"],
            "stream": normalized_stream(records),
        }
        tags = ["capture_pcapng" if fixture.suffix == ".pcapng" else "capture_pcap"]
        if expected["valid"]:
            if returncode != 0 or any(record.get("status") != "success" for record in records):
                raise ParityError(f"valid capture fixture failed: {fixture}")
            transcodes: dict[str, Any] = {}
            requested_formats = ["pcapng"]
            link_types = provenance.get("capture", {}).get("link_types", [])
            if isinstance(link_types, list) and len(set(link_types)) == 1:
                requested_formats.append("pcap")
            for output_format in requested_formats:
                output = formats / f"{len(cases)}.{output_format}"
                encoded = run(
                    [str(binary), "--output", output_format, "read", str(fixture)],
                    cwd=workspace,
                ).stdout
                output.write_bytes(encoded)
                transcode_returncode, transcoded_records = read_capture(
                    binary, workspace, output
                )
                if transcode_returncode != 0:
                    raise ParityError(f"{output_format} transcode could not be read")
                transcodes[output_format] = {
                    "sha256": digest_bytes(encoded),
                    "stream": normalized_stream(transcoded_records),
                }
            value["transcodes"] = transcodes
        else:
            tags.append("capture_malformed")
            if returncode == 0 or records[-1].get("status") != "error":
                raise ParityError(f"malformed capture fixture was accepted: {fixture}")
        add_case(
            cases,
            coverage,
            case_id="capture-" + relative.replace("/", "-").replace(".", "-"),
            kind="capture_fixture",
            tags=tags,
            value=value,
        )


def record_fuzz_cases(
    binary: Path,
    workspace: Path,
    manifest: dict[str, Any],
    expressions: dict[str, str],
    cases: list[dict[str, Any]],
    coverage: set[str],
) -> None:
    for item in manifest.get("fuzz_cases", []):
        if not isinstance(item, dict):
            raise ParityError("fuzz case must be an object")
        case_id = item.get("id")
        packet_case = item.get("packet_case")
        tags = item.get("coverage")
        if not isinstance(case_id, str) or not isinstance(packet_case, str) or not isinstance(tags, list):
            raise ParityError("fuzz case has invalid fields")
        expression = expressions.get(packet_case)
        if expression is None:
            raise ParityError(f"fuzz case references unknown packet case {packet_case!r}")
        arguments = [
            str(binary),
            "--output",
            "json",
            "fuzz",
            "--packet",
            expression,
            "--seed",
            str(item.get("seed")),
            "--first-case",
            str(item.get("first_case", 0)),
            "--cases",
            str(item.get("cases")),
            "--strategy",
            str(item.get("strategy")),
            "--mode",
            str(item.get("mode", "strict")),
        ]
        envelope = parse_json_output(run(arguments, cwd=workspace), "fuzz")
        if envelope.get("status") != "success":
            raise ParityError(f"offline fuzz case failed: {case_id}")
        add_case(
            cases,
            coverage,
            case_id=case_id,
            kind="offline_fuzz",
            tags=tags,
            value=normalized_envelope(envelope),
        )


def create_bundle(evidence: Path, bundle: Path) -> None:
    bundle = bundle.resolve()
    bundle.parent.mkdir(parents=True, exist_ok=True)
    if bundle == evidence or evidence in bundle.parents:
        raise ParityError("evidence bundle must be outside the evidence directory")
    with tarfile.open(bundle, "w:gz") as archive:
        archive.add(evidence, arcname=evidence.name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--candidate-directory", type=Path)
    source.add_argument("--archive", type=Path)
    parser.add_argument("--checksums", type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args()

    evidence = args.evidence.resolve()
    temporary: Path | None = None
    try:
        verify_host(args.platform)
        if not re.fullmatch(r"[0-9a-f]{40}", args.expected_commit):
            raise ParityError("--expected-commit must be a full lowercase Git SHA")
        if evidence.exists() and any(evidence.iterdir()):
            raise ParityError(f"evidence directory must be absent or empty: {evidence}")
        evidence.mkdir(parents=True, exist_ok=True)

        if args.candidate_directory:
            archive, checksums = locate_candidate(args.candidate_directory)
        else:
            archive = args.archive.resolve(strict=True)
            if args.checksums is None:
                raise ParityError("--checksums is required with --archive")
            checksums = args.checksums.resolve(strict=True)
        archive_sha256 = verify_archive(archive, checksums)

        temporary = Path(tempfile.mkdtemp(prefix="packetcraftr-parity-"))
        workspace = extract_candidate(archive, temporary / "candidate")
        release = tomllib.loads(
            (workspace / "RELEASE-METADATA.toml").read_text(encoding="utf-8")
        )
        cargo = tomllib.loads((workspace / "Cargo.toml").read_text(encoding="utf-8"))
        if release.get("commit") != args.expected_commit:
            raise ParityError(
                f"archive commit {release.get('commit')!r} differs from {args.expected_commit}"
            )
        version = cargo["workspace"]["package"]["version"]
        if release.get("version") != version:
            raise ParityError("archive release and Cargo versions differ")

        rust_version = run(["rustc", "--version"], cwd=workspace).stdout.decode().strip()
        if not rust_version.startswith("rustc 1.96.0 "):
            raise ParityError(f"Rust 1.96.0 is required, got {rust_version}")

        run_logged(
            [
                "cargo",
                "build",
                "--locked",
                "--release",
                "--no-default-features",
                "--bin",
                "packetcraftr",
            ],
            cwd=workspace,
            log=evidence / "build.log",
        )
        run_logged(
            ["cargo", "test", "--locked", "--workspace", "--no-default-features"],
            cwd=workspace,
            log=evidence / "tests.log",
        )
        run_logged(
            [
                "cargo",
                "test",
                "--locked",
                "--no-default-features",
                "--test",
                "external_protocol",
            ],
            cwd=workspace,
            log=evidence / "external-protocol.log",
        )
        executable = "packetcraftr.exe" if os.name == "nt" else "packetcraftr"
        binary = workspace / "target" / "release" / executable
        if not binary.is_file():
            raise ParityError("portable release binary was not built")
        version_output = run([str(binary), "--version"], cwd=workspace).stdout.decode().strip()
        if version_output != f"packetcraftr {version}":
            raise ParityError(f"candidate binary version mismatch: {version_output!r}")

        manifest_path = workspace / "tests" / "parity" / "manifest.json"
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        if not isinstance(manifest, dict) or manifest.get("schema") != CORPUS_SCHEMA:
            raise ParityError("parity corpus manifest has an unsupported schema")
        required_coverage = manifest.get("required_coverage")
        if not isinstance(required_coverage, list) or not all(
            isinstance(value, str) for value in required_coverage
        ):
            raise ParityError("parity corpus required_coverage must be a string list")

        cases: list[dict[str, Any]] = []
        coverage: set[str] = set()
        expressions = record_packet_cases(
            binary, workspace, manifest, cases, coverage
        )
        record_document_cases(binary, workspace, manifest, cases, coverage)
        record_frame_fixtures(binary, workspace, cases, coverage)
        record_capture_fixtures(binary, workspace, temporary, cases, coverage)
        record_fuzz_cases(
            binary, workspace, manifest, expressions, cases, coverage
        )
        add_case(
            cases,
            coverage,
            case_id="external-protocol-module",
            kind="external_codec",
            tags=["external_codec"],
            value={
                "test_target": "external_protocol",
                "feature_profile": "no-default-features",
                "passed": True,
            },
        )

        missing = sorted(set(required_coverage) - coverage)
        if missing:
            raise ParityError(f"parity corpus did not exercise required coverage: {missing}")
        cases.sort(key=lambda item: item["id"])
        case_hashes = {item["id"]: item["sha256"] for item in cases}
        corpus_sha256 = digest_bytes(
            canonical(
                {
                    "manifest_sha256": digest_bytes(manifest_bytes),
                    "cases": case_hashes,
                }
            )
        )
        report = {
            "schema": SCHEMA,
            "status": "pass",
            "platform": args.platform,
            "host": {
                "system": platform.system(),
                "architecture": normalize_architecture(platform.machine()),
                "python": platform.python_version(),
            },
            "candidate": {
                "commit": args.expected_commit,
                "version": version,
                "archive": archive.name,
                "archive_sha256": archive_sha256,
                "binary_sha256": digest_file(binary),
                "rust": rust_version,
                "feature_profile": "no-default-features",
            },
            "manifest_sha256": digest_bytes(manifest_bytes),
            "required_coverage": sorted(required_coverage),
            "observed_coverage": sorted(coverage),
            "case_count": len(cases),
            "cases": cases,
            "corpus_sha256": corpus_sha256,
        }
        write_json(evidence / "parity-evidence.json", report)
        shutil.copyfile(manifest_path, evidence / "manifest.json")
        if args.bundle:
            create_bundle(evidence, args.bundle)
        print(
            f"{args.platform}: {len(cases)} parity cases, corpus sha256:{corpus_sha256}"
        )
        return 0
    except (OSError, KeyError, ValueError, ParityError, subprocess.TimeoutExpired) as error:
        evidence.mkdir(parents=True, exist_ok=True)
        write_json(
            evidence / "failure.json",
            {
                "schema": "packetcraftr.parity-failure/v1",
                "platform": args.platform,
                "error": str(error),
            },
        )
        print(f"parity evidence generation failed: {error}", file=sys.stderr)
        return 1
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
