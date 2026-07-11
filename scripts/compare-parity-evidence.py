#!/usr/bin/env python3
"""Compare all four PacketcraftR platform parity evidence documents."""

# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path
from typing import Any


EVIDENCE_SCHEMA = "packetcraftr.parity-evidence/v1"
COMPARISON_SCHEMA = "packetcraftr.parity-comparison/v1"
EXPECTED_PLATFORMS = {
    "linux-x86_64",
    "macos-arm64",
    "macos-x86_64",
    "windows-x86_64",
}


class ComparisonError(RuntimeError):
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


def validate_report(path: Path) -> tuple[dict[str, Any], dict[str, str]]:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ComparisonError(f"invalid evidence document {path}") from error
    if (
        not isinstance(report, dict)
        or report.get("schema") != EVIDENCE_SCHEMA
        or report.get("status") != "pass"
        or report.get("platform") not in EXPECTED_PLATFORMS
    ):
        raise ComparisonError(f"invalid parity evidence envelope {path}")
    required = report.get("required_coverage")
    observed = report.get("observed_coverage")
    if (
        not isinstance(required, list)
        or not isinstance(observed, list)
        or not set(required).issubset(set(observed))
    ):
        raise ComparisonError(f"incomplete coverage in {path}")
    cases = report.get("cases")
    if not isinstance(cases, list) or report.get("case_count") != len(cases):
        raise ComparisonError(f"invalid parity case count in {path}")
    case_hashes: dict[str, str] = {}
    for case in cases:
        if not isinstance(case, dict):
            raise ComparisonError(f"invalid parity case in {path}")
        case_id = case.get("id")
        recorded = case.get("sha256")
        comparable = {
            "kind": case.get("kind"),
            "coverage": case.get("coverage"),
            "value": case.get("value"),
        }
        actual = digest_bytes(canonical(comparable))
        if (
            not isinstance(case_id, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", case_id)
            or not isinstance(recorded, str)
            or recorded != actual
            or case_id in case_hashes
        ):
            raise ComparisonError(f"invalid or duplicate parity case in {path}: {case_id!r}")
        case_hashes[case_id] = recorded
    manifest_sha256 = report.get("manifest_sha256")
    if not isinstance(manifest_sha256, str):
        raise ComparisonError(f"missing manifest identity in {path}")
    corpus_sha256 = digest_bytes(
        canonical({"manifest_sha256": manifest_sha256, "cases": case_hashes})
    )
    if report.get("corpus_sha256") != corpus_sha256:
        raise ComparisonError(f"invalid corpus digest in {path}")
    candidate = report.get("candidate")
    required_candidate_fields = {
        "commit",
        "version",
        "archive",
        "archive_sha256",
        "binary_sha256",
        "rust",
        "feature_profile",
    }
    if not isinstance(candidate, dict) or not required_candidate_fields.issubset(candidate):
        raise ComparisonError(f"incomplete candidate identity in {path}")
    return report, case_hashes


def create_bundle(output: Path, bundle: Path) -> None:
    bundle = bundle.resolve()
    bundle.parent.mkdir(parents=True, exist_ok=True)
    if bundle == output or output in bundle.parents:
        raise ComparisonError("comparison bundle must be outside the output directory")
    with tarfile.open(bundle, "w:gz") as archive:
        archive.add(output, arcname=output.name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-root", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args()

    output = args.output.resolve()
    try:
        if not re.fullmatch(r"[0-9a-f]{40}", args.expected_commit):
            raise ComparisonError("--expected-commit must be a full lowercase Git SHA")
        artifacts_root = args.artifacts_root.resolve(strict=True)
        documents = sorted(artifacts_root.glob("**/parity-evidence.json"))
        if len(documents) != len(EXPECTED_PLATFORMS):
            raise ComparisonError(
                f"expected {len(EXPECTED_PLATFORMS)} evidence documents, found {len(documents)}"
            )
        if output.exists() and any(output.iterdir()):
            raise ComparisonError(f"output directory must be absent or empty: {output}")
        output.mkdir(parents=True, exist_ok=True)

        reports: dict[str, tuple[Path, dict[str, Any], dict[str, str]]] = {}
        for path in documents:
            report, hashes = validate_report(path)
            platform_id = report["platform"]
            if platform_id in reports:
                raise ComparisonError(f"duplicate evidence for {platform_id}")
            reports[platform_id] = (path, report, hashes)
        if set(reports) != EXPECTED_PLATFORMS:
            raise ComparisonError(
                f"platform evidence set differs: {sorted(reports)}"
            )

        baseline_id = "linux-x86_64"
        _, baseline, baseline_hashes = reports[baseline_id]
        baseline_candidate = baseline["candidate"]
        comparable_candidate_fields = (
            "commit",
            "version",
            "archive",
            "archive_sha256",
            "rust",
            "feature_profile",
        )
        if baseline_candidate["commit"] != args.expected_commit:
            raise ComparisonError("baseline evidence is not for the expected commit")
        for platform_id, (_, report, hashes) in sorted(reports.items()):
            candidate = report["candidate"]
            for field in comparable_candidate_fields:
                if candidate[field] != baseline_candidate[field]:
                    raise ComparisonError(
                        f"{platform_id} candidate {field} differs from {baseline_id}"
                    )
            if report["manifest_sha256"] != baseline["manifest_sha256"]:
                raise ComparisonError(f"{platform_id} used a different corpus manifest")
            if hashes != baseline_hashes:
                missing = sorted(set(baseline_hashes) - set(hashes))
                extra = sorted(set(hashes) - set(baseline_hashes))
                changed = sorted(
                    case_id
                    for case_id in set(hashes) & set(baseline_hashes)
                    if hashes[case_id] != baseline_hashes[case_id]
                )
                raise ComparisonError(
                    f"{platform_id} parity mismatch: missing={missing}, extra={extra}, "
                    f"changed={changed}"
                )
            if report["corpus_sha256"] != baseline["corpus_sha256"]:
                raise ComparisonError(f"{platform_id} corpus digest differs")

        platform_rows = []
        for platform_id, (path, report, _) in sorted(reports.items()):
            platform_rows.append(
                {
                    "platform": platform_id,
                    "evidence_sha256": digest_file(path),
                    "binary_sha256": report["candidate"]["binary_sha256"],
                    "host": report["host"],
                    "case_count": report["case_count"],
                }
            )
        comparison = {
            "schema": COMPARISON_SCHEMA,
            "status": "pass",
            "candidate": {
                field: baseline_candidate[field]
                for field in comparable_candidate_fields
            },
            "manifest_sha256": baseline["manifest_sha256"],
            "corpus_sha256": baseline["corpus_sha256"],
            "case_count": len(baseline_hashes),
            "case_hashes": baseline_hashes,
            "platforms": platform_rows,
        }
        write_json(output / "parity-comparison.json", comparison)
        if args.bundle:
            create_bundle(output, args.bundle)
        print(
            f"four-platform parity passed: {len(baseline_hashes)} cases, "
            f"corpus sha256:{baseline['corpus_sha256']}"
        )
        return 0
    except (OSError, KeyError, TypeError, ValueError, ComparisonError) as error:
        output.mkdir(parents=True, exist_ok=True)
        write_json(
            output / "failure.json",
            {
                "schema": "packetcraftr.parity-comparison-failure/v1",
                "error": str(error),
            },
        )
        print(f"parity comparison failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
