#!/usr/bin/env python3
"""Verify hosted Windows x86_64 MSVC qualification evidence."""

# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


EXPECTED_WIRE = {
    "ipv4_udp": "450000260201000040118c8fc0000201c63364029c4000090012562c0001027f80ffdeadbeef",  # pragma: allowlist secret
    "ipv6_udp": "600008030012114020010db800000000000000000000000120010db80000000000000000000000029c4100090012e6ed0001027f80ffdeadbeef",  # pragma: allowlist secret
    "stacked_vlan": "02510000010902510000010288a80064810000c808004500002a01ff0000401162540a3301020a330109abe023280016fa9177696e646f77732d706172697479",  # pragma: allowlist secret
}


class EvidenceError(ValueError):
    pass


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise EvidenceError(f"{path.name} is not a JSON object")
    return value


def success(root: Path, name: str, command: str) -> dict[str, object]:
    value = load_json(root / name)
    if (
        value.get("schema") != "packetcraftr.output/v1"
        or value.get("command") != command
        or value.get("status") != "success"
        or not isinstance(value.get("result"), dict)
    ):
        raise EvidenceError(f"{name} is not a successful {command} result")
    return value["result"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        root = args.evidence.resolve(strict=True)
        metadata = load_json(root / "metadata.json")
        if (
            metadata.get("platform") != "windows"
            or metadata.get("architecture") != "x86_64-msvc"
            or metadata.get("input_kind") != "archive"
            or metadata.get("npcap_runtime") != "absent-hosted-boundary"
            or not re.fullmatch(r"[0-9a-f]{40}", str(metadata.get("candidate_commit", "")))
        ):
            raise EvidenceError("metadata does not identify the exact hosted Windows boundary")

        interfaces = success(root, "interfaces.json", "interfaces").get("interfaces")
        if not isinstance(interfaces, list) or not any(
            isinstance(item, dict)
            and isinstance(item.get("flags"), dict)
            and item["flags"].get("loopback")
            and item["flags"].get("up")
            for item in interfaces
        ):
            raise EvidenceError("native Windows interface inventory omitted loopback")
        success(root, "routes.json", "routes")

        rows: list[dict[str, str]] = []
        for family in ("ipv4", "ipv6"):
            plan = success(root, f"plan-{family}.json", "plan").get("route")
            if not isinstance(plan, dict) or plan.get("mode") != "layer3":
                raise EvidenceError(f"{family} plan did not retain raw Layer 3 mode")
            route = plan.get("route")
            if not isinstance(route, dict) or route.get("selection_reason") != "local":
                raise EvidenceError(f"{family} plan did not use a native local route")
            rows.append({"case": f"get-best-route2-{family}", "status": "pass"})
            sent = success(root, f"send-layer3-{family}.json", "send")
            frame = sent.get("frame")
            route = sent.get("route")
            if (
                not isinstance(frame, dict)
                or not frame.get("bytes_hex")
                or not isinstance(route, dict)
                or not isinstance(route.get("plan"), dict)
                or route["plan"].get("mode") != "layer3"
            ):
                raise EvidenceError(f"{family} raw send omitted exact Layer 3 evidence")
            rows.append({"case": f"winsock-raw-{family}", "status": "pass"})

        missing_exit = int((root / "missing-npcap.exit").read_text(encoding="utf-8").strip())
        records = [
            json.loads(line)
            for line in (root / "missing-npcap.ndjson").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if not records or not isinstance(records[-1], dict):
            raise EvidenceError("missing-Npcap preflight has no structured error")
        error = records[-1].get("error")
        if (
            missing_exit != 4
            or not isinstance(error, dict)
            or error.get("code") != "capability.missing_dependency"
            or "Npcap 1.88" not in str(error.get("message", ""))
            or "native dependency" not in str(error.get("message", ""))
        ):
            raise EvidenceError("missing Npcap was not an actionable capability error")
        rows.append({"case": "npcap-missing-no-fallback", "status": "pass"})

        dependency_tree = (root / "native-dependencies.txt").read_text(
            encoding="utf-8", errors="replace"
        )
        for dependency in ("libloading ", "socket2 ", "windows "):
            if not any(line.startswith(dependency) for line in dependency_tree.splitlines()):
                raise EvidenceError(f"native dependency tree omitted {dependency.strip()}")
        if any(
            line.startswith(("pcap ", "pnet ", "pnet_"))
            for line in dependency_tree.splitlines()
        ):
            raise EvidenceError("Windows native profile statically resolved pcap/pnet")
        pe_dependencies = (root / "pe-dependencies.txt").read_text(
            encoding="utf-8", errors="replace"
        ).casefold()
        if "wpcap.dll" in pe_dependencies or "packet.dll" in pe_dependencies:
            raise EvidenceError("candidate PE imports Npcap instead of loading it at runtime")
        rows.append({"case": "msvc-dynamic-npcap-boundary", "status": "pass"})

        baseline = load_json(root / "wire-baseline.json")
        for name, expected in EXPECTED_WIRE.items():
            value = baseline.get(name)
            if not isinstance(value, dict) or value.get("bytes_hex") != expected:
                raise EvidenceError(f"{name} differs from the portable exact-byte baseline")
            rows.append({"case": f"wire-parity-{name}", "status": "pass"})

        report = {
            "schema": "packetcraftr.windows-hosted-qualification/v1",
            "status": "pass",
            "candidate_commit": metadata["candidate_commit"],
            "archive_sha256": metadata["archive_sha256"],
            "binary_sha256": metadata["binary_sha256"],
            "runner_image": metadata.get("runner_image"),
            "runner_image_version": metadata.get("runner_image_version"),
            "matrix": rows,
            "matrix_rows": len(rows),
            "boundary": "hosted-msvc-without-npcap-runtime",
        }
        (root / "report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"Windows hosted evidence passed {len(rows)} semantic matrix rows")
    except (EvidenceError, KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Windows hosted evidence verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
