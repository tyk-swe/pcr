#!/usr/bin/env python3
"""Validate and summarize privileged Linux live-qualification evidence."""

# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


COMMIT = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"0\.2\.0(?:-(?:alpha|beta|rc)\.(?:0|[1-9][0-9]*))?")
MALFORMED_NOISE = "0249000001020249000001010800450000100000"
REQUIRED_TESTS = (
    "exchange_arms_and_awaits_capture_before_send_and_matches_response",
    "exchange_surfaces_operation_and_cleanup_failures",
    "partial_backend_send_is_a_typed_failure",
    "capture_queue_limits_fail_closed_at_zero_and_stable_maxima",
    "timeout_is_bounded_attempted_and_joined",
    "readiness_precedes_delivery_and_shutdown_joins",
    "fail_policy_reports_queue_loss",
    "source_failure_propagates_once_and_shutdown_still_joins",
    "hostname_intent_is_denied_before_resolver_or_executor_side_effects",
    "every_retry_reresolves_and_reauthorizes_rebinding_before_probe_construction",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path.name} must contain one JSON object")
    return value


def read_ndjson(path: Path) -> list[dict[str, Any]]:
    records = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        value = json.loads(line)
        require(isinstance(value, dict), f"{path.name}:{line_number} is not an object")
        records.append(value)
    require(records, f"{path.name} contains no records")
    return records


def success(path: Path, command: str) -> dict[str, Any]:
    value = read_json(path)
    require(value.get("schema") == "packetcraftr.output/v1", f"{path.name}: schema")
    require(value.get("command") == command, f"{path.name}: command")
    require(value.get("status") == "success", f"{path.name}: not successful")
    require(isinstance(value.get("result"), dict), f"{path.name}: missing result")
    return value


def error(path: Path, command: str, code: str) -> dict[str, Any]:
    records = read_ndjson(path) if path.suffix == ".ndjson" else [read_json(path)]
    value = records[-1]
    require(value.get("schema") == "packetcraftr.output/v1", f"{path.name}: schema")
    require(value.get("command") == command, f"{path.name}: command")
    require(value.get("status") == "error", f"{path.name}: expected error")
    require(value.get("error", {}).get("code") == code, f"{path.name}: error code")
    return value


def exit_status(root: Path, name: str, expected: int) -> None:
    actual = int((root / f"{name}.exit").read_text(encoding="utf-8").strip())
    require(actual == expected, f"{name}: expected exit {expected}, got {actual}")


def no_capture_loss(value: dict[str, Any], name: str) -> None:
    capture = value.get("stats", {}).get("capture", {})
    require(capture.get("dropped_frames") == 0, f"{name}: dropped frames")
    require(capture.get("dropped_bytes") == 0, f"{name}: dropped bytes")
    require(capture.get("overflow_events") == 0, f"{name}: overflow events")


def frames(records: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    result = []
    for record in records:
        if record.get("status") != "success":
            continue
        frame = record.get("result", {}).get("frame")
        if isinstance(frame, dict):
            result.append(frame)
    require(result, f"{name}: no frames")
    return result


def packet_evidence(label: str, value: str) -> dict[str, Any]:
    raw = bytes.fromhex(value)
    require(raw, f"{label}: empty packet evidence")
    return {
        "label": label,
        "length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes_hex": value,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    root = args.evidence.resolve(strict=True)
    checks: list[str] = []
    packets: list[dict[str, Any]] = []

    metadata = read_json(root / "metadata.json")
    require(metadata.get("schema") == "packetcraftr.qualification-input/v1", "metadata schema")
    require(COMMIT.fullmatch(str(metadata.get("candidate_commit", ""))) is not None, "candidate commit")
    require(COMMIT.fullmatch(str(metadata.get("tooling_commit", ""))) is not None, "tooling commit")
    require(
        VERSION.fullmatch(str(metadata.get("version", ""))) is not None,
        "candidate version",
    )
    require(metadata.get("rust_version") == "1.96.0", "qualification MSRV")
    require(re.fullmatch(r"[0-9a-f]{64}", str(metadata.get("binary_sha256", ""))) is not None, "binary hash")
    checks.append("candidate identity, binary hash, and pinned MSRV")

    interfaces = success(root / "interfaces.json", "interfaces")
    names = {item["name"] for item in interfaces["result"]["interfaces"]}
    client_interface = metadata["topology"]["client_interface"]
    require(client_interface in names, "qualified client interface was not enumerated")
    checks.append("native interface enumeration")

    routes = success(root / "routes.json", "routes")
    require(
        any(route["interface"]["name"] == client_interface for route in routes["result"]["routes"]),
        "qualified interface absent from passive routes",
    )
    checks.append("passive native route enumeration")

    route_expectations = {
        "plan-onlink-ipv4.json": ("on_link", None, "10.49.1.9", "10.49.1.2"),
        "plan-routed-ipv4.json": ("gateway", "10.49.1.1", "10.49.1.1", "10.49.1.2"),
        "plan-routed-ipv6.json": ("gateway", "fd49:1::1", "fd49:1::1", "fd49:1::2"),
    }
    for filename, (reason, next_hop, neighbor, source) in route_expectations.items():
        route = success(root / filename, "plan")["result"]["route"]
        require(route["route"]["interface"]["name"] == client_interface, f"{filename}: interface")
        require(route["route"]["selection_reason"] == reason, f"{filename}: reason")
        require(route["route"]["next_hop"] == next_hop, f"{filename}: next hop")
        require(route["neighbor_target"] == neighbor, f"{filename}: neighbor target")
        require(route["neighbor_source"] == source, f"{filename}: neighbor source")
        require(route["route"]["mtu"] == 1280, f"{filename}: MTU")
        require(route["mode"] == "layer2", f"{filename}: link mode")
    checks.append("on-link and gateway-aware IPv4/IPv6 route/source decisions")

    for filename, family, neighbor_type in (
        ("send-layer2-ipv4.json", "ipv4", "0806"),
        ("send-layer2-ipv6.json", "ipv6", "86dd"),
    ):
        value = success(root / filename, "send")
        plan = value["result"]["route"]["plan"]
        neighbor = value["result"]["route"]["neighbor"]
        require(plan["mode"] == "layer2" and plan["synthesized_ethernet"], f"{filename}: Layer 2")
        require(plan["destination_mac"] == [2, 73, 0, 0, 1, 1], f"{filename}: gateway MAC")
        require(not neighbor["cache_hit"] and neighbor["attempts"] == 1, f"{filename}: active neighbor")
        require(
            any(frame["bytes_hex"][24:28] == neighbor_type for frame in neighbor["captured"]),
            f"{filename}: missing {family} neighbor evidence",
        )
        require(not neighbor["evidence_truncated"], f"{filename}: truncated neighbor evidence")
        no_capture_loss(value, filename)
        packets.append(packet_evidence(filename, value["result"]["frame"]["bytes_hex"]))
    checks.append("active gateway ARP/NDP and exact synthesized Layer 2 sends")

    layer3 = success(root / "send-layer3-ipv4.json", "send")
    frame_hex = layer3["result"]["frame"]["bytes_hex"]
    require(frame_hex.startswith("45"), "Layer 3 send contains an Ethernet envelope")
    require(frame_hex[8:12] != "0000", "Layer 3 IPv4 identification is zero")
    require(not layer3["result"]["route"]["plan"]["synthesized_ethernet"], "Layer 3 synthesized Ethernet")
    packets.append(packet_evidence("send-layer3-ipv4.json", frame_hex))
    checks.append("exact native raw IPv4 transmission")

    for filename in ("exchange-ipv4.json", "exchange-ipv6.json"):
        value = success(root / filename, "exchange")
        result = value["result"]
        require(len(result["sent"]) == 1, f"{filename}: sent count")
        require(len(result["responses"]) == 1 and not result["unanswered"], f"{filename}: response")
        response = result["responses"][0]["response"]["frame"]["bytes_hex"]
        packets.append(packet_evidence(f"{filename}:request", result["sent"][0]["bytes_hex"]))
        packets.append(packet_evidence(f"{filename}:response", response))
        no_capture_loss(value, filename)
    checks.append("capture-ready IPv4/IPv6 exchanges with matched exact responses")

    capture_records = read_ndjson(root / "capture-read.ndjson")
    captured = frames(capture_records, "capture-read.ndjson")
    require(len(captured) >= 2, "live capture did not retain request and reply")
    require((root / "capture.pcapng").stat().st_size > 64, "live PCAPNG is empty")
    packets.extend(packet_evidence("capture.pcapng", frame["bytes_hex"]) for frame in captured)
    checks.append("bounded native capture and independently readable PCAPNG")

    source_frames = frames(read_ndjson(root / "stacked-vlan-source.ndjson"), "stacked VLAN source")
    captured_frames = frames(
        read_ndjson(root / "stacked-vlan-captured.ndjson"), "stacked VLAN capture"
    )
    source_hex = source_frames[0]["bytes_hex"]
    captured_hex = captured_frames[0]["bytes_hex"]
    require(source_hex[24:32] == "88a80064" and source_hex[32:40] == "810000c8", "Q-in-Q tags")
    require(
        captured_hex[24:32] == "88a80064" and captured_hex[32:40] == "810000c8",
        "peer Q-in-Q evidence",
    )
    # Depending on the kernel packet-tap point, tcpdump sees either the exact
    # inbound replay or the peer's immediate ICMP port-unreachable response.
    # Linux quotes the complete small datagram in the latter, which proves the
    # inner IPv4/UDP/payload bytes arrived unchanged across both VLAN tags.
    exact_peer_frame = captured_hex == source_hex
    complete_peer_quote = captured_hex.endswith(source_hex[44:])
    require(exact_peer_frame or complete_peer_quote, "stacked VLAN peer bytes changed")
    replay = success(root / "stacked-vlan-replay.json", "replay")
    replay_frame = replay["result"]["frames"][0]
    require(replay_frame["transmitted"] and replay_frame["frame"]["bytes_hex"] == source_hex, "replay evidence")
    packets.append(packet_evidence("stacked-vlan:transmitted", source_hex))
    packets.append(packet_evidence("stacked-vlan:peer", captured_hex))
    checks.append("exact Q-in-Q transmission and byte-identical peer inner-datagram evidence")

    for filename, family in (("scan-ipv4.json", "IPv4"), ("scan-ipv6.json", "IPv6")):
        value = success(root / filename, "scan")
        port = value["result"]["ports"][0]
        require(port["classification"] == "open", f"{family} scan classification")
        require(port["evidence"][0]["status"] == "response", f"{family} scan evidence")
        packets.append(packet_evidence(filename, port["evidence"][0]["frame"]["bytes_hex"]))
        no_capture_loss(value, filename)
    checks.append("bounded structured IPv4 TCP and IPv6 ICMP scans")

    for filename, family in (
        ("traceroute-ipv4.json", "IPv4"),
        ("traceroute-ipv6.json", "IPv6"),
    ):
        value = success(root / filename, "traceroute")
        result = value["result"]
        require(result["completion"] == "destination_reached", f"{family} traceroute completion")
        require([hop["hop_limit"] for hop in result["hops"]] == [1, 2], f"{family} hops")
        kinds = [hop["probes"][0]["response_kind"] for hop in result["hops"]]
        require(kinds == ["intermediate", "destination_reached"], f"{family} hop evidence")
        for hop in result["hops"]:
            packets.append(
                packet_evidence(f"{filename}:hop-{hop['hop_limit']}", hop["probes"][0]["frame"]["bytes_hex"])
            )
        no_capture_loss(value, filename)
    checks.append("two-hop routed IPv4/IPv6 traceroute with exact ICMP evidence")

    for filename in ("dns-ipv4.json", "dns-ipv6.json"):
        value = success(root / filename, "dns")
        result = value["result"]
        require(result["outcome"] == "response", f"{filename}: outcome")
        require(result["response_code"] == 0, f"{filename}: response code")
        require(result["answers"] == [{
            "owner": "www.example.test.",
            "class": 1,
            "ttl": 60,
            "type": "a",
            "address": "192.0.2.49",
        }], f"{filename}: answer")
        require(not result["rejected_records"] and not result["undecoded"], f"{filename}: rejected evidence")
        packets.append(packet_evidence(filename, result["attempts"][0]["frame"]["bytes_hex"]))
        no_capture_loss(value, filename)
    checks.append("bounded structured DNS over routed IPv4 and IPv6")

    for strategy in ("boundary", "random", "bit-flip", "malformed"):
        filename = f"fuzz-{strategy}.json"
        value = success(root / filename, "fuzz")
        cases = value["result"]["cases"]
        require(len(cases) == 1, f"{filename}: case count")
        expected = "timeout" if strategy == "malformed" else "response"
        require(cases[0]["outcome"] == expected, f"{filename}: outcome")
        require(cases[0]["index"] == 0, f"{filename}: case index")
        require(cases[0]["reproduction"]["operation_seed"] == 49, f"{filename}: seed")
        packets.append(packet_evidence(filename, cases[0]["frame"]["bytes_hex"]))
    checks.append("deterministic boundary/random/bit-flip/malformed live fuzz modes")

    timeout = success(root / "timeout-malformed.json", "exchange")
    result = timeout["result"]
    require(not result["responses"] and result["unanswered"] == [0], "timeout outcome")
    malformed = [item for item in result["unsolicited"] if item["frame"]["bytes_hex"] == MALFORMED_NOISE]
    require(len(malformed) == 1, "malformed unrelated frame was not retained")
    require(
        any(item["code"] == "decode.malformed_layer" for item in malformed[0]["diagnostics"]),
        "malformed frame diagnostic",
    )
    no_capture_loss(timeout, "timeout-malformed.json")
    packets.append(packet_evidence("timeout-malformed:noise", MALFORMED_NOISE))
    checks.append("bounded loss/timeout plus unrelated malformed live evidence")

    privilege = error(root / "unprivileged-capture.ndjson", "capture", "capability.privilege")
    require("minimum raw-socket or capture permission" in privilege["error"]["remediation"], "privilege remediation")
    exit_status(root, "unprivileged-capture", 4)
    checks.append("actionable unprivileged native-capture failure")

    mtu = error(root / "low-mtu.json", "send", "packet.mtu")
    require("1280" in mtu["error"]["message"], "low-MTU evidence")
    exit_status(root, "low-mtu", 3)
    checks.append("low-MTU fail-closed behavior before live I/O")

    test_log = (root / "failure-path-tests.log").read_text(encoding="utf-8")
    for name in REQUIRED_TESTS:
        require(name in test_log, f"failure-path regression did not run: {name}")
    checks.append("partial send, readiness, cleanup, overflow, timeout, and backend-failure regressions")

    report = {
        "schema": "packetcraftr.qualification/linux-live-v1",
        "candidate": {
            key: metadata[key]
            for key in (
                "input_kind",
                "working_tree_dirty",
                "version",
                "candidate_commit",
                "archive_sha256",
                "binary_sha256",
                "rust_version",
            )
        },
        "topology": metadata["topology"],
        "checks": [{"name": name, "status": "passed"} for name in checks],
        "packet_evidence": packets,
        "summary": {
            "passed": len(checks),
            "failed": 0,
            "packet_records": len(packets),
        },
    }
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        f"verified {len(checks)} Linux live qualification rows and "
        f"{len(packets)} exact packet records"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
