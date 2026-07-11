#!/usr/bin/env python3
"""Verify dedicated Windows/Npcap live-I/O qualification evidence."""

# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


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


def ndjson_records(path: Path) -> list[dict[str, object]]:
    records = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise EvidenceError(f"{path.name} contains a non-object record")
            records.append(value)
    if not records:
        raise EvidenceError(f"{path.name} is empty")
    return records


def frame_hex(record: dict[str, object]) -> str:
    result = record.get("result")
    if not isinstance(result, dict):
        raise EvidenceError("capture record has no result")
    frame = result.get("frame")
    if not isinstance(frame, dict) or not isinstance(frame.get("bytes_hex"), str):
        raise EvidenceError("capture record has no exact frame bytes")
    return str(frame["bytes_hex"])


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
            or not re.fullmatch(r"[0-9a-f]{40}", str(metadata.get("candidate_commit", "")))
            or not str(metadata.get("npcap_version", "")).startswith("1.88")
            or metadata.get("npcap_sdk_abi") != "1.16"
        ):
            raise EvidenceError("metadata does not identify the pinned Windows/Npcap boundary")
        topology = metadata.get("topology")
        if (
            not isinstance(topology, dict)
            or topology.get("kind") != "dedicated-isolated-switch"
            or topology.get("peer_mode") != "packetcraftr-native-npcap"
            or topology.get("peer_target_addresses") != "unassigned"
        ):
            raise EvidenceError("metadata does not identify the isolated Npcap topology")
        client_interface = topology["client_interface"]
        peer_interface = topology["peer_interface"]

        npcap = load_json(root / "npcap.json")
        if (
            not str(npcap.get("version", "")).startswith("1.88")
            or npcap.get("service") != "running"
            or npcap.get("sdk_abi") != "1.16"
            or npcap.get("loading") != "runtime-only-no-import-library"
            or npcap.get("dll_sha256") != metadata.get("npcap_dll_sha256")
        ):
            raise EvidenceError("Npcap runtime/ABI evidence is inconsistent")

        peer = load_json(root / "peer-report.json")
        if (
            peer.get("schema") != "packetcraftr.live-qualification-peer/v1"
            or peer.get("status") != "pass"
            or peer.get("interface") != peer_interface
        ):
            raise EvidenceError("the Packetcraftr-backed Npcap peer did not complete")
        peer_capture = peer.get("capture")
        if not isinstance(peer_capture, dict) or any(
            peer_capture.get(field, 0) != 0
            for field in (
                "dropped_frames",
                "dropped_bytes",
                "overflow_events",
                "receiver_dropped_frames",
            )
        ):
            raise EvidenceError("the Packetcraftr-backed Npcap peer reported capture loss")
        peer_responses = peer.get("responses")
        required_peer_responses = (
            "arp",
            "ndp",
            "udp_echo_ipv4",
            "udp_echo_ipv6",
            "dns_ipv4",
            "dns_ipv6",
            "tcp_syn_ack_ipv4",
            "icmp_echo_ipv6",
            "traceroute_unreachable_ipv4",
            "traceroute_unreachable_ipv6",
        )
        if not isinstance(peer_responses, dict) or any(
            not isinstance(peer_responses.get(case), int)
            or int(peer_responses[case]) < 1
            for case in required_peer_responses
        ):
            raise EvidenceError("the Npcap peer omitted a required protocol response")
        if peer_responses.get("total") != sum(
            int(peer_responses[case]) for case in required_peer_responses
        ):
            raise EvidenceError("the Npcap peer response accounting is inconsistent")

        interfaces = success(root, "interfaces.json", "interfaces").get("interfaces")
        if not isinstance(interfaces, list):
            raise EvidenceError("native interface output omitted its list")
        for name in (client_interface, peer_interface):
            if not any(
                isinstance(item, dict)
                and item.get("name") == name
                and item.get("capability") == "layer2_and3"
                and item.get("link_type") == 1
                for item in interfaces
            ):
                raise EvidenceError(f"native interface inventory omitted Ethernet adapter {name}")
        success(root, "routes.json", "routes")

        rows: list[dict[str, str]] = []
        for family in ("ipv4", "ipv6"):
            plan = success(root, f"plan-{family}.json", "plan").get("route")
            if not isinstance(plan, dict):
                raise EvidenceError(f"{family} plan omitted its route")
            route = plan.get("route")
            if (
                not isinstance(route, dict)
                or not isinstance(route.get("interface"), dict)
                or route["interface"].get("name") != client_interface
                or plan.get("mode") != "layer2"
                or not plan.get("synthesized_ethernet")
            ):
                raise EvidenceError(f"{family} plan escaped the dedicated client adapter")
            rows.append({"case": f"get-best-route2-{family}", "status": "pass"})
            for mode in ("layer2", "layer3"):
                sent = success(root, f"send-{mode}-{family}.json", "send").get("frame")
                if not isinstance(sent, dict) or not sent.get("bytes_hex"):
                    raise EvidenceError(f"{mode} {family} send omitted exact bytes")
                rows.append({"case": f"send-{mode}-{family}", "status": "pass"})
            exchange = success(root, f"exchange-{family}.json", "exchange")
            if not exchange.get("sent") or not exchange.get("responses"):
                raise EvidenceError(f"{family} exchange omitted sent/response evidence")
            rows.append({"case": f"exchange-{family}", "status": "pass"})
            scan = success(root, f"scan-{family}.json", "scan")
            ports = scan.get("ports")
            if not isinstance(ports, list) or not ports or ports[0].get("classification") != "open":
                raise EvidenceError(f"{family} scan did not produce open evidence")
            rows.append({"case": f"scan-{family}", "status": "pass"})
            trace = success(root, f"traceroute-{family}.json", "traceroute")
            if trace.get("completion") != "destination_reached":
                raise EvidenceError(f"{family} traceroute did not reach the isolated peer")
            rows.append({"case": f"traceroute-{family}", "status": "pass"})
            dns = success(root, f"dns-{family}.json", "dns")
            if dns.get("outcome") != "response" or dns.get("response_code") != 0:
                raise EvidenceError(f"{family} DNS did not retain a validated answer")
            rows.append({"case": f"dns-{family}", "status": "pass"})

        capture = ndjson_records(root / "capture-read.ndjson")
        if not any(record.get("status") == "success" for record in capture):
            raise EvidenceError("finite Npcap capture did not retain a frame")
        success(root, "capture-trigger.json", "send")
        rows.append({"case": "npcap-pcapng-capture-readback", "status": "pass"})

        expected_hex = (root / "stacked-vlan.hex").read_text(encoding="utf-8").strip()
        source_hex = [
            frame_hex(record)
            for record in ndjson_records(root / "stacked-vlan-source.ndjson")
        ]
        captured_hex = [
            frame_hex(record)
            for record in ndjson_records(root / "stacked-vlan-captured.ndjson")
        ]
        if expected_hex not in source_hex or expected_hex not in captured_hex:
            raise EvidenceError("stacked VLAN Npcap replay changed explicit packet bytes")
        replay = success(root, "stacked-vlan-replay.json", "replay")
        if replay.get("frames_completed") != 1:
            raise EvidenceError("stacked VLAN replay did not report one complete frame")
        rows.append({"case": "npcap-stacked-vlan-exact-replay", "status": "pass"})

        for strategy in ("boundary", "random", "bit-flip", "malformed"):
            fuzz = success(root, f"fuzz-{strategy}.json", "fuzz")
            if fuzz.get("mode") != "live" or fuzz.get("cases_generated") != 1:
                raise EvidenceError(f"{strategy} fuzz result is not the bounded live case")
            rows.append({"case": f"fuzz-{strategy}", "status": "pass"})

        timeout = success(root, "exchange-timeout.json", "exchange")
        if timeout.get("responses"):
            raise EvidenceError("ignored peer endpoint unexpectedly produced a matched response")
        rows.append({"case": "npcap-timeout-cleanup", "status": "pass"})

        mtu_exit = int((root / "low-mtu.exit").read_text(encoding="utf-8").strip())
        mtu = load_json(root / "low-mtu.json")
        mtu_error = mtu.get("error")
        if (
            mtu_exit == 0
            or not isinstance(mtu_error, dict)
            or mtu_error.get("code") != "packet.mtu"
        ):
            raise EvidenceError("low-MTU send did not fail before native I/O")
        rows.append({"case": "low-mtu", "status": "pass"})
        rows.append({"case": "npcap-native-peer-zero-loss", "status": "pass"})

        before = load_json(root / "adapter-before.json")
        after = load_json(root / "adapter-after.json")
        if (
            after.get("qualification_addresses_removed") is not True
            or after.get("mtus_restored") is not True
        ):
            raise EvidenceError("dedicated adapter cleanup was not confirmed")
        for side in ("client", "peer"):
            original = before.get(side)
            restored = after.get(side)
            if not isinstance(original, dict) or not isinstance(restored, dict):
                raise EvidenceError(f"{side} adapter cleanup evidence is missing")
            for field in ("mtu_ipv4", "mtu_ipv6"):
                if original.get(field) != restored.get(field):
                    raise EvidenceError(f"{side} {field} was not restored")
        rows.append({"case": "dedicated-adapter-cleanup", "status": "pass"})

        packet_files = [
            "send-layer2-ipv4.json",
            "send-layer2-ipv6.json",
            "send-layer3-ipv4.json",
            "send-layer3-ipv6.json",
            "stacked-vlan.hex",
        ]
        report = {
            "schema": "packetcraftr.windows-live-qualification/v1",
            "status": "pass",
            "candidate_commit": metadata["candidate_commit"],
            "archive_sha256": metadata["archive_sha256"],
            "binary_sha256": metadata["binary_sha256"],
            "npcap_version": metadata["npcap_version"],
            "npcap_dll_sha256": metadata["npcap_dll_sha256"],
            "runner_image": metadata.get("runner_image"),
            "runner_image_version": metadata.get("runner_image_version"),
            "matrix": rows,
            "matrix_rows": len(rows),
            "packet_evidence": {
                name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                for name in packet_files
            },
        }
        (root / "report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"Windows Npcap live evidence passed {len(rows)} semantic matrix rows")
    except (EvidenceError, KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Windows Npcap live evidence verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
