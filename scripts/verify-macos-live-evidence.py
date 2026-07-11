#!/usr/bin/env python3
"""Verify the semantic macOS live-I/O qualification evidence."""

# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import hashlib
import json
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
    if value.get("schema") != "packetcraftr.output/v1":
        raise EvidenceError(f"{name} has the wrong output schema")
    if value.get("command") != command or value.get("status") != "success":
        raise EvidenceError(f"{name} is not a successful {command} result")
    result = value.get("result")
    if not isinstance(result, dict):
        raise EvidenceError(f"{name} has no result object")
    return result


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
        if metadata.get("platform") != "macos" or metadata.get("architecture") not in {
            "arm64",
            "x86_64",
        }:
            raise EvidenceError("metadata does not identify a stable macOS architecture")
        if metadata.get("input_kind") != "archive":
            raise EvidenceError("release sign-off requires an exact candidate archive")
        topology = metadata.get("topology")
        if not isinstance(topology, dict) or topology.get("kind") != "paired-feth":
            raise EvidenceError("metadata does not identify the isolated feth topology")
        if (
            topology.get("peer_mode") != "packetcraftr-native-bpf"
            or topology.get("peer_interface_addresses") != "none"
        ):
            raise EvidenceError("metadata does not identify the isolated native-I/O peer")
        interface_name = topology["client_interface"]
        peer_interface = topology["peer_interface"]

        peer = load_json(root / "peer-report.json")
        if (
            peer.get("schema") != "packetcraftr.live-qualification-peer/v1"
            or peer.get("status") != "pass"
            or peer.get("interface") != peer_interface
        ):
            raise EvidenceError("the Packetcraftr-backed peer did not complete successfully")
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
            raise EvidenceError("the Packetcraftr-backed peer reported capture loss")
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
            raise EvidenceError("the isolated peer omitted a required protocol response")
        if peer_responses.get("total") != sum(
            int(peer_responses[case]) for case in required_peer_responses
        ):
            raise EvidenceError("the isolated peer response accounting is inconsistent")
        received_frames = peer_capture.get("received_frames")
        if not isinstance(received_frames, int) or received_frames < int(
            peer_responses["total"]
        ):
            raise EvidenceError("the isolated peer sent more replies than it captured requests")

        interfaces = success(root, "interfaces.json", "interfaces").get("interfaces")
        if not isinstance(interfaces, list) or not any(
            isinstance(item, dict)
            and item.get("name") == interface_name
            and item.get("capability") == "layer2_and3"
            and item.get("link_type") == 1
            for item in interfaces
        ):
            raise EvidenceError("native interface inventory omitted the client feth device")
        success(root, "routes.json", "routes")

        rows: list[dict[str, str]] = []
        for family in ("ipv4", "ipv6"):
            plan = success(root, f"plan-{family}.json", "plan").get("route")
            if not isinstance(plan, dict):
                raise EvidenceError(f"{family} plan omitted its route")
            route = plan.get("route")
            if not isinstance(route, dict) or route.get("interface", {}).get("name") != interface_name:
                raise EvidenceError(f"{family} plan escaped the selected feth interface")
            if plan.get("mode") != "layer2" or not plan.get("synthesized_ethernet"):
                raise EvidenceError(f"{family} plan did not preserve Layer 2 intent")
            rows.append({"case": f"plan-{family}", "status": "pass"})
            for mode in ("layer2",):
                sent = success(root, f"send-{mode}-{family}.json", "send").get("frame")
                if not isinstance(sent, dict) or not sent.get("bytes_hex"):
                    raise EvidenceError(f"{mode} {family} send omitted exact bytes")
                rows.append({"case": f"send-{mode}-{family}", "status": "pass"})

        sent_ipv4 = success(root, "send-layer3-ipv4.json", "send").get("frame")
        if not isinstance(sent_ipv4, dict) or not sent_ipv4.get("bytes_hex"):
            raise EvidenceError("Layer 3 IPv4 send omitted exact bytes")
        rows.append({"case": "send-layer3-ipv4", "status": "pass"})

        layer3_ipv6_exit = int((root / "send-layer3-ipv6.exit").read_text().strip())
        layer3_ipv6 = load_json(root / "send-layer3-ipv6.json")
        layer3_ipv6_error = layer3_ipv6.get("error")
        if (
            layer3_ipv6_exit != 4
            or layer3_ipv6.get("command") != "send"
            or layer3_ipv6.get("status") != "error"
            or not isinstance(layer3_ipv6_error, dict)
            or layer3_ipv6_error.get("code") != "capability.unsupported"
        ):
            raise EvidenceError(
                "Darwin exact-header Layer 3 IPv6 did not fail as a typed capability"
            )
        rows.append({"case": "send-layer3-ipv6-typed-unsupported", "status": "pass"})

        for family in ("ipv4", "ipv6"):
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
            raise EvidenceError("finite capture did not retain a frame")
        success(root, "capture-trigger.json", "send")
        rows.append({"case": "capture-pcapng-readback", "status": "pass"})

        source_records = ndjson_records(root / "stacked-vlan-source.ndjson")
        captured_records = ndjson_records(root / "stacked-vlan-captured.ndjson")
        expected_hex = (root / "stacked-vlan.hex").read_text(encoding="utf-8").strip()
        source_hex = [frame_hex(record) for record in source_records]
        captured_hex = [frame_hex(record) for record in captured_records]
        if expected_hex not in source_hex or expected_hex not in captured_hex:
            raise EvidenceError("stacked VLAN replay changed explicit packet bytes")
        replay = success(root, "stacked-vlan-replay.json", "replay")
        if replay.get("frames_completed") != 1:
            raise EvidenceError("stacked VLAN replay did not report one complete frame")
        rows.append({"case": "stacked-vlan-exact-replay", "status": "pass"})

        for strategy in ("boundary", "random", "bit-flip", "malformed"):
            fuzz = success(root, f"fuzz-{strategy}.json", "fuzz")
            if fuzz.get("mode") != "live" or fuzz.get("cases_generated") != 1:
                raise EvidenceError(f"{strategy} fuzz result is not the bounded live case")
            rows.append({"case": f"fuzz-{strategy}", "status": "pass"})

        privilege_exit = int((root / "unprivileged-capture.exit").read_text().strip())
        privilege = ndjson_records(root / "unprivileged-capture.ndjson")[-1]
        error = privilege.get("error")
        if privilege_exit == 0 or not isinstance(error, dict) or error.get("code") != "capability.privilege":
            raise EvidenceError("unprivileged BPF capture was not an actionable typed failure")
        rows.append({"case": "unprivileged-bpf", "status": "pass"})

        mtu_exit = int((root / "low-mtu.exit").read_text().strip())
        mtu = load_json(root / "low-mtu.json")
        mtu_error = mtu.get("error")
        if mtu_exit == 0 or not isinstance(mtu_error, dict) or mtu_error.get("code") != "packet.mtu":
            raise EvidenceError("low-MTU send did not fail before native I/O")
        rows.append({"case": "low-mtu", "status": "pass"})
        rows.append({"case": "native-bpf-userspace-peer-zero-loss", "status": "pass"})

        packet_files = [
            "send-layer2-ipv4.json",
            "send-layer2-ipv6.json",
            "send-layer3-ipv4.json",
            "send-layer3-ipv6.json",
            "stacked-vlan.hex",
        ]
        report = {
            "schema": "packetcraftr.macos-live-qualification/v1",
            "status": "pass",
            "candidate_commit": metadata["candidate_commit"],
            "archive_sha256": metadata["archive_sha256"],
            "binary_sha256": metadata["binary_sha256"],
            "architecture": metadata["architecture"],
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
        print(
            f"macOS {metadata['architecture']} evidence passed "
            f"{len(rows)} semantic matrix rows"
        )
    except (EvidenceError, KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"macOS live evidence verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
