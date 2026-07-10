#!/usr/bin/env python3
"""Explicit maintenance command for the reviewed XOD-60 fixture corpus.

This command is never run by tests or CI. It exists so reviewers can reproduce
the synthetic bytes, inspect their provenance changes, and independently run
tcpdump over each supported capture root before accepting an update.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures"
CREATED_UTC = "2026-07-10T00:00:00Z"
REVIEW_EVIDENCE = "https://linear.app/xodud/issue/XOD-60"
XOD36_REVIEW_EVIDENCE = "https://linear.app/xodud/issue/XOD-36"
GENERATOR_INVOCATION = (
    "python3 scripts/seed-fixture-corpus.py --write --verify-tcpdump"
)


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def icmp_echo(payload: bytes) -> bytes:
    body = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + payload
    checksum = internet_checksum(body)
    return struct.pack("!BBHHH", 8, 0, checksum, 0x1234, 1) + payload


def ipv4(payload: bytes, protocol: int, source: str, destination: str) -> bytes:
    source_bytes = ipaddress.IPv4Address(source).packed
    destination_bytes = ipaddress.IPv4Address(destination).packed
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        0x1234,
        0x4000,
        64,
        protocol,
        0,
        source_bytes,
        destination_bytes,
    )
    checksum = internet_checksum(header)
    return header[:10] + struct.pack("!H", checksum) + header[12:] + payload


def udp_ipv4(payload: bytes, source: str, destination: str) -> bytes:
    source_bytes = ipaddress.IPv4Address(source).packed
    destination_bytes = ipaddress.IPv4Address(destination).packed
    length = 8 + len(payload)
    header = struct.pack("!HHHH", 49152, 9, length, 0)
    pseudo = source_bytes + destination_bytes + struct.pack("!BBH", 0, 17, length)
    checksum = internet_checksum(pseudo + header + payload) or 0xFFFF
    return struct.pack("!HHHH", 49152, 9, length, checksum) + payload


def udp_ipv6(payload: bytes, source: str, destination: str) -> bytes:
    source_bytes = ipaddress.IPv6Address(source).packed
    destination_bytes = ipaddress.IPv6Address(destination).packed
    length = 8 + len(payload)
    header = struct.pack("!HHHH", 49152, 9, length, 0)
    pseudo = (
        source_bytes
        + destination_bytes
        + struct.pack("!I", length)
        + b"\0\0\0"
        + bytes([17])
    )
    checksum = internet_checksum(pseudo + header + payload) or 0xFFFF
    return struct.pack("!HHHH", 49152, 9, length, checksum) + payload


def ipv6(payload: bytes, next_header: int, source: str, destination: str) -> bytes:
    return struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(payload),
        next_header,
        64,
        ipaddress.IPv6Address(source).packed,
        ipaddress.IPv6Address(destination).packed,
    ) + payload


def pcap(link_type: int, frames: list[bytes]) -> bytes:
    output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type))
    for index, frame in enumerate(frames):
        output.extend(struct.pack("<IIII", 1_700_000_000 + index, 125_000, len(frame), len(frame)))
        output.extend(frame)
    return bytes(output)


def pcapng_interface(link_type: int) -> bytes:
    return struct.pack("<IIHHII", 1, 20, link_type, 0, 65535, 20)


def pcapng_packet(interface: int, timestamp: int, frame: bytes) -> bytes:
    padded = frame + bytes((-len(frame)) % 4)
    body = struct.pack(
        "<IIIII",
        interface,
        timestamp >> 32,
        timestamp & 0xFFFF_FFFF,
        len(frame),
        len(frame),
    ) + padded
    length = 12 + len(body)
    return struct.pack("<II", 6, length) + body + struct.pack("<I", length)


def multi_interface_pcapng(ethernet: bytes, raw: bytes) -> bytes:
    section = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    return b"".join(
        [
            section,
            pcapng_interface(1),
            pcapng_interface(101),
            pcapng_packet(0, 1_700_000_000_125_000, ethernet),
            pcapng_packet(1, 1_700_000_001_125_000, raw),
        ]
    )


def write(path: Path, content: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def tool(name: str, version: str, invocation: str, summary: str) -> dict[str, str]:
    return {
        "name": name,
        "version": version,
        "invocation": invocation,
        "summary": summary,
    }


def provenance(
    relative: str,
    content: bytes,
    *,
    kind: str,
    authority: str,
    protocols: list[str],
    link_type: int | None,
    layers: list[str],
    diagnostics: list[str],
    valid: bool,
    exact_rebuild: bool | None,
    notes: str,
    reference: str,
    capture: dict[str, Any] | None = None,
    oracle: dict[str, str] | None = None,
    source_type: str | None = None,
    generator_tool: dict[str, str] | None = None,
    reviewer: str = "Codex XOD-60 automated implementation review",
    review_evidence: str = REVIEW_EVIDENCE,
) -> dict[str, Any]:
    generator_tool = generator_tool or tool(
        "Python standard library",
        platform.python_version(),
        GENERATOR_INVOCATION,
        "Deterministic network-byte-order construction with explicit checksums and lengths",
    )
    return {
        "schema": "packetcraftr.fixture-provenance/v1",
        "fixture": relative,
        "sha256": hashlib.sha256(content).hexdigest(),
        "kind": kind,
        "authority": authority,
        "created_utc": CREATED_UTC,
        "protocols": protocols,
        "capture": capture,
        "source": {
            "type": source_type or ("generated" if authority != "derived" else "derived"),
            "description": notes,
            "reference": reference,
            "generator": generator_tool,
            "oracle": oracle,
        },
        "license": {
            "spdx": "CC0-1.0",
            "evidence": (
                "Synthetic fixture authored for the PacketcraftR XOD-60 corpus; no production "
                "capture, private data, or third-party payload is included"
            ),
        },
        "expected": {
            "link_type": link_type,
            "layers": layers,
            "diagnostic_codes": diagnostics,
            "exact_rebuild": exact_rebuild,
            "valid": valid,
            "notes": notes,
        },
        "review": {
            "reviewer": reviewer,
            "reviewed_utc": CREATED_UTC,
            "evidence": review_evidence,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write the reviewed fixture set")
    parser.add_argument(
        "--verify-tcpdump",
        action="store_true",
        help="require tcpdump to accept each supported-link frame and compatible capture",
    )
    arguments = parser.parse_args()
    if not arguments.write:
        parser.error("refusing to modify authoritative fixtures without explicit --write")
    if not arguments.verify_tcpdump:
        parser.error("--write requires the independent --verify-tcpdump oracle")
    executable = shutil.which("tcpdump")
    if executable is None:
        raise SystemExit("--verify-tcpdump requested but tcpdump is unavailable")
    version_lines = subprocess.run(
        [executable, "--version"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout.splitlines()
    tcpdump_version = " / ".join(line.strip() for line in version_lines[:2])

    payload4 = b"hello"
    udp4 = udp_ipv4(payload4, "192.0.2.1", "198.51.100.2")
    ip4_udp = ipv4(udp4, 17, "192.0.2.1", "198.51.100.2")
    ip4_icmp = ipv4(icmp_echo(b"ping"), 1, "192.0.2.1", "198.51.100.2")
    udp6 = udp_ipv6(b"ipv6", "2001:db8::1", "2001:db8::2")
    ip6_udp = ipv6(udp6, 17, "2001:db8::1", "2001:db8::2")
    ethernet = (
        bytes.fromhex("0200000000020200000000010800")
        + ip4_udp
    )
    null_ipv4 = struct.pack("<I", 2) + ip4_icmp
    null_ipv6_big_endian = struct.pack("!I", 30) + ip6_udp
    loop_ipv6 = struct.pack("!I", 30) + ip6_udp
    sll_ipv4 = struct.pack("!HHH8sH", 0, 1, 6, bytes.fromhex("0200000000010000"), 0x0800) + ip4_icmp
    sll2_ipv6 = (
        struct.pack("!H", 0x86DD)
        + b"\0\0"
        + struct.pack("!IHBB8s", 7, 1, 0, 6, bytes.fromhex("0200000000010000"))
        + ip6_udp
    )
    unknown = bytes.fromhex("deadbeef01020304")
    malformed = bytes.fromhex("0200000000020200000000010800") + ip4_udp[:10]

    section = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    valid_pcap = pcap(1, [ethernet])
    valid_pcapng = multi_interface_pcapng(ethernet, ip4_icmp)
    truncated_pcap = (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1_700_000_000, 0, 60, 60)
        + b"\0\1\2\3"
    )
    oversized_pcapng = section + struct.pack("<II", 6, 32 * 1024 * 1024)

    packet_document = json.dumps(
        {
            "schema": "packetcraftr.packet/v1",
            "layers": [
                {
                    "protocol": "ipv4",
                    "fields": {
                        "source": {"type": "ipv4", "value": "192.0.2.1"},
                        "destination": {"type": "ipv4", "value": "198.51.100.2"},
                    },
                },
                {
                    "protocol": "udp",
                    "fields": {
                        "source_port": {"type": "unsigned", "value": 49152},
                        "destination_port": {"type": "unsigned", "value": 9},
                    },
                },
                {
                    "protocol": "raw",
                    "fields": {"bytes": {"type": "bytes", "value": list(payload4)}},
                },
            ],
        },
        indent=2,
    ) + "\n"
    yaml_document = """schema: packetcraftr.packet/v1
layers:
  - protocol: raw
    fields:
      bytes:
        type: bytes
        value: [222, 173, 190, 239]
"""
    expected_decode = json.dumps(
        {
            "fixture": "frames/ethernet/ipv4-udp.bin",
            "link_type": 1,
            "layers": ["ethernet", "ipv4", "udp", "raw"],
            "source": "192.0.2.1",
            "destination": "198.51.100.2",
            "source_port": 49152,
            "destination_port": 9,
            "payload_hex": "68656c6c6f",
        },
        indent=2,
    ) + "\n"

    generated: dict[str, bytes] = {
        "frames/ethernet/ipv4-udp.bin": ethernet,
        "frames/raw/ipv4-icmp.bin": ip4_icmp,
        "frames/raw/ipv6-udp.bin": ip6_udp,
        "frames/raw/dlt-12-ipv4-icmp.bin": ip4_icmp,
        "frames/raw/linktype-ipv4-icmp.bin": ip4_icmp,
        "frames/raw/linktype-ipv6-udp.bin": ip6_udp,
        "frames/null/ipv4-icmp.bin": null_ipv4,
        "frames/null/ipv6-big-endian.bin": null_ipv6_big_endian,
        "frames/loop/ipv6-udp.bin": loop_ipv6,
        "frames/sll/ipv4-icmp.bin": sll_ipv4,
        "frames/sll2/ipv6-udp.bin": sll2_ipv6,
        "frames/unknown/dlt-147.bin": unknown,
        "frames/malformed/truncated-ipv4.bin": malformed,
        "captures/pcap/ethernet-ipv4-udp.pcap": valid_pcap,
        "captures/pcapng/multi-link.pcapng": valid_pcapng,
        "captures/malformed/truncated-record.pcap": truncated_pcap,
        "captures/malformed/oversized-block.pcapng": oversized_pcapng,
        "documents/ipv4-udp.json": packet_document.encode(),
        "documents/raw.yaml": yaml_document.encode(),
        "expected/ethernet-ipv4-udp.json": expected_decode.encode(),
    }
    for relative, content in generated.items():
        write(FIXTURES / relative, content)

    tcpdump_oracle = tool(
        "tcpdump/libpcap",
        tcpdump_version,
        "tcpdump -nn -vvv -r <deterministic wrapper capture>",
        "Independent libpcap parser accepted the frame/capture and decoded its documented root",
    )
    link_reference = "https://www.tcpdump.org/linktypes.html"
    pcap_reference = "https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-02.html"
    pcapng_reference = "https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html"
    packet_schema_reference = (
        "https://raw.githubusercontent.com/tyk-swe/pcr/main/schemas/"
        "packetcraftr.packet.v1.schema.json"
    )
    output_schema_reference = (
        "https://raw.githubusercontent.com/tyk-swe/pcr/main/schemas/"
        "packetcraftr.output.v1.schema.json"
    )

    descriptions: dict[str, dict[str, Any]] = {
        "frames/ethernet/ipv4-udp.bin": dict(
            kind="frame", authority="authoritative", protocols=["ethernet", "ipv4", "udp", "raw"],
            link_type=1, layers=["ethernet", "ipv4", "udp", "raw"], diagnostics=[], valid=True,
            exact_rebuild=True, notes="Ethernet/IPv4/UDP known-answer frame over documentation addresses",
            reference="https://www.rfc-editor.org/rfc/rfc894", oracle=tcpdump_oracle,
        ),
        "frames/raw/ipv4-icmp.bin": dict(
            kind="frame", authority="authoritative", protocols=["ipv4", "icmpv4"],
            link_type=101, layers=["ipv4", "icmpv4"], diagnostics=[], valid=True,
            exact_rebuild=True, notes="DLT_RAW IPv4 ICMP echo known-answer packet",
            reference="https://www.rfc-editor.org/rfc/rfc792", oracle=tcpdump_oracle,
        ),
        "frames/raw/ipv6-udp.bin": dict(
            kind="frame", authority="authoritative", protocols=["ipv6", "udp", "raw"],
            link_type=101, layers=["ipv6", "udp", "raw"], diagnostics=[], valid=True,
            exact_rebuild=True, notes="DLT_RAW IPv6 UDP known-answer packet",
            reference="https://www.rfc-editor.org/rfc/rfc8200", oracle=tcpdump_oracle,
        ),
        "frames/raw/dlt-12-ipv4-icmp.bin": dict(
            kind="frame", authority="authoritative", protocols=["raw_ip", "ipv4", "icmpv4"],
            link_type=12, layers=["ipv4", "icmpv4"], diagnostics=[], valid=True,
            exact_rebuild=True, notes="BSD DLT_RAW IPv4 ICMP echo known-answer packet",
            reference=link_reference, oracle=tcpdump_oracle,
            reviewer="Codex XOD-36 automated implementation review",
            review_evidence=XOD36_REVIEW_EVIDENCE,
        ),
        "frames/raw/linktype-ipv4-icmp.bin": dict(
            kind="frame", authority="authoritative", protocols=["ipv4", "icmpv4"],
            link_type=228, layers=["ipv4", "icmpv4"], diagnostics=[], valid=True,
            exact_rebuild=True, notes="LINKTYPE_IPV4 ICMP echo known-answer packet",
            reference=link_reference, oracle=tcpdump_oracle,
            reviewer="Codex XOD-36 automated implementation review",
            review_evidence=XOD36_REVIEW_EVIDENCE,
        ),
        "frames/raw/linktype-ipv6-udp.bin": dict(
            kind="frame", authority="authoritative", protocols=["ipv6", "udp", "raw"],
            link_type=229, layers=["ipv6", "udp", "raw"], diagnostics=[], valid=True,
            exact_rebuild=True, notes="LINKTYPE_IPV6 UDP known-answer packet",
            reference=link_reference, oracle=tcpdump_oracle,
            reviewer="Codex XOD-36 automated implementation review",
            review_evidence=XOD36_REVIEW_EVIDENCE,
        ),
        "frames/null/ipv4-icmp.bin": dict(
            kind="frame", authority="authoritative", protocols=["bsd_null", "ipv4", "icmpv4"],
            link_type=0, layers=["bsd_null", "ipv4", "icmpv4"], diagnostics=[], valid=True,
            exact_rebuild=True, notes="Little-endian BSD NULL family header followed by IPv4 ICMP",
            reference=link_reference, oracle=tcpdump_oracle,
        ),
        "frames/null/ipv6-big-endian.bin": dict(
            kind="frame", authority="authoritative", protocols=["bsd_null", "ipv6", "udp", "raw"],
            link_type=0, layers=["bsd_null", "ipv6", "udp", "raw"], diagnostics=[], valid=True,
            exact_rebuild=True, notes="Big-endian BSD NULL AF_INET6 header followed by IPv6 UDP",
            reference=link_reference, oracle=None,
            reviewer="Codex XOD-36 automated implementation review",
            review_evidence=XOD36_REVIEW_EVIDENCE,
        ),
        "frames/loop/ipv6-udp.bin": dict(
            kind="frame", authority="authoritative", protocols=["bsd_loop", "ipv6", "udp", "raw"],
            link_type=108, layers=["bsd_loop", "ipv6", "udp", "raw"], diagnostics=[], valid=True,
            exact_rebuild=True, notes="Network-order BSD LOOP AF_INET6 header followed by IPv6 UDP",
            reference=link_reference, oracle=tcpdump_oracle,
        ),
        "frames/sll/ipv4-icmp.bin": dict(
            kind="frame", authority="authoritative", protocols=["linux_sll", "ipv4", "icmpv4"],
            link_type=113, layers=["linux_sll", "ipv4", "icmpv4"], diagnostics=[], valid=True,
            exact_rebuild=True, notes="Linux cooked capture v1 IPv4 ICMP frame",
            reference=link_reference, oracle=tcpdump_oracle,
        ),
        "frames/sll2/ipv6-udp.bin": dict(
            kind="frame", authority="authoritative", protocols=["linux_sll2", "ipv6", "udp", "raw"],
            link_type=276, layers=["linux_sll2", "ipv6", "udp", "raw"], diagnostics=[], valid=True,
            exact_rebuild=True, notes="Linux cooked capture v2 IPv6 UDP frame",
            reference=link_reference, oracle=tcpdump_oracle,
        ),
        "frames/unknown/dlt-147.bin": dict(
            kind="frame", authority="malformed_seed", protocols=["raw"], link_type=147,
            layers=["raw"], diagnostics=["decode.unsupported_link_type"], valid=True,
            exact_rebuild=True, notes="Unknown DLT bytes must remain a complete raw record",
            reference=link_reference, oracle=None,
        ),
        "frames/malformed/truncated-ipv4.bin": dict(
            kind="malformed_input", authority="malformed_seed", protocols=["ethernet", "malformed"],
            link_type=1, layers=["ethernet", "malformed"], diagnostics=["decode.malformed_layer"],
            valid=False, exact_rebuild=False, notes="Ethernet selects IPv4 but only ten IPv4 header bytes remain",
            reference="https://www.rfc-editor.org/rfc/rfc791", oracle=None,
        ),
        "captures/pcap/ethernet-ipv4-udp.pcap": dict(
            kind="pcap", authority="authoritative", protocols=["ethernet", "ipv4", "udp", "raw"],
            link_type=1, layers=["ethernet", "ipv4", "udp", "raw"], diagnostics=[], valid=True,
            exact_rebuild=True, notes="Little-endian classic PCAP with one Ethernet frame",
            reference=pcap_reference, oracle=tcpdump_oracle,
            capture={"link_types": [1], "interfaces": [{"id": 0, "link_type": 1}]},
        ),
        "captures/pcapng/multi-link.pcapng": dict(
            kind="pcapng", authority="authoritative", protocols=["ethernet", "ipv4", "udp", "icmpv4", "raw"],
            link_type=None, layers=["ethernet", "ipv4", "udp", "icmpv4", "raw"], diagnostics=[], valid=True,
            exact_rebuild=True, notes="PCAPNG section with Ethernet and DLT_RAW interfaces",
            reference=pcapng_reference, oracle=None,
            capture={"link_types": [1, 101], "interfaces": [{"id": 0, "link_type": 1}, {"id": 1, "link_type": 101}]},
        ),
        "captures/malformed/truncated-record.pcap": dict(
            kind="malformed_input", authority="malformed_seed", protocols=["pcap"], link_type=1,
            layers=[], diagnostics=["capture.truncated"], valid=False, exact_rebuild=None,
            notes="Classic PCAP record declares sixty captured bytes but stores four",
            reference=pcap_reference, oracle=None,
            capture={"link_types": [1], "interfaces": [{"id": 0, "link_type": 1}]},
        ),
        "captures/malformed/oversized-block.pcapng": dict(
            kind="malformed_input", authority="malformed_seed", protocols=["pcapng"], link_type=None,
            layers=[], diagnostics=["capture.size_limit"], valid=False, exact_rebuild=None,
            notes="PCAPNG packet block declares thirty-two MiB and must fail before allocation",
            reference=pcapng_reference, oracle=None,
            capture={"link_types": [1], "interfaces": []},
        ),
        "documents/ipv4-udp.json": dict(
            kind="document", authority="derived", protocols=["ipv4", "udp", "raw"], link_type=None,
            layers=["ipv4", "udp", "raw"], diagnostics=[], valid=True, exact_rebuild=True,
            notes="Versioned JSON packet document for strict IPv4/UDP construction",
            reference=packet_schema_reference, oracle=None,
        ),
        "documents/raw.yaml": dict(
            kind="document", authority="derived", protocols=["raw"], link_type=None,
            layers=["raw"], diagnostics=[], valid=True, exact_rebuild=True,
            notes="Versioned YAML packet document preserving four raw bytes",
            reference=packet_schema_reference, oracle=None,
        ),
        "expected/ethernet-ipv4-udp.json": dict(
            kind="expected_result", authority="derived", protocols=["ethernet", "ipv4", "udp", "raw"],
            link_type=1, layers=["ethernet", "ipv4", "udp", "raw"], diagnostics=[], valid=True,
            exact_rebuild=True, notes="Expected semantic decode for the Ethernet known-answer frame",
            reference="https://www.rfc-editor.org/rfc/rfc894", oracle=tcpdump_oracle,
        ),
    }

    for relative, metadata in descriptions.items():
        content = generated[relative]
        if metadata.get("capture") is None and metadata["link_type"] is not None:
            metadata["capture"] = {
                "link_types": [metadata["link_type"]],
                "interfaces": [],
            }
        document = provenance(relative, content, **metadata)
        write(
            Path(f"{FIXTURES / relative}.provenance.json"),
            json.dumps(document, indent=2, sort_keys=True) + "\n",
        )

    for fixture in sorted(
        path
        for path in (FIXTURES / "invalid-output").glob("*.json")
        if not path.name.endswith(".provenance.json")
    ):
        relative = fixture.relative_to(FIXTURES).as_posix()
        content = fixture.read_bytes()
        document = provenance(
            relative,
            content,
            kind="malformed_input",
            authority="malformed_seed",
            protocols=["output_contract"],
            link_type=None,
            layers=[],
            diagnostics=["cli.output_schema"],
            valid=False,
            exact_rebuild=None,
            notes="Negative packetcraftr.output/v1 schema fixture",
            reference=output_schema_reference,
            oracle=None,
            source_type="derived",
            generator_tool=tool(
                "PacketcraftR output-contract fixture",
                "a2f5650",
                "hand-authored negative JSON document",
                "Authored with XOD-62 to freeze a schema-invalid output shape",
            ),
        )
        write(
            Path(f"{fixture}.provenance.json"),
            json.dumps(document, indent=2, sort_keys=True) + "\n",
        )

    frame_link_types = {
        "frames/ethernet/ipv4-udp.bin": 1,
        "frames/raw/ipv4-icmp.bin": 101,
        "frames/raw/ipv6-udp.bin": 101,
        "frames/raw/dlt-12-ipv4-icmp.bin": 12,
        "frames/raw/linktype-ipv4-icmp.bin": 228,
        "frames/raw/linktype-ipv6-udp.bin": 229,
        "frames/null/ipv4-icmp.bin": 0,
        "frames/loop/ipv6-udp.bin": 108,
        "frames/sll/ipv4-icmp.bin": 113,
        "frames/sll2/ipv6-udp.bin": 276,
    }
    with tempfile.TemporaryDirectory(prefix="packetcraftr-fixture-oracle-") as directory:
        temporary = Path(directory)
        for relative, link_type in frame_link_types.items():
            wrapper = temporary / (Path(relative).stem + ".pcap")
            wrapper.write_bytes(pcap(link_type, [generated[relative]]))
            subprocess.run(
                [executable, "-nn", "-vvv", "-r", str(wrapper)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        for relative in ("captures/pcap/ethernet-ipv4-udp.pcap",):
            subprocess.run(
                [executable, "-nn", "-vvv", "-r", str(FIXTURES / relative)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )

    subprocess.run(
        [sys.executable, str(ROOT / "scripts/validate-fixture-corpus.py")],
        cwd=ROOT,
        check=True,
    )
    fixture_count = sum(
        1
        for path in FIXTURES.rglob("*")
        if path.is_file()
        and not path.name.endswith(".provenance.json")
        and path.name != "README.md"
        and not path.name.endswith(".example.json")
    )
    print(f"wrote and validated the {fixture_count}-fixture reviewed corpus")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
