#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Extract decoded fuzz seeds from classic PCAP example captures."""
import argparse
import pathlib
import struct
import sys

ROOT_SELECTORS = {0: 0, 1: 1, 101: 2, 12: 3, 108: 4, 113: 5, 228: 6, 229: 7, 276: 8}
MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}
DNS_PORTS = (53, 5353)


def read_pcap_frames(data):
    if len(data) < 24 or data[:4] not in MAGICS:
        raise ValueError("unsupported capture container")
    endian = MAGICS[data[:4]]
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    frames = []
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError("truncated pcap record header")
        captured = struct.unpack_from(endian + "I", data, offset + 8)[0]
        offset += 16
        if offset + captured > len(data):
            raise ValueError("truncated pcap packet data")
        frames.append(data[offset:offset + captured])
        offset += captured
    return linktype, frames


def packet_seeds(data):
    linktype, frames = read_pcap_frames(data)
    selector = ROOT_SELECTORS.get(linktype)
    if selector is None:
        return []
    return [bytes([selector]) + frame for frame in frames]


def dns_payload(linktype, frame):
    ip = strip_link(linktype, frame)
    if ip is None or not ip:
        return None
    version = ip[0] >> 4
    if version == 4:
        if len(ip) < 20:
            return None
        header = (ip[0] & 0x0F) * 4
        if header < 20 or len(ip) < header:
            return None
        protocol, transport = ip[9], ip[header:]
    elif version == 6:
        if len(ip) < 40:
            return None
        protocol, transport = ip[6], ip[40:]
    else:
        return None
    if protocol == 17 and len(transport) >= 8:
        source, destination = struct.unpack_from("!HH", transport)
        return transport[8:] if source in DNS_PORTS or destination in DNS_PORTS else None
    if protocol == 6 and len(transport) >= 20:
        source, destination = struct.unpack_from("!HH", transport)
        header = (transport[12] >> 4) * 4
        if header < 20 or len(transport) < header or not (
            source in DNS_PORTS or destination in DNS_PORTS
        ):
            return None
        payload = transport[header:]
        if len(payload) >= 2 and struct.unpack_from("!H", payload)[0] == len(payload) - 2:
            return payload[2:]
        return payload or None
    return None


def strip_link(linktype, frame):
    if linktype == 1:
        if len(frame) < 14:
            return None
        offset = 18 if frame[12:14] == b"\x81\x00" and len(frame) >= 18 else 14
        return frame[offset:]
    widths = {0: 4, 108: 4, 113: 16, 276: 20, 12: 0, 101: 0, 228: 0, 229: 0}
    width = widths.get(linktype)
    return None if width is None or len(frame) < width else frame[width:]


def extract(paths, packet_dir, dns_dir):
    packet_dir.mkdir(parents=True, exist_ok=True)
    dns_dir.mkdir(parents=True, exist_ok=True)
    written = {"packet": 0, "dns": 0, "skipped": 0}
    for path in paths:
        try:
            data = path.read_bytes()
            linktype, frames = read_pcap_frames(data)
            seeds = packet_seeds(data)
            payloads = [dns_payload(linktype, frame) for frame in frames]
        except (OSError, ValueError):
            written["skipped"] += 1
            continue
        for index, seed in enumerate(seeds):
            (packet_dir / f"{path.stem}-{index}.bin").write_bytes(seed)
            written["packet"] += 1
        for index, payload in enumerate(p for p in payloads if p):
            (dns_dir / f"{path.stem}-{index}.bin").write_bytes(payload)
            written["dns"] += 1
    return written


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-dir", type=pathlib.Path, required=True)
    parser.add_argument("--dns-dir", type=pathlib.Path, required=True)
    parser.add_argument("captures", type=pathlib.Path, nargs="+")
    args = parser.parse_args(argv)
    written = extract(args.captures, args.packet_dir, args.dns_dir)
    print(
        f"packet seeds {written['packet']}, dns seeds {written['dns']}, "
        f"skipped captures {written['skipped']}"
    )
    return 0 if written["packet"] and written["dns"] else 1


if __name__ == "__main__":
    sys.exit(main())
