#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Derive fuzz seeds from the checked-in example captures, filters, and documents."""
import argparse
import collections
import pathlib
import struct
import sys

ROOT_SELECTORS = {0: 0, 1: 1, 101: 2, 12: 3, 108: 4, 113: 5, 228: 6, 229: 7, 276: 8}
MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1),
    b"\xa1\xb2\x3c\x4d": (">", 1),
}
PCAPNG_SECTION = b"\x0a\x0d\x0d\x0a"
PCAPNG_BYTE_ORDERS = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}
DNS_PORTS = (53, 5353)
TCP, UDP = 6, 17
SYN, RST, FIN, ACK = 0x02, 0x04, 0x01, 0x10

# These mirror the input layouts documented in fuzz/fuzz_targets.
MAX_RECORDS = 64
MAX_CHUNKS = 64
MAX_SEGMENT_PAYLOAD = 1460
FRAGMENT_UNITS = 2
IN_ORDER, REVERSED = 1, 2
DOCUMENT_SELECTORS = {
    "service-probes": 0,
    "service-exclusions": 1,
    "os-fingerprints": 2,
    "udp-profiles": 3,
    "indicators": 4,
    "rewrite-field-edits": 5,
}
RECIPE_SELECTOR = 6

Segment = collections.namedtuple(
    "Segment",
    "nanoseconds family source destination flags sequence acknowledgment window payload",
)


def read_frames(data):
    """Return (linktype, nanoseconds, frame) for every packet record."""
    if data[:4] == PCAPNG_SECTION:
        return read_pcapng_frames(data)
    return read_pcap_frames(data)


def read_pcap_frames(data):
    if len(data) < 24 or data[:4] not in MAGICS:
        raise ValueError("unsupported capture container")
    endian, scale = MAGICS[data[:4]]
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    frames = []
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError("truncated pcap record header")
        seconds, fraction, captured = struct.unpack_from(endian + "III", data, offset)
        offset += 16
        if offset + captured > len(data):
            raise ValueError("truncated pcap packet data")
        nanoseconds = seconds * 1_000_000_000 + fraction * scale
        frames.append((linktype, nanoseconds, data[offset:offset + captured]))
        offset += captured
    return frames


def read_pcapng_frames(data):
    frames, interfaces, endian, offset = [], [], "<", 0
    while offset < len(data):
        if offset + 12 > len(data):
            raise ValueError("truncated pcapng block header")
        if data[offset:offset + 4] == PCAPNG_SECTION:
            endian = PCAPNG_BYTE_ORDERS.get(data[offset + 8:offset + 12])
            if endian is None:
                raise ValueError("unsupported pcapng byte order")
            interfaces = []
        block_type, length = struct.unpack_from(endian + "II", data, offset)
        if length < 12 or length % 4 or offset + length > len(data):
            raise ValueError("truncated pcapng block")
        body = data[offset + 8:offset + length - 4]
        if block_type == 1 and len(body) >= 8:
            interfaces.append((struct.unpack_from(endian + "H", body)[0], tsresol(endian, body[8:])))
        elif block_type == 6 and len(body) >= 20:
            interface, high, low, captured = struct.unpack_from(endian + "IIII", body)
            if interface >= len(interfaces) or 20 + captured > len(body):
                raise ValueError("invalid pcapng packet block")
            linktype, units = interfaces[interface]
            nanoseconds = ((high << 32) | low) * 1_000_000_000 // units
            frames.append((linktype, nanoseconds, body[20:20 + captured]))
        offset += length
    return frames


def tsresol(endian, options):
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack_from(endian + "HH", options, offset)
        if code == 0:
            break
        if code == 9 and length >= 1 and offset + 5 <= len(options):
            value = options[offset + 4]
            return 2 ** (value & 0x7F) if value & 0x80 else 10 ** value
        offset += 4 + (length + 3) // 4 * 4
    return 1_000_000


def packet_seeds(data):
    return [
        bytes([ROOT_SELECTORS[linktype]]) + frame
        for linktype, _, frame in read_frames(data)
        if linktype in ROOT_SELECTORS
    ]


def strip_link(linktype, frame):
    if linktype == 1:
        if len(frame) < 14:
            return None
        offset = 18 if frame[12:14] == b"\x81\x00" and len(frame) >= 18 else 14
        return frame[offset:]
    widths = {0: 4, 108: 4, 113: 16, 276: 20, 12: 0, 101: 0, 228: 0, 229: 0}
    width = widths.get(linktype)
    return None if width is None or len(frame) < width else frame[width:]


def ip_transport(linktype, frame):
    """Return (family, protocol, source, destination, transport) of an unfragmented packet."""
    ip = strip_link(linktype, frame)
    if not ip:
        return None
    version = ip[0] >> 4
    if version == 4 and len(ip) >= 20:
        header = (ip[0] & 0x0F) * 4
        total = struct.unpack_from("!H", ip, 2)[0]
        if header < 20 or len(ip) < header or struct.unpack_from("!H", ip, 6)[0] & 0x3FFF:
            return None
        return 4, ip[9], ip[12:16], ip[16:20], ip[header:max(header, total)]
    if version == 6 and len(ip) >= 40:
        length = struct.unpack_from("!H", ip, 4)[0]
        return 6, ip[6], ip[8:24], ip[24:40], ip[40:40 + length]
    return None


def dns_payload(linktype, frame):
    parsed = ip_transport(linktype, frame)
    if parsed is None:
        return None
    _, protocol, _, _, transport = parsed
    if protocol == UDP and len(transport) >= 8:
        source, destination = struct.unpack_from("!HH", transport)
        return transport[8:] if source in DNS_PORTS or destination in DNS_PORTS else None
    if protocol == TCP and len(transport) >= 20:
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


def tcp_segment(linktype, nanoseconds, frame):
    parsed = ip_transport(linktype, frame)
    if parsed is None or parsed[1] != TCP or len(parsed[4]) < 20:
        return None
    family, _, source, destination, transport = parsed
    ports = struct.unpack_from("!HH", transport)
    sequence, acknowledgment = struct.unpack_from("!II", transport, 4)
    header = (transport[12] >> 4) * 4
    if header < 20 or len(transport) < header:
        return None
    return Segment(
        nanoseconds, family, (source, ports[0]), (destination, ports[1]), transport[13],
        sequence, acknowledgment, struct.unpack_from("!H", transport, 14)[0], transport[header:],
    )


def tcp_segments(data):
    segments = (tcp_segment(*record) for record in read_frames(data))
    return [segment for segment in segments if segment is not None]


def conversation(segment):
    return frozenset((segment.source, segment.destination))


def client_of(segment):
    is_syn_ack = segment.flags & SYN and segment.flags & ACK
    return segment.destination if is_syn_ack else segment.source


def reassembly_seeds(segments):
    """Encode TCP segments as `ip_tcp_reassembly` input, unfragmented and fragmented."""
    clients, first_sequence = {}, {}
    for segment in segments:
        clients.setdefault(conversation(segment), (len(clients) % 4, client_of(segment)))
        first_sequence.setdefault((conversation(segment), segment.source), segment.sequence)
    records, previous = [], segments[0].nanoseconds if segments else 0
    for segment in segments[:MAX_RECORDS]:
        index, client = clients[conversation(segment)]
        peer = first_sequence.get((conversation(segment), segment.destination))
        acknowledged = 0 if peer is None or not segment.flags & ACK else segment.acknowledgment - peer
        control = (segment.source != client) | (segment.family == 6) << 1 | index << 2
        delta = max(-128, min(127, (segment.nanoseconds - previous) // 1_000_000_000))
        previous = segment.nanoseconds
        payload = segment.payload[:MAX_SEGMENT_PAYLOAD]
        header = struct.pack(
            "!BBHHHbBBBH", control, segment.flags,
            (segment.sequence - first_sequence[(conversation(segment), segment.source)]) & 0xFFFF,
            acknowledged & 0xFFFF,
            segment.window, delta, len(records) & 0xFF, FRAGMENT_UNITS, 0, len(payload),
        )
        records.append((header, payload))
    if not records:
        return []
    return [
        b"\x00" + b"".join(bytes([header[0] | mode << 4]) + header[1:] + payload
                           for header, payload in records)
        for mode in (0, IN_ORDER, REVERSED)
    ]


def http2_seed(segments):
    """Encode the first TCP conversation as `http2_connection` input."""
    if not segments:
        return None
    first = segments[0]
    client = client_of(first)
    server = first.destination if client == first.source else first.source
    selected = [segment for segment in segments if conversation(segment) == conversation(first)]
    resets = [segment for segment in selected if segment.flags & RST]
    if resets:
        close = 2 if resets[0].source == client else 3
    else:
        close = 1 if any(segment.flags & FIN for segment in selected) else 0
    settings = (
        (2 if any(segment.flags & SYN for segment in selected) else 0)
        | (4 if first.family == 6 else 0)
        | (8 if server[1] == 8080 else 0)
        | close << 4
    )
    chunks = [
        struct.pack("!BH", segment.source != client, len(segment.payload)) + segment.payload
        for segment in selected
        if segment.payload
    ][:MAX_CHUNKS]
    return bytes([settings]) + b"".join(chunks) if chunks else None


def filter_examples(source):
    """Return the filters listed in the first ```text block of `//!` module docs."""
    lines = [line[3:].strip() for line in source.splitlines() if line.startswith("//!")]
    if "```text" not in lines:
        return []
    start = lines.index("```text") + 1
    end = lines.index("```", start) if "```" in lines[start:] else len(lines)
    return [line for line in lines[start:end] if line]


def document_seed(path):
    selector = DOCUMENT_SELECTORS.get(path.stem)
    if selector is None and path.stem.startswith("packet-"):
        selector = RECIPE_SELECTOR
    return None if selector is None else bytes([selector]) + path.read_bytes()


def capture_seeds(paths):
    seeds = {"packet": [], "dns": [], "reassembly": [], "http2": [], "filter_packets": []}
    skipped = 0
    for path in paths:
        try:
            data = path.read_bytes()
            records = read_frames(data)
            packets = packet_seeds(data)
            segments = tcp_segments(data)
        except (OSError, ValueError):
            skipped += 1
            continue
        stem = path.stem
        seeds["packet"] += [(f"{stem}-{i}", seed) for i, seed in enumerate(packets)]
        payloads = (dns_payload(linktype, frame) for linktype, _, frame in records)
        seeds["dns"] += [(f"{stem}-{i}", p) for i, p in enumerate(p for p in payloads if p)]
        seeds["reassembly"] += [
            (f"{stem}-{i}", seed) for i, seed in enumerate(reassembly_seeds(segments))
        ]
        http2 = http2_seed(segments)
        seeds["http2"] += [(stem, http2)] if http2 else []
        seeds["filter_packets"] += [(stem, packets[0])] if packets else []
    return seeds, skipped


def write_seeds(directory, named):
    directory.mkdir(parents=True, exist_ok=True)
    for name, seed in named:
        (directory / f"{name}.bin").write_bytes(seed)
    return len(named)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-dir", type=pathlib.Path)
    parser.add_argument("--dns-dir", type=pathlib.Path)
    parser.add_argument("--reassembly-dir", type=pathlib.Path)
    parser.add_argument("--http2-dir", type=pathlib.Path)
    parser.add_argument("--filter-dir", type=pathlib.Path)
    parser.add_argument("--filter-source", type=pathlib.Path,
                        help="Rust source whose //! ```text block lists example filters")
    parser.add_argument("--documents-dir", type=pathlib.Path)
    parser.add_argument("--document-source", type=pathlib.Path,
                        help="directory of example documents")
    parser.add_argument("captures", type=pathlib.Path, nargs="*")
    args = parser.parse_args(argv)
    if (args.filter_dir is None) != (args.filter_source is None):
        parser.error("--filter-dir and --filter-source go together")
    if (args.documents_dir is None) != (args.document_source is None):
        parser.error("--documents-dir and --document-source go together")

    seeds, skipped = capture_seeds(args.captures)
    if args.filter_dir:
        filters = filter_examples(args.filter_source.read_text(encoding="utf-8"))
        seeds["filter"] = [(f"filter-{i}", f.encode()) for i, f in enumerate(filters)] + [
            (f"filter-{i}-{stem}", f.encode() + b"\x00" + packet)
            for i, f in enumerate(filters)
            for stem, packet in seeds["filter_packets"]
        ]
    if args.documents_dir:
        documents = sorted(args.document_source.iterdir())
        seeds["documents"] = [
            (path.stem, seed) for path in documents if (seed := document_seed(path))
        ]
    outputs = {
        "packet": args.packet_dir,
        "dns": args.dns_dir,
        "reassembly": args.reassembly_dir,
        "http2": args.http2_dir,
        "filter": args.filter_dir,
        "documents": args.documents_dir,
    }
    written = {
        target: write_seeds(directory, seeds[target])
        for target, directory in outputs.items()
        if directory is not None
    }
    print(", ".join(f"{target} seeds {count}" for target, count in written.items())
          + f", skipped captures {skipped}")
    return 0 if written and all(written.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
