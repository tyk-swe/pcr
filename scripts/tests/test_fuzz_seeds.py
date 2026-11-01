# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import contextlib
import io
import pathlib
import struct
import tempfile
import unittest

from support import load_script

seeds = load_script("fuzz_seeds")
DNS = bytes.fromhex("123401000001000000000000076578616d706c6504746573740000010001")


def dns_frame(linktype):
    payload = struct.pack("!HHHH", 49152, 53, 8 + len(DNS), 0) + DNS
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, 17, 0,
        bytes([192, 0, 2, 1]), bytes([192, 0, 2, 53]),
    ) + payload
    if linktype == 228:
        return ip
    return bytes.fromhex("00112233445566778899aabb0800") + ip


def pcap(linktype, frames):
    records = b"".join(
        struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame for frame in frames
    )
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype) + records


CLIENT, SERVER = bytes([192, 0, 2, 1]), bytes([198, 51, 100, 2])
SYN, ACK, FIN, PSH = 0x02, 0x10, 0x01, 0x08


def tcp_frame(source, destination, ports, sequence, acknowledgment, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", *ports, sequence, acknowledgment, 0x50, flags, 1024, 0, 0)
    return struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 1, 0, 64, 6, 0, source, destination,
    ) + tcp + payload


def timed_pcap(linktype, records):
    body = b"".join(
        struct.pack("<IIII", seconds, 0, len(frame), len(frame)) + frame
        for seconds, frame in records
    )
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype) + body


def pcapng(linktype, nanoseconds, frame):
    section = struct.pack("<IIIHHq", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1) + struct.pack("<I", 28)
    resolution = struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0)
    interface_body = struct.pack("<HHI", linktype, 0, 65535) + resolution
    interface = struct.pack("<II", 1, 12 + len(interface_body)) + interface_body + struct.pack(
        "<I", 12 + len(interface_body)
    )
    padded = frame + b"\x00" * (-len(frame) % 4)
    packet_body = struct.pack(
        "<IIIII", 0, nanoseconds >> 32, nanoseconds & 0xFFFFFFFF, len(frame), len(frame)
    ) + padded
    length = 12 + len(packet_body)
    packet = struct.pack("<II", 6, length) + packet_body + struct.pack("<I", length)
    return section + interface + packet


def handshake_and_request():
    client, server = (CLIENT, SERVER, (49152, 8080)), (SERVER, CLIENT, (8080, 49152))
    return timed_pcap(228, [
        (10, tcp_frame(*client, 1000, 0, SYN)),
        (10, tcp_frame(*server, 5000, 1001, SYN | ACK)),
        (13, tcp_frame(*client, 1001, 5001, PSH | ACK, b"GET / HTTP/1.1\r\n\r\n")),
        (13, tcp_frame(*server, 5001, 1019, PSH | ACK, b"HTTP/1.1 200 OK\r\n\r\n")),
        (14, tcp_frame(*client, 1019, 5020, FIN | ACK)),
    ])


def reassembly_records(seed):
    records, offset = [], 1
    while offset < len(seed):
        header = struct.unpack_from("!BBHHHbBBBH", seed, offset)
        offset += 14
        records.append(header + (seed[offset:offset + header[-1]],))
        offset += header[-1]
    return records


class FuzzSeedTests(unittest.TestCase):
    def test_raw_ipv4_seed_carries_selector_and_dns_payload_is_extracted(self):
        frame = dns_frame(228)
        self.assertEqual(seeds.packet_seeds(pcap(228, [frame])), [b"\x06" + frame])
        self.assertEqual(seeds.dns_payload(228, frame), DNS)

    def test_ethernet_seed_carries_selector_and_dns_payload_is_extracted(self):
        frame = dns_frame(1)
        self.assertEqual(seeds.packet_seeds(pcap(1, [frame])), [b"\x01" + frame])
        self.assertEqual(seeds.dns_payload(1, frame), DNS)

    def test_truncated_and_unknown_containers_are_rejected(self):
        whole = pcap(228, [dns_frame(228)])
        with self.assertRaises(ValueError):
            seeds.packet_seeds(whole[:-5])
        self.assertEqual(seeds.packet_seeds(pcap(999, [dns_frame(228)])), [])

    def test_pcapng_frames_yield_packet_seeds_with_declared_timestamp_resolution(self):
        frame = dns_frame(228)
        capture = pcapng(228, 1_500_000_000, frame)
        self.assertEqual(seeds.packet_seeds(capture), [b"\x06" + frame])
        self.assertEqual(seeds.read_frames(capture), [(228, 1_500_000_000, frame)])

    def test_reassembly_seed_encodes_directions_relative_sequences_and_time(self):
        plain, in_order, reversed_ = seeds.reassembly_seeds(
            seeds.tcp_segments(handshake_and_request())
        )
        self.assertEqual(plain[0], 0)
        records = reassembly_records(plain)
        self.assertEqual([r[0] & 1 for r in records], [0, 1, 0, 1, 0])
        self.assertEqual([r[2] for r in records], [0, 0, 1, 1, 19])
        self.assertEqual([r[3] for r in records], [0, 1, 1, 19, 20])
        self.assertEqual([r[5] for r in records], [0, 0, 3, 0, 1])
        self.assertEqual(records[2][-1], b"GET / HTTP/1.1\r\n\r\n")
        for mode, seed in ((1, in_order), (2, reversed_)):
            fragmented = reassembly_records(seed)
            self.assertEqual([r[0] >> 4 for r in fragmented], [mode] * 5)
            self.assertEqual([r[1:] for r in fragmented], [r[1:] for r in records])

    def test_http2_seed_carries_one_connection_as_directed_chunks(self):
        seed = seeds.http2_seed(seeds.tcp_segments(handshake_and_request()))
        handshake, port_8080, fin_close = 0x02, 0x08, 0x10
        self.assertEqual(seed[0], handshake | port_8080 | fin_close)
        request, response = b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n"
        self.assertEqual(
            seed[1:],
            struct.pack("!BH", 0, len(request)) + request
            + struct.pack("!BH", 1, len(response)) + response,
        )

    def test_filter_examples_come_from_the_first_text_block_of_module_docs(self):
        source = "\n".join([
            "//! Filters.", "//!", "//! ```text", "//! tcp.port == 80", "//!",
            "//! dns && udp", "//! ```", "//! ```text", "//! ignored", "//! ```",
            "fn main() {}",
        ])
        self.assertEqual(seeds.filter_examples(source), ["tcp.port == 80", "dns && udp"])
        self.assertEqual(seeds.filter_examples("//! no examples"), [])

    def test_main_fails_when_a_requested_corpus_receives_no_seeds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            udp_only = root / "dns.pcap"
            udp_only.write_bytes(pcap(228, [dns_frame(228)]))
            tcp = root / "tcp.pcap"
            tcp.write_bytes(handshake_and_request())
            arguments = ["--reassembly-dir", str(root / "r"), "--http2-dir", str(root / "h")]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(seeds.main(arguments + [str(udp_only)]), 1)
                self.assertEqual(seeds.main(arguments + [str(udp_only), str(tcp)]), 0)
            self.assertEqual(len(list((root / "r").iterdir())), 3)
            self.assertEqual(len(list((root / "h").iterdir())), 1)


if __name__ == "__main__":
    unittest.main()
