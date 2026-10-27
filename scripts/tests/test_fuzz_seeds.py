# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import struct
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


if __name__ == "__main__":
    unittest.main()
