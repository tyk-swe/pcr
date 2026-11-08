"""Generate synthetic QUIC captures using Python cryptography independently of Rust."""

from pathlib import Path
import hmac
import ipaddress
import struct
from typing import Literal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

Version = Literal[1, 2]

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = bytes.fromhex("8394c8f03e515708")
CLIENT = bytes.fromhex("1212121212121212")
SERVER = bytes.fromhex("3434343434343434")
MIGRATED = bytes.fromhex("5656565656565656")
SECRETS = {
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET": bytes([0x33]) * 32,
    "SERVER_HANDSHAKE_TRAFFIC_SECRET": bytes([0x44]) * 32,
    "CLIENT_TRAFFIC_SECRET_0": bytes([0x55]) * 32,
    "SERVER_TRAFFIC_SECRET_0": bytes([0x66]) * 32,
}


def varint(value: int) -> bytes:
    for width, prefix in ((1, 0), (2, 0x4000), (4, 0x80000000), (8, 0xC000000000000000)):
        if value < (1 << (width * 8 - 2)):
            return (value | prefix).to_bytes(width, "big")
    raise ValueError("QUIC integer too large")


def expand(secret: bytes, label: bytes, length: int) -> bytes:
    label = b"tls13 " + label
    info = struct.pack("!HB", length, len(label)) + label + b"\0"
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)


def protect(
    secret: bytes, version: Version, header: bytes, pn_offset: int, number: int, plaintext: bytes
) -> bytes:
    label = b"quic " if version == 1 else b"quicv2 "
    key = expand(secret, label + b"key", 16)
    iv = expand(secret, label + b"iv", 12)
    hp = expand(secret, label + b"hp", 16)
    nonce = bytes(a ^ b for a, b in zip(iv, number.to_bytes(12, "big")))
    packet = bytearray(header + AESGCM(key).encrypt(nonce, plaintext, header))
    encryptor = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = encryptor.update(bytes(packet[pn_offset + 4 : pn_offset + 20]))
    packet[0] ^= mask[0] & (15 if packet[0] & 0x80 else 31)
    for index in range(4):
        packet[pn_offset + index] ^= mask[index + 1]
    return bytes(packet)


def initial_secret(version: Version, client: bool) -> bytes:
    salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a" if version == 1 else "0dede3def700a6db819381be6e269dcbf9bd2ed9")
    secret = hmac.digest(salt, ORIGINAL, "sha256")
    return expand(secret, b"client in" if client else b"server in", 32)


def long_packet(
    version: Version, kind: Literal["initial", "handshake"], client: bool, number: int, plaintext: bytes
) -> bytes:
    types = {1: {"initial": 0, "handshake": 2}, 2: {"initial": 1, "handshake": 3}}
    wire_version = 1 if version == 1 else 0x6B3343CF
    dcid = ORIGINAL if client and kind == "initial" else SERVER if client else CLIENT
    scid = CLIENT if client else SERVER
    prefix = bytes([0xC3 | (types[version][kind] << 4)]) + struct.pack("!I", wire_version) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    if kind == "initial":
        prefix += b"\0"
    if kind == "initial" and client:
        plaintext += bytes(max(0, 1200 - len(prefix) - 2 - 4 - 16 - len(plaintext)))
    header = prefix + varint(4 + len(plaintext) + 16)
    offset = len(header)
    header += number.to_bytes(4, "big")
    secret = initial_secret(version, client) if kind == "initial" else SECRETS[("CLIENT" if client else "SERVER") + "_HANDSHAKE_TRAFFIC_SECRET"]
    return protect(secret, version, header, offset, number, plaintext)


def short_packet(
    version: Version, client: bool, number: int, plaintext: bytes, update: bool = False, migrated: bool = False
) -> bytes:
    cid = MIGRATED if migrated else SERVER if client else CLIENT
    header = bytes([0x43 | (4 if update else 0)]) + cid
    offset = len(header)
    secret = SECRETS[("CLIENT" if client else "SERVER") + "_TRAFFIC_SECRET_0"]
    if update:
        next_secret = expand(secret, b"quic ku" if version == 1 else b"quicv2 ku", 32)
        wire = protect(next_secret, version, header + number.to_bytes(4, "big"), offset, number, plaintext)
        original_hp = expand(secret, b"quic hp" if version == 1 else b"quicv2 hp", 16)
        next_hp = expand(next_secret, b"quic hp" if version == 1 else b"quicv2 hp", 16)
        packet = bytearray(wire)
        sample = bytes(packet[offset + 4 : offset + 20])
        masks = [Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(sample) for key in (next_hp, original_hp)]
        packet[0] ^= (masks[0][0] ^ masks[1][0]) & 31
        for index in range(4):
            packet[offset + index] ^= masks[0][index + 1] ^ masks[1][index + 1]
        return bytes(packet)
    return protect(secret, version, header + number.to_bytes(4, "big"), offset, number, plaintext)


def extension(kind: int, value: bytes) -> bytes:
    return struct.pack("!HH", kind, len(value)) + value


def handshake(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def hello(client: bool) -> bytes:
    body = b"\3\3" + bytes([0x11 if client else 0x22]) * 32 + b"\0"
    if client:
        name = b"quic.example.test"
        server_name = b"\0" + struct.pack("!H", len(name)) + name
        extensions = extension(0, struct.pack("!H", len(server_name)) + server_name)
        extensions += extension(16, b"\0\x0a\x09quic-test") + extension(43, b"\2\3\4")
        extensions += extension(57, varint(3) + varint(2) + varint(1200))
        body += b"\0\2\x13\1\1\0"
    else:
        extensions = extension(43, b"\3\4")
        body += b"\x13\1\0"
    return handshake(1 if client else 2, body + struct.pack("!H", len(extensions)) + extensions)


def crypto(data: bytes) -> bytes:
    return b"\6\0" + varint(len(data)) + data


def stream(identifier: int, offset: int, data: bytes) -> bytes:
    return b"\x0f" + varint(identifier) + varint(offset) + varint(len(data)) + data


def ip_packet(payload: bytes, client: bool, migrated: bool = False) -> bytes:
    source, destination = ("192.0.2.1", "198.51.100.1") if client else ("198.51.100.1", "192.0.2.1")
    source_port, destination_port = ((55556 if migrated else 55555), 443) if client else (443, 55556 if migrated else 55555)
    udp = struct.pack("!HHHH", source_port, destination_port, len(payload) + 8, 0) + payload
    header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(udp) + 20, 0, 0, 64, 17, 0, ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed))
    total = sum(struct.unpack("!10H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    header[10:12] = struct.pack("!H", total ^ 0xFFFF)
    return bytes(header) + udp


def packets(version: Version) -> list[bytes]:
    extensions = extension(16, b"\0\x0a\x09quic-test") + extension(57, varint(14) + varint(1) + varint(4))
    encrypted = handshake(8, struct.pack("!H", len(extensions)) + extensions) + handshake(20, bytes([0x77]) * 32)
    new_cid = b"\x18\1\0\x08" + MIGRATED + bytes([0xAA]) * 16
    return [
        ip_packet(long_packet(version, "initial", True, 0, crypto(hello(True))), True),
        ip_packet(long_packet(version, "initial", False, 0, crypto(hello(False))) + long_packet(version, "handshake", False, 0, crypto(encrypted)), False),
        ip_packet(long_packet(version, "handshake", True, 0, crypto(handshake(20, bytes([0x88]) * 32))), True),
        ip_packet(short_packet(version, True, 1, stream(0, 5, b" world")), True),
        ip_packet(short_packet(version, True, 0, b"\x0e\0\0\5hello"), True),
        ip_packet(short_packet(version, False, 0, b"\x1e" + stream(0, 0, b"received hello world\n")), False),
        ip_packet(short_packet(version, False, 1, new_cid + b"\x1aabcdefgh" + b"\x31\5probe"), False, migrated=True),
        ip_packet(short_packet(version, True, 2, b"\x1babcdefgh" + stream(4, 0, b"updated keys\n"), update=True, migrated=True), True, migrated=True),
        ip_packet(short_packet(version, False, 2, b"\x1d\0\4done"), False),
    ]


def block(kind: int, body: bytes) -> bytes:
    body += bytes((-len(body)) % 4)
    size = len(body) + 12
    return struct.pack("<II", kind, size) + body + struct.pack("<I", size)


def write_pcap(path: Path, records: list[tuple[int, bytes, int]]) -> None:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
    body = b"".join(struct.pack("<IIII", timestamp // 1000000, timestamp % 1000000, len(packet), original) + packet for timestamp, packet, original in records)
    path.write_bytes(header + body)


def main() -> None:
    directory = ROOT / "examples/captures"
    demo = packets(1)
    records = [(1000000 + index * 10000, packet, len(packet)) for index, packet in enumerate(demo)]
    write_pcap(directory / "quic-demo-v1.pcap", records)
    truncated = (1080000, demo[0][:24], len(demo[0]))
    write_pcap(directory / "quic-demo-truncated.pcap", records[:-1] + [truncated, records[-1]])
    fragment = bytearray(demo[0][:36])
    fragment[2:8] = struct.pack("!HHH", len(fragment), 0x7711, 0x2000)
    fragment[10:12] = b"\0\0"
    checksum = sum(struct.unpack("!10H", fragment[:20]))
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    fragment[10:12] = struct.pack("!H", checksum ^ 0xFFFF)
    incomplete = records + [(1090000, bytes(fragment), len(fragment)), (122000000, demo[0], len(demo[0]))]
    write_pcap(directory / "quic-demo-incomplete-ip.pcap", incomplete)
    early_secret = bytes([0x77]) * 32
    plain = stream(0, 0, b"early")
    header = b"\xd3\0\0\0\1" + bytes([len(ORIGINAL)]) + ORIGINAL + bytes([len(CLIENT)]) + CLIENT + varint(len(plain) + 20)
    early = ip_packet(protect(early_secret, 1, header + bytes(4), len(header), 0, plain), True)
    rejected = [demo[0], early, demo[1], ip_packet(short_packet(1, True, 1, stream(0, 0, b"replacement")), True), ip_packet(short_packet(1, False, 0, b"\x1d\0\0"), False)]
    write_pcap(directory / "quic-demo-early-data.pcap", [(1000000 + index * 10000, packet, len(packet)) for index, packet in enumerate(rejected)])
    v2 = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    v2 += block(1, struct.pack("<HHI", 101, 0, 65535))
    for index, packet in enumerate(packets(2)):
        v2 += block(6, struct.pack("<IIIII", 0, 0, 1000000 + index * 10000, len(packet), len(packet)) + packet)
    (directory / "quic-demo-v2.pcapng").write_bytes(v2)
    keylog = "# Synthetic fixture secrets only, generated without an endpoint\n"
    keylog += "".join(f"{label} {(bytes([0x11]) * 32).hex()} {secret.hex()}\n" for label, secret in SECRETS.items())
    (directory / "quic-demo.keys").write_text(keylog)
    (directory / "quic-demo-early-data.keys").write_text(keylog + f"CLIENT_EARLY_TRAFFIC_SECRET {(bytes([0x11]) * 32).hex()} {early_secret.hex()}\n")


if __name__ == "__main__":
    main()
