#!/usr/bin/env python3
"""Deterministic private-network peers for privileged Linux qualification."""

# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import selectors
import signal
import socket
import struct
from collections.abc import Callable
from pathlib import Path


DNS_HEADER_BYTES = 12
DNS_CLASS_IN = 1
DNS_TYPE_A = 1


def dns_response(query: bytes) -> bytes | None:
    """Return one deterministic A response for a bounded standard query."""
    if len(query) < DNS_HEADER_BYTES:
        return None
    transaction_id, flags, questions, _, _, _ = struct.unpack("!6H", query[:12])
    if flags & 0x8000 or questions != 1:
        return None

    cursor = DNS_HEADER_BYTES
    labels = 0
    while True:
        if cursor >= len(query):
            return None
        length = query[cursor]
        cursor += 1
        if length == 0:
            break
        if length > 63 or cursor + length > len(query):
            return None
        cursor += length
        labels += 1
        if labels > 32:
            return None
    if cursor + 4 != len(query):
        return None
    query_type, query_class = struct.unpack("!HH", query[cursor : cursor + 4])
    if query_type != DNS_TYPE_A or query_class != DNS_CLASS_IN:
        return None

    response_flags = 0x8000 | 0x0080 | (flags & 0x0100)
    header = struct.pack("!6H", transaction_id, response_flags, 1, 1, 0, 0)
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", DNS_TYPE_A, DNS_CLASS_IN, 60, 4)
        + socket.inet_aton("192.0.2.49")
    )
    return header + query[DNS_HEADER_BYTES:] + answer


def register_udp(
    selector: selectors.BaseSelector,
    family: socket.AddressFamily,
    address: str,
    port: int,
    handler: Callable[[bytes], bytes | None],
) -> socket.socket:
    sock = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((address, port))
    sock.setblocking(False)

    def receive() -> None:
        data, peer = sock.recvfrom(65_535)
        response = handler(data)
        if response is not None:
            sock.sendto(response, peer)

    selector.register(sock, selectors.EVENT_READ, receive)
    return sock


def register_tcp(
    selector: selectors.BaseSelector,
    family: socket.AddressFamily,
    address: str,
    port: int,
) -> socket.socket:
    sock = socket.socket(family, socket.SOCK_STREAM)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    sock.listen()
    sock.setblocking(False)

    def accept() -> None:
        connection, _ = sock.accept()
        connection.close()

    selector.register(sock, selectors.EVENT_READ, accept)
    return sock


def serve(args: argparse.Namespace) -> int:
    selector = selectors.DefaultSelector()
    sockets = [
        register_udp(selector, socket.AF_INET, args.ipv4, args.echo_port, lambda data: data),
        register_udp(selector, socket.AF_INET6, args.ipv6, args.echo_port, lambda data: data),
        register_udp(selector, socket.AF_INET, args.ipv4, args.dns_port, dns_response),
        register_udp(selector, socket.AF_INET6, args.ipv6, args.dns_port, dns_response),
        register_tcp(selector, socket.AF_INET, args.ipv4, args.tcp_port),
        register_tcp(selector, socket.AF_INET6, args.ipv6, args.tcp_port),
    ]
    running = True

    def stop(_signum: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    print(
        f"ready ipv4={args.ipv4} ipv6={args.ipv6} "
        f"echo={args.echo_port} dns={args.dns_port} tcp={args.tcp_port}",
        flush=True,
    )
    try:
        while running:
            for key, _ in selector.select(timeout=0.25):
                key.data()
    finally:
        for sock in sockets:
            selector.unregister(sock)
            sock.close()
        selector.close()
    return 0


def inject(args: argparse.Namespace) -> int:
    frame = bytes.fromhex(args.frame_hex)
    if len(frame) < 14:
        raise ValueError("an injected Ethernet frame must contain at least 14 bytes")
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    try:
        sock.bind((args.interface, 0))
        for _ in range(args.count):
            sent = sock.send(frame)
            if sent != len(frame):
                raise RuntimeError(f"partial AF_PACKET send: {sent}/{len(frame)}")
    finally:
        sock.close()
    return 0


def make_pcap(args: argparse.Namespace) -> int:
    frame = bytes.fromhex(args.frame_hex)
    if not frame:
        raise ValueError("a PCAP frame cannot be empty")
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, args.link_type)
    record = struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
    Path(args.output).write_bytes(header + record)
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)

    serve_parser = commands.add_parser("serve")
    serve_parser.add_argument("--ipv4", required=True)
    serve_parser.add_argument("--ipv6", required=True)
    serve_parser.add_argument("--echo-port", type=int, default=9_000)
    serve_parser.add_argument("--dns-port", type=int, default=5_353)
    serve_parser.add_argument("--tcp-port", type=int, default=9_443)
    serve_parser.set_defaults(run=serve)

    inject_parser = commands.add_parser("inject")
    inject_parser.add_argument("--interface", required=True)
    inject_parser.add_argument("--frame-hex", required=True)
    inject_parser.add_argument("--count", type=int, default=1)
    inject_parser.set_defaults(run=inject)

    pcap_parser = commands.add_parser("make-pcap")
    pcap_parser.add_argument("--frame-hex", required=True)
    pcap_parser.add_argument("--link-type", type=int, default=1)
    pcap_parser.add_argument("--output", required=True)
    pcap_parser.set_defaults(run=make_pcap)
    return result


def main() -> int:
    args = parser().parse_args()
    if getattr(args, "count", 1) < 1:
        raise ValueError("count must be positive")
    return args.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
