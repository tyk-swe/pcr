#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Independent IPv4/IPv6 UDP and TCP responders for native E2E tests."""

from __future__ import annotations

import argparse
import json
import os
import selectors
import signal
import socket
import sys
from dataclasses import dataclass
from typing import NoReturn

MAX_REQUEST_BYTES = 1024 * 1024
RESPONSE_PREFIX = b"packetcraftr-native-e2e/"


class FixtureStopping(Exception):
    """Raised by the signal handler to unwind blocking socket work."""


@dataclass(frozen=True)
class Listener:
    family_name: str
    transport: str
    address: str
    port: int
    socket: socket.socket

    def ready_value(self) -> dict[str, object]:
        return {
            "family": self.family_name,
            "transport": self.transport,
            "address": self.address,
            "port": self.port,
        }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ipv4", required=True)
    parser.add_argument("--ipv6", required=True)
    parser.add_argument("--udp-port", required=True, type=int)
    parser.add_argument("--tcp-port", required=True, type=int)
    parser.add_argument("--ready-socket", required=True)
    parser.add_argument("--ready-token", required=True)
    return parser.parse_args()


def socket_address(family: int, address: str, port: int) -> tuple[object, ...]:
    if family == socket.AF_INET6:
        return (address, port, 0, 0)
    return (address, port)


def open_listener(
    family: int,
    family_name: str,
    transport: str,
    address: str,
    port: int,
) -> Listener:
    kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    listener = socket.socket(family, kind)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind(socket_address(family, address, port))
        if transport == "tcp":
            listener.listen(16)
        listener.setblocking(False)
        return Listener(family_name, transport, address, port, listener)
    except BaseException:
        listener.close()
        raise


def signal_ready(
    path: str,
    token: str,
    listeners: list[Listener],
) -> None:
    message = {
        "token": token,
        "pid": os.getpid(),
        "listeners": [listener.ready_value() for listener in listeners],
    }
    encoded = (json.dumps(message, sort_keys=True) + "\n").encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as readiness:
        readiness.settimeout(5.0)
        readiness.connect(path)
        readiness.sendall(encoded)


def handle_udp(listener: Listener) -> None:
    payload, peer = listener.socket.recvfrom(65_535)
    response = RESPONSE_PREFIX + b"udp:" + payload
    listener.socket.sendto(response, peer)
    print(
        json.dumps(
            {
                "event": "response",
                "family": listener.family_name,
                "transport": "udp",
                "peer": peer,
                "request_bytes": len(payload),
                "response_bytes": len(response),
            },
            sort_keys=True,
        ),
        flush=True,
    )


def handle_tcp(listener: Listener) -> None:
    connection, peer = listener.socket.accept()
    with connection:
        connection.settimeout(5.0)
        chunks: list[bytes] = []
        received = 0
        while True:
            chunk = connection.recv(65_536)
            if not chunk:
                break
            received += len(chunk)
            if received > MAX_REQUEST_BYTES:
                raise ValueError(
                    f"TCP request exceeded {MAX_REQUEST_BYTES} bytes"
                )
            chunks.append(chunk)
        payload = b"".join(chunks)
        response = RESPONSE_PREFIX + b"tcp:" + payload
        connection.sendall(response)
    print(
        json.dumps(
            {
                "event": "response",
                "family": listener.family_name,
                "transport": "tcp",
                "peer": peer,
                "request_bytes": len(payload),
                "response_bytes": len(response),
            },
            sort_keys=True,
        ),
        flush=True,
    )


def stop_on_signal(signum: int, _frame: object) -> NoReturn:
    raise FixtureStopping(f"received signal {signum}")


def serve(arguments: argparse.Namespace) -> None:
    listeners: list[Listener] = []
    selector = selectors.DefaultSelector()
    try:
        for family, family_name, address in (
            (socket.AF_INET, "ipv4", arguments.ipv4),
            (socket.AF_INET6, "ipv6", arguments.ipv6),
        ):
            for transport, port in (
                ("udp", arguments.udp_port),
                ("tcp", arguments.tcp_port),
            ):
                listener = open_listener(
                    family,
                    family_name,
                    transport,
                    address,
                    port,
                )
                listeners.append(listener)
                selector.register(listener.socket, selectors.EVENT_READ, listener)

        signal_ready(arguments.ready_socket, arguments.ready_token, listeners)
        print(
            json.dumps(
                {
                    "event": "ready",
                    "pid": os.getpid(),
                    "listeners": [
                        listener.ready_value() for listener in listeners
                    ],
                },
                sort_keys=True,
            ),
            flush=True,
        )
        while True:
            for key, _events in selector.select():
                listener = key.data
                if listener.transport == "udp":
                    handle_udp(listener)
                else:
                    handle_tcp(listener)
    except FixtureStopping as stopping:
        print(
            json.dumps({"event": "stopping", "reason": str(stopping)}),
            flush=True,
        )
    finally:
        selector.close()
        for listener in listeners:
            listener.socket.close()


def main() -> int:
    arguments = parse_arguments()
    signal.signal(signal.SIGINT, stop_on_signal)
    signal.signal(signal.SIGTERM, stop_on_signal)
    try:
        serve(arguments)
    except BaseException as error:
        print(f"responder failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
