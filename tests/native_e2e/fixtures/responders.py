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
    parser.add_argument(
        "--udp-mode",
        choices=("echo", "sink", "wrong-port"),
        default="echo",
    )
    parser.add_argument("--udp-response-port", type=int)
    parser.add_argument("--ready-socket", required=True)
    parser.add_argument("--ready-token", required=True)
    parser.add_argument("--event-socket", required=True)
    parser.add_argument("--event-token", required=True)
    arguments = parser.parse_args()
    if arguments.udp_mode == "wrong-port" and arguments.udp_response_port is None:
        parser.error("--udp-response-port is required for --udp-mode wrong-port")
    if arguments.udp_response_port == arguments.udp_port:
        parser.error("--udp-response-port must differ from --udp-port")
    return arguments


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
    udp_mode: str,
    udp_response_port: int | None,
) -> None:
    message = {
        "token": token,
        "pid": os.getpid(),
        "listeners": [listener.ready_value() for listener in listeners],
        "udp_mode": udp_mode,
        "udp_response_port": udp_response_port,
    }
    signal_message(path, message)


def signal_message(path: str, message: dict[str, object]) -> None:
    encoded = (json.dumps(message, sort_keys=True) + "\n").encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as readiness:
        readiness.settimeout(5.0)
        readiness.connect(path)
        readiness.sendall(encoded)


def handle_udp(
    listener: Listener,
    arguments: argparse.Namespace,
    response_sockets: dict[str, socket.socket],
) -> None:
    payload, peer = listener.socket.recvfrom(65_535)
    response = RESPONSE_PREFIX + b"udp:" + payload
    response_source_port: int | None = None
    if arguments.udp_mode == "echo":
        listener.socket.sendto(response, peer)
        response_source_port = listener.port
    elif arguments.udp_mode == "wrong-port":
        response_socket = response_sockets[listener.family_name]
        response_socket.sendto(response, peer)
        response_source_port = arguments.udp_response_port
    event = {
        "token": arguments.event_token,
        "event": "udp_request",
        "family": listener.family_name,
        "transport": "udp",
        "listener_address": listener.address,
        "listener_port": listener.port,
        "peer_address": peer[0],
        "peer_port": peer[1],
        "request_hex": payload.hex(),
        "request_bytes": len(payload),
        "response_hex": response.hex() if response_source_port is not None else None,
        "response_bytes": len(response) if response_source_port is not None else 0,
        "response_source_port": response_source_port,
        "udp_mode": arguments.udp_mode,
    }
    signal_message(arguments.event_socket, event)
    print(
        json.dumps(event, sort_keys=True),
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
    response_sockets: dict[str, socket.socket] = {}
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
            if arguments.udp_response_port is not None:
                response = open_listener(
                    family,
                    family_name,
                    "udp",
                    address,
                    arguments.udp_response_port,
                )
                response_sockets[family_name] = response.socket

        signal_ready(
            arguments.ready_socket,
            arguments.ready_token,
            listeners,
            arguments.udp_mode,
            arguments.udp_response_port,
        )
        print(
            json.dumps(
                {
                    "event": "ready",
                    "pid": os.getpid(),
                    "udp_mode": arguments.udp_mode,
                    "udp_response_port": arguments.udp_response_port,
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
                    handle_udp(listener, arguments, response_sockets)
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
        for response in response_sockets.values():
            response.close()


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
