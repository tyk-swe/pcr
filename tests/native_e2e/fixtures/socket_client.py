#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Standard-library socket verifier, deliberately independent of PacketcraftR."""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys

RESPONSE_PREFIX = b"packetcraftr-native-e2e/"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--family", required=True, choices=("ipv4", "ipv6"))
    parser.add_argument("--transport", required=True, choices=("udp", "tcp"))
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--payload", required=True)
    parser.add_argument("--expected")
    parser.add_argument("--timeout", type=float, default=3.0)
    return parser.parse_args()


def endpoint(family: int, address: str, port: int) -> tuple[object, ...]:
    if family == socket.AF_INET6:
        return (address, port, 0, 0)
    return (address, port)


def verify_udp(
    family: int,
    source: str,
    destination: str,
    port: int,
    payload: bytes,
    timeout: float,
) -> tuple[bytes, tuple[object, ...]]:
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.bind(endpoint(family, source, 0))
        client.connect(endpoint(family, destination, port))
        client.send(payload)
        response = client.recv(65_535)
        return response, client.getsockname()


def verify_tcp(
    family: int,
    source: str,
    destination: str,
    port: int,
    payload: bytes,
    timeout: float,
) -> tuple[bytes, tuple[object, ...]]:
    with socket.socket(family, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.bind(endpoint(family, source, 0))
        client.connect(endpoint(family, destination, port))
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while True:
            chunk = client.recv(65_536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), client.getsockname()


def main() -> int:
    arguments = parse_arguments()
    family = socket.AF_INET if arguments.family == "ipv4" else socket.AF_INET6
    payload = arguments.payload.encode("utf-8")
    expected = (
        arguments.expected.encode("utf-8")
        if arguments.expected is not None
        else RESPONSE_PREFIX + arguments.transport.encode("ascii") + b":" + payload
    )
    try:
        if arguments.transport == "udp":
            response, local = verify_udp(
                family,
                arguments.source,
                arguments.destination,
                arguments.port,
                payload,
                arguments.timeout,
            )
        else:
            response, local = verify_tcp(
                family,
                arguments.source,
                arguments.destination,
                arguments.port,
                payload,
                arguments.timeout,
            )
        if response != expected:
            raise AssertionError(
                f"response {response!r} did not equal {expected!r}"
            )
        if ipaddress.ip_address(str(local[0])) != ipaddress.ip_address(
            arguments.source
        ):
            raise AssertionError(
                f"socket selected source {local[0]}, expected {arguments.source}"
            )
    except BaseException as error:
        print(
            f"{arguments.family} {arguments.transport} fixture check failed: "
            f"{type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            {
                "family": arguments.family,
                "transport": arguments.transport,
                "source": local[0],
                "destination": arguments.destination,
                "port": arguments.port,
                "request_bytes": len(payload),
                "response_bytes": len(response),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
