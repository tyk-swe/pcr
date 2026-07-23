# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Independent baseline connectivity checks for all routed socket families."""

from __future__ import annotations

import json
from dataclasses import dataclass

from ..support.command import CommandFailure
from ..support.context import CaseContext
from ..support.fixture_process import TCP_PORT, UDP_PORT


class ConnectivityError(RuntimeError):
    """An independent socket fixture did not traverse the topology."""


@dataclass(frozen=True)
class Check:
    name: str
    family: str
    transport: str
    source: str
    destination: str
    port: int


def run(context: CaseContext, forced_failure: str | None = None) -> list[dict[str, object]]:
    addresses = context.topology.addresses
    checks = (
        Check(
            "ipv4-udp",
            "ipv4",
            "udp",
            addresses.client_ipv4,
            addresses.server_ipv4,
            UDP_PORT,
        ),
        Check(
            "ipv6-udp",
            "ipv6",
            "udp",
            addresses.client_ipv6,
            addresses.server_ipv6,
            UDP_PORT,
        ),
        Check(
            "ipv4-tcp",
            "ipv4",
            "tcp",
            addresses.client_ipv4,
            addresses.server_ipv4,
            TCP_PORT,
        ),
        Check(
            "ipv6-tcp",
            "ipv6",
            "tcp",
            addresses.client_ipv6,
            addresses.server_ipv6,
            TCP_PORT,
        ),
    )
    results: list[dict[str, object]] = []
    client = context.native_e2e_root / "fixtures" / "socket_client.py"

    for check in checks:
        context.responder.ensure_running()
        payload = f"{context.topology.names.run_id}:{check.name}"
        command = [
            "ip",
            "netns",
            "exec",
            context.topology.names.client_namespace,
            "python3",
            str(client),
            "--family",
            check.family,
            "--transport",
            check.transport,
            "--source",
            check.source,
            "--destination",
            check.destination,
            "--port",
            str(check.port),
            "--payload",
            payload,
            "--timeout",
            "3",
        ]
        if forced_failure == check.name:
            command.extend(("--expected", "intentional-native-e2e-mismatch"))
        try:
            completed = context.runner.run(
                command,
                privileged=True,
                timeout=8.0,
            )
        except CommandFailure as error:
            raise ConnectivityError(f"{check.name} failed: {error}") from error
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise ConnectivityError(
                f"{check.name} returned invalid JSON: {completed.stdout!r}"
            ) from error
        if not isinstance(result, dict):
            raise ConnectivityError(
                f"{check.name} returned a non-object result: {result!r}"
            )
        context.responder.ensure_running()
        results.append(result)
        print(
            f"PASS {check.name}: {result['source']} -> "
            f"{result['destination']}:{result['port']}",
            flush=True,
        )
    return results
