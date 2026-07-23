# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Native Layer 3 send cases with an independent UDP receiver."""

from __future__ import annotations

from typing import Any

from ..support.context import CaseContext, NativeCase
from ..support.output import invoke_json


def cases() -> tuple[NativeCase, ...]:
    return (
        NativeCase(
            name="send-ipv4-layer3",
            address_slot=3,
            source_port=50_103,
            destination_port=42_103,
            tcp_port=43_103,
            udp_mode="sink",
            run=run_ipv4,
        ),
        NativeCase(
            name="send-ipv6-layer3",
            address_slot=4,
            source_port=50_104,
            destination_port=42_104,
            tcp_port=43_104,
            udp_mode="sink",
            run=run_ipv6,
        ),
    )


def run_ipv4(context: CaseContext) -> dict[str, object]:
    return _run(context, "ipv4", b"native-send-ipv4")


def run_ipv6(context: CaseContext) -> dict[str, object]:
    return _run(context, "ipv6", b"native-send-ipv6")


def _run(
    context: CaseContext,
    family: str,
    payload: bytes,
) -> dict[str, object]:
    topology = context.topology
    addresses = topology.addresses
    if family == "ipv4":
        source = addresses.client_ipv4
        destination = addresses.server_ipv4
        packet = (
            f"ipv4(dst={destination},identification={0x2200 + context.case.address_slot})"
            f"/udp(sport={context.case.source_port},"
            f"dport={context.case.destination_port})"
            f'/raw(hex="{payload.hex()}")'
        )
        expected_version = 4
    else:
        source = addresses.client_ipv6
        destination = addresses.server_ipv6
        packet = (
            f"ipv6(dst={destination})"
            f"/udp(sport={context.case.source_port},"
            f"dport={context.case.destination_port})"
            f'/raw(hex="{payload.hex()}")'
        )
        expected_version = 6

    document = invoke_json(
        context,
        "send",
        (
            "--packet",
            packet,
            "--interface",
            topology.names.client_interface,
            "--source",
            source,
            "--link-mode",
            "layer3",
        ),
        timeout=8.0,
    )
    event = context.require_responder().wait_event(
        "udp_request",
        family,
        timeout=5.0,
    )
    expected_event = {
        "listener_address": destination,
        "listener_port": context.case.destination_port,
        "peer_address": source,
        "peer_port": context.case.source_port,
        "request_hex": payload.hex(),
        "request_bytes": len(payload),
        "response_source_port": None,
        "udp_mode": "sink",
    }
    actual_event = {key: event.get(key) for key in expected_event}
    if actual_event != expected_event:
        raise AssertionError(
            f"{family} independent receiver event {actual_event!r} did not "
            f"equal {expected_event!r}"
        )

    result = _object(document, "result")
    frame = _object(result, "frame")
    route = _object(result, "route")
    plan = _object(route, "plan")
    decision = _object(plan, "route")
    wire_hex = frame.get("bytes_hex")
    if not isinstance(wire_hex, str):
        raise AssertionError(f"{family} send omitted exact wire bytes: {frame!r}")
    wire = bytes.fromhex(wire_hex)
    if not wire or wire[0] >> 4 != expected_version:
        raise AssertionError(f"{family} send emitted wrong IP version: {wire_hex!r}")
    if frame.get("length") != len(wire):
        raise AssertionError(f"{family} send length disagreed with wire bytes: {frame!r}")
    if plan.get("mode") != "layer3":
        raise AssertionError(f"{family} send did not use Layer 3: {plan!r}")
    if decision.get("interface", {}).get("name") != topology.names.client_interface:
        raise AssertionError(f"{family} send used wrong interface: {decision!r}")
    if plan.get("packet_source") != source:
        raise AssertionError(f"{family} send used wrong packet source: {plan!r}")
    stats = _object(document, "stats")
    if stats.get("packets_attempted") != 1 or stats.get("packets_completed") != 1:
        raise AssertionError(f"{family} send statistics were unexpected: {stats!r}")
    if stats.get("bytes") != len(wire):
        raise AssertionError(f"{family} byte statistics were unexpected: {stats!r}")

    return {
        "family": family,
        "bytes": len(wire),
        "source": source,
        "destination": destination,
        "independent_receiver": True,
    }


def _object(value: dict[str, Any], key: str) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        raise AssertionError(f"{key!r} was not an object in {value!r}")
    return child
