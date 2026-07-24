# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Native IPv4 and IPv6 route-planning cases."""

from __future__ import annotations

import ipaddress
from typing import Any

from ..support.context import CaseContext, NativeCase
from ..support.output import invoke_json


def cases() -> tuple[NativeCase, ...]:
    return (
        NativeCase(
            name="route-ipv4",
            address_slot=1,
            source_port=50_101,
            destination_port=42_101,
            tcp_port=43_101,
            run=run_ipv4,
        ),
        NativeCase(
            name="route-ipv6",
            address_slot=2,
            source_port=50_102,
            destination_port=42_102,
            tcp_port=43_102,
            run=run_ipv6,
        ),
    )


def run_ipv4(context: CaseContext) -> dict[str, object]:
    return _run(context, "ipv4")


def run_ipv6(context: CaseContext) -> dict[str, object]:
    return _run(context, "ipv6")


def _run(context: CaseContext, family: str) -> dict[str, object]:
    topology = context.topology
    addresses = topology.addresses
    if family == "ipv4":
        source = addresses.client_ipv4
        destination = addresses.server_ipv4
        next_hop = addresses.router_client_ipv4
        packet = (
            f"ipv4(dst={destination},identification={0x1100 + context.case.address_slot})"
            f"/udp(sport={context.case.source_port},"
            f"dport={context.case.destination_port})"
            '/raw(hex="726f7574652d69707634")'
        )
        expected_version = 4
    else:
        source = addresses.client_ipv6
        destination = addresses.server_ipv6
        next_hop = addresses.router_client_ipv6
        packet = (
            f"ipv6(dst={destination})"
            f"/udp(sport={context.case.source_port},"
            f"dport={context.case.destination_port})"
            '/raw(hex="726f7574652d69707636")'
        )
        expected_version = 6

    document = invoke_json(
        context,
        "plan",
        (
            "--packet",
            packet,
            "--link-mode",
            "layer3",
        ),
    )
    result = _object(document, "result")
    plan = _object(result, "route")
    decision = _object(plan, "route")
    interface = _object(decision, "interface")
    expected_index = topology.interface_index(
        topology.names.client_namespace,
        topology.names.client_interface,
    )

    expected_values = {
        "interface.name": topology.names.client_interface,
        "interface.index": expected_index,
        "selected_address": source,
        "preferred_source": None,
        "next_hop": next_hop,
        "selection_reason": "gateway",
        "destination_scope": "private",
        "mode": "layer3",
        "lookup_destination": destination,
        "final_destination": destination,
        "packet_source": source,
    }
    actual_values = {
        "interface.name": interface.get("name"),
        "interface.index": interface.get("index"),
        "selected_address": decision.get("selected_address"),
        "preferred_source": decision.get("preferred_source"),
        "next_hop": decision.get("next_hop"),
        "selection_reason": decision.get("selection_reason"),
        "destination_scope": decision.get("destination_scope"),
        "mode": plan.get("mode"),
        "lookup_destination": plan.get("lookup_destination"),
        "final_destination": plan.get("final_destination"),
        "packet_source": plan.get("packet_source"),
    }
    if actual_values != expected_values:
        raise AssertionError(
            f"{family} planned route {actual_values!r} did not equal "
            f"{expected_values!r}"
        )
    for field in (
        decision["selected_address"],
        decision["next_hop"],
        plan["lookup_destination"],
        plan["packet_source"],
    ):
        if ipaddress.ip_address(field).version != expected_version:
            raise AssertionError(
                f"{family} plan contained wrong-family address {field!r}"
            )
    if decision.get("mtu") != 1_500:
        raise AssertionError(f"{family} route MTU was not 1500: {decision!r}")
    if decision.get("capability") != "layer2_and3":
        raise AssertionError(f"{family} veth capability was unexpected: {decision!r}")
    if plan.get("neighbor_target") is not None or plan.get("synthesized_ethernet"):
        raise AssertionError(f"{family} Layer 3 plan retained link work: {plan!r}")

    return {
        "family": family,
        "interface": interface["name"],
        "interface_index": interface["index"],
        "selected_source": source,
        "next_hop": next_hop,
    }


def _object(value: dict[str, Any], key: str) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        raise AssertionError(f"{key!r} was not an object in {value!r}")
    return child
