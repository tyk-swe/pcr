# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Native UDP exchange, timeout, and unsolicited-response cases."""

from __future__ import annotations

from typing import Any

from ..support.context import CaseContext, NativeCase
from ..support.output import invoke_json, packet_field

RESPONSE_PREFIX = b"packetcraftr-native-e2e/udp:"


def cases() -> tuple[NativeCase, ...]:
    return (
        NativeCase(
            name="exchange-udp-success",
            address_slot=5,
            source_port=50_105,
            destination_port=42_105,
            tcp_port=43_105,
            udp_mode="echo",
            run=run_success,
        ),
        NativeCase(
            name="exchange-timeout",
            address_slot=6,
            source_port=50_106,
            destination_port=42_106,
            tcp_port=43_106,
            udp_mode="sink",
            run=run_timeout,
        ),
        NativeCase(
            name="exchange-unsolicited-rejection",
            address_slot=7,
            source_port=50_107,
            destination_port=42_107,
            tcp_port=43_107,
            udp_mode="wrong-port",
            response_port=44_107,
            run=run_unsolicited_rejection,
        ),
    )


def run_success(context: CaseContext) -> dict[str, object]:
    payload = b"native-exchange-success"
    document = _exchange(context, payload, timeout_ms=450)
    event = _wait_request_event(context, payload)
    if event.get("response_source_port") != context.case.destination_port:
        raise AssertionError(f"echo fixture responded from wrong port: {event!r}")

    result = _object(document, "result")
    responses = _array(result, "responses")
    if len(responses) != 1:
        raise AssertionError(f"successful exchange retained {len(responses)} responses")
    if result.get("unanswered") != []:
        raise AssertionError(f"successful exchange was unanswered: {result!r}")
    response_entry = responses[0]
    if not isinstance(response_entry, dict) or response_entry.get("request_index") != 0:
        raise AssertionError(f"response correlation index was invalid: {response_entry!r}")
    response = _object(response_entry, "response")
    _assert_udp_packet(
        response,
        source=context.topology.addresses.server_ipv4,
        destination=context.topology.addresses.client_ipv4,
        source_port=context.case.destination_port,
        destination_port=context.case.source_port,
    )
    raw_value = packet_field(response, "raw", "bytes")
    expected_response = RESPONSE_PREFIX + payload
    if not isinstance(raw_value, list) or bytes(raw_value) != expected_response:
        raise AssertionError(
            f"captured response payload {raw_value!r} did not equal "
            f"{expected_response!r}"
        )
    stats = _object(document, "stats")
    capture = _object(stats, "capture")
    if capture.get("received_frames", 0) < 1 or capture.get("received_bytes", 0) < 1:
        raise AssertionError(
            f"successful exchange did not prove active native capture: {capture!r}"
        )
    if stats.get("packets_attempted") != 1 or stats.get("packets_completed") != 1:
        raise AssertionError(f"successful exchange send statistics failed: {stats!r}")

    return {
        "classification": "response",
        "responses": 1,
        "capture_received_frames": capture["received_frames"],
        "fixture_response_source_port": event["response_source_port"],
    }


def run_timeout(context: CaseContext) -> dict[str, object]:
    payload = b"native-exchange-timeout"
    document = _exchange(context, payload, timeout_ms=250)
    event = _wait_request_event(context, payload)
    if event.get("response_source_port") is not None:
        raise AssertionError(f"timeout fixture unexpectedly responded: {event!r}")

    result = _object(document, "result")
    if result.get("responses") != [] or result.get("unanswered") != [0]:
        raise AssertionError(
            "exchange timeout must be a successful bounded operation with one "
            f"unanswered request: {result!r}"
        )
    invocation = context.invocations[-1]
    if invocation.outcome != "exit 0":
        raise AssertionError(f"exchange timeout exit behavior changed: {invocation!r}")
    if invocation.elapsed_seconds >= 6.0:
        raise AssertionError(
            f"exchange timeout exceeded its outer process bound: {invocation!r}"
        )
    stats = _object(document, "stats")
    if stats.get("packets_attempted") != 1 or stats.get("packets_completed") != 1:
        raise AssertionError(f"timeout send statistics were unexpected: {stats!r}")

    return {
        "classification": "timeout_unanswered",
        "exit_code": 0,
        "timeout_ms": 250,
        "fixture_received_request": True,
    }


def run_unsolicited_rejection(context: CaseContext) -> dict[str, object]:
    payload = b"native-exchange-unsolicited"
    document = _exchange(context, payload, timeout_ms=350)
    event = _wait_request_event(context, payload)
    if event.get("response_source_port") != context.case.response_port:
        raise AssertionError(f"wrong-port fixture event was invalid: {event!r}")
    if context.case.response_port == context.case.destination_port:
        raise AssertionError("unsolicited fixture did not change the UDP source port")

    result = _object(document, "result")
    if result.get("responses") != [] or result.get("unanswered") != [0]:
        raise AssertionError(
            f"wrong-port UDP response was incorrectly correlated: {result!r}"
        )
    unsolicited = _array(result, "unsolicited")
    observed = []
    for decoded in unsolicited:
        if not isinstance(decoded, dict):
            continue
        try:
            source_port = packet_field(decoded, "udp", "source_port")
            destination_port = packet_field(decoded, "udp", "destination_port")
            source = packet_field(decoded, "ipv4", "source")
            destination = packet_field(decoded, "ipv4", "destination")
            response_payload = packet_field(decoded, "raw", "bytes")
        except AssertionError:
            continue
        if (
            source_port == context.case.response_port
            and destination_port == context.case.source_port
            and source == context.topology.addresses.server_ipv4
            and destination == context.topology.addresses.client_ipv4
            and isinstance(response_payload, list)
            and bytes(response_payload) == RESPONSE_PREFIX + payload
        ):
            observed.append(decoded)
    if len(observed) != 1:
        raise AssertionError(
            "native capture did not retain exactly one deliberately wrong-port "
            f"response; observed={len(observed)}, unsolicited={unsolicited!r}"
        )
    capture = _object(_object(document, "stats"), "capture")
    if capture.get("received_frames", 0) < 1:
        raise AssertionError(f"unsolicited traffic was not captured: {capture!r}")

    return {
        "classification": "timeout_unanswered",
        "unsolicited_observed": True,
        "matcher_key": "udp_source_port",
        "expected_source_port": context.case.destination_port,
        "observed_source_port": context.case.response_port,
    }


def _exchange(
    context: CaseContext,
    payload: bytes,
    *,
    timeout_ms: int,
) -> dict[str, Any]:
    topology = context.topology
    packet = (
        f"ipv4(dst={topology.addresses.server_ipv4},"
        f"identification={0x3300 + context.case.address_slot})"
        f"/udp(sport={context.case.source_port},"
        f"dport={context.case.destination_port})"
        f'/raw(hex="{payload.hex()}")'
    )
    return invoke_json(
        context,
        "exchange",
        (
            "--packet",
            packet,
            "--interface",
            topology.names.client_interface,
            "--source",
            topology.addresses.client_ipv4,
            "--link-mode",
            "layer3",
            "--timeout-ms",
            str(timeout_ms),
            "--max-responses",
            "8",
            "--max-unsolicited",
            "32",
            "--max-queue-frames",
            "64",
            "--max-captured-bytes",
            "1048576",
            "--snap-length",
            "65535",
        ),
        timeout=6.0,
    )


def _wait_request_event(
    context: CaseContext,
    payload: bytes,
) -> dict[str, Any]:
    event = context.require_responder().wait_event(
        "udp_request",
        "ipv4",
        timeout=5.0,
    )
    expected = {
        "listener_address": context.topology.addresses.server_ipv4,
        "listener_port": context.case.destination_port,
        "peer_address": context.topology.addresses.client_ipv4,
        "peer_port": context.case.source_port,
        "request_hex": payload.hex(),
        "request_bytes": len(payload),
        "udp_mode": context.case.udp_mode,
    }
    response = None if context.case.udp_mode == "sink" else RESPONSE_PREFIX + payload
    expected["response_hex"] = None if response is None else response.hex()
    expected["response_bytes"] = 0 if response is None else len(response)
    actual = {key: event.get(key) for key in expected}
    if actual != expected:
        raise AssertionError(
            f"independent exchange fixture event {actual!r} did not equal "
            f"{expected!r}"
        )
    return event


def _assert_udp_packet(
    decoded: dict[str, Any],
    *,
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
) -> None:
    expected = {
        "source": source,
        "destination": destination,
        "source_port": source_port,
        "destination_port": destination_port,
    }
    actual = {
        "source": packet_field(decoded, "ipv4", "source"),
        "destination": packet_field(decoded, "ipv4", "destination"),
        "source_port": packet_field(decoded, "udp", "source_port"),
        "destination_port": packet_field(decoded, "udp", "destination_port"),
    }
    if actual != expected:
        raise AssertionError(
            f"captured UDP response {actual!r} did not equal {expected!r}"
        )


def _object(value: dict[str, Any], key: str) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        raise AssertionError(f"{key!r} was not an object in {value!r}")
    return child


def _array(value: dict[str, Any], key: str) -> list[Any]:
    child = value.get(key)
    if not isinstance(child, list):
        raise AssertionError(f"{key!r} was not an array in {value!r}")
    return child
