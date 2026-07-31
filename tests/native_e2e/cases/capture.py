# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Native capture-filter budget and invalid-expression cases."""

from __future__ import annotations

import json
import subprocess
from typing import Any

from ..support.context import CaseContext, NativeCase

PRIME_SCRIPT = """\
import socket
import sys
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((sys.argv[1], int(sys.argv[2])))
sock.sendto(b"prime-neighbor", (sys.argv[3], int(sys.argv[4])))
time.sleep(0.4)
"""

EMITTER_SCRIPT = """\
import socket
import sys
import time
from pathlib import Path

target_netns = Path("/run/netns", sys.argv[1]).stat().st_ino
deadline = time.monotonic() + 5.0
initial_switches = {}
while True:
    for task in Path("/proc").glob("[0-9]*/task/*"):
        try:
            # Linux truncates the named capture worker to 15 bytes. It enters
            # repeated native receive waits only after reporting ready.
            if (task / "comm").read_text().strip() != "packetcraftr-ca":
                continue
            if (task.parents[1] / "ns/net").stat().st_ino != target_netns:
                continue
            switches = next(
                int(line.split()[1])
                for line in (task / "status").read_text().splitlines()
                if line.startswith("voluntary_ctxt_switches:")
            )
            first = initial_switches.setdefault(str(task), switches)
            if switches >= first + 2:
                break
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    else:
        if time.monotonic() >= deadline:
            raise RuntimeError("capture worker did not become ready")
        time.sleep(0.01)
        continue
    break

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((sys.argv[2], int(sys.argv[3])))
sock.sendto(b"wrong-port", (sys.argv[4], int(sys.argv[5])))
sock.sendto(b"selected-port", (sys.argv[4], int(sys.argv[6])))
"""


def cases() -> tuple[NativeCase, ...]:
    return (
        NativeCase(
            name="capture-native-filter-before-budget",
            address_slot=8,
            source_port=50_108,
            destination_port=42_108,
            tcp_port=43_108,
            run=run_filter_before_budget,
        ),
        NativeCase(
            name="capture-invalid-native-filter",
            address_slot=9,
            source_port=50_109,
            destination_port=42_109,
            tcp_port=43_109,
            run=run_invalid_filter,
        ),
    )


def run_filter_before_budget(context: CaseContext) -> dict[str, object]:
    topology = context.topology
    addresses = topology.addresses
    context.runner.run(
        (
            "ip",
            "netns",
            "exec",
            topology.names.server_namespace,
            "python3",
            "-c",
            PRIME_SCRIPT,
            addresses.server_ipv4,
            str(context.case.source_port),
            addresses.client_ipv4,
            str(context.case.tcp_port),
        ),
        privileged=True,
        timeout=3.0,
    )

    emitter_stdout_path = context.temporary_directory / "capture-emitter.stdout"
    emitter_stderr_path = context.temporary_directory / "capture-emitter.stderr"
    with emitter_stdout_path.open("w", encoding="utf-8") as emitter_stdout, (
        emitter_stderr_path.open("w", encoding="utf-8")
    ) as emitter_stderr:
        emitter = context.runner.start(
            (
                "ip",
                "netns",
                "exec",
                topology.names.server_namespace,
                "python3",
                "-c",
                EMITTER_SCRIPT,
                topology.names.client_namespace,
                addresses.server_ipv4,
                str(context.case.source_port),
                addresses.client_ipv4,
                str(context.case.tcp_port),
                str(context.case.destination_port),
            ),
            privileged=True,
            stdout=emitter_stdout,
            stderr=emitter_stderr,
        )
        try:
            completed = context.run_packetcraftr(
                (
                    "--output",
                    "ndjson",
                    "capture",
                    "--packet",
                    f"ipv4(dst={addresses.server_ipv4})"
                    f"/udp(dport={context.case.destination_port})",
                    "--interface",
                    topology.names.client_interface,
                    "--timeout-ms",
                    "2500",
                    "--max-packets",
                    "1",
                    "--capture-filter",
                    f"udp dst port {context.case.destination_port}",
                    "--filter",
                    f"udp.destination_port == {context.case.destination_port}",
                ),
                timeout=6.0,
            )
        finally:
            try:
                emitter.wait(timeout=3.0)
            except subprocess.TimeoutExpired as error:
                emitter.kill()
                emitter.wait(timeout=1.0)
                raise AssertionError("capture traffic emitter did not exit") from error
            finally:
                context.runner.note_process_exit(emitter)

    if emitter.returncode != 0:
        diagnostic = emitter_stderr_path.read_text(encoding="utf-8")
        raise AssertionError(
            f"capture traffic emitter exited {emitter.returncode}: {diagnostic}"
        )
    records = _records(completed)
    if completed.returncode != 0:
        raise AssertionError(f"filtered capture failed: {records!r}")
    frame_records = [
        record
        for record in records
        if _object(record, "result").get("event") == "frame"
    ]
    complete_records = [
        record
        for record in records
        if _object(record, "result").get("event") == "complete"
    ]
    if len(frame_records) != 1 or len(complete_records) != 1:
        raise AssertionError(f"capture emitted unexpected records: {records!r}")

    frame = _object(_object(frame_records[0], "result"), "frame")
    wire_hex = frame.get("bytes_hex")
    if not isinstance(wire_hex, str):
        raise AssertionError(f"capture frame omitted exact bytes: {frame!r}")
    selected_port = _udp_destination_port(bytes.fromhex(wire_hex))
    if selected_port != context.case.destination_port:
        raise AssertionError(
            f"capture emitted UDP destination {selected_port}, "
            f"expected {context.case.destination_port}"
        )

    complete = complete_records[0]
    if _object(complete, "result").get("frames") != 1:
        raise AssertionError(f"capture completion count was not one: {complete!r}")
    stats = _object(complete, "stats")
    if stats.get("packets_attempted") != 1 or stats.get("packets_completed") != 1:
        raise AssertionError(f"native filter did not precede frame budget: {stats!r}")

    return {
        "selected_destination_port": selected_port,
        "packets_attempted": 1,
        "packets_completed": 1,
    }


def run_invalid_filter(context: CaseContext) -> dict[str, object]:
    completed = context.run_packetcraftr(
        (
            "--output",
            "ndjson",
            "capture",
            "--packet",
            f"ipv4(dst={context.topology.addresses.server_ipv4})"
            f"/udp(dport={context.case.destination_port})",
            "--interface",
            context.topology.names.client_interface,
            "--timeout-ms",
            "500",
            "--capture-filter",
            "udp and (",
        ),
        timeout=5.0,
    )
    records = _records(completed)
    if completed.returncode == 0:
        raise AssertionError(f"invalid native filter succeeded: {records!r}")
    if any(record.get("status") == "success" for record in records):
        raise AssertionError(f"invalid native filter emitted capture success: {records!r}")
    if len(records) != 1:
        raise AssertionError(f"invalid native filter emitted unexpected output: {records!r}")
    error = _object(records[0], "error")
    if error.get("code") != "cli.capture_filter":
        raise AssertionError(f"invalid native filter classification changed: {error!r}")

    return {
        "classification": error["code"],
        "exit_code": completed.returncode,
        "successful_capture_records": 0,
    }


def _records(completed: subprocess.CompletedProcess[str]) -> list[dict[str, Any]]:
    if completed.stderr:
        raise AssertionError(f"NDJSON capture wrote stderr: {completed.stderr!r}")
    records: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        value = json.loads(line)
        if not isinstance(value, dict):
            raise AssertionError(f"NDJSON capture record was not an object: {value!r}")
        records.append(value)
    if not records:
        raise AssertionError("NDJSON capture emitted no records")
    return records


def _object(value: dict[str, Any], key: str) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        raise AssertionError(f"{key} was not an object: {child!r}")
    return child


def _udp_destination_port(wire: bytes) -> int:
    if len(wire) < 42 or wire[12:14] != b"\x08\x00":
        raise AssertionError(f"capture frame was not Ethernet IPv4: {wire.hex()}")
    ip_offset = 14
    header_length = (wire[ip_offset] & 0x0F) * 4
    udp_offset = ip_offset + header_length
    if header_length < 20 or len(wire) < udp_offset + 4:
        raise AssertionError(f"capture frame had an invalid IPv4 header: {wire.hex()}")
    return int.from_bytes(wire[udp_offset + 2 : udp_offset + 4], "big")
