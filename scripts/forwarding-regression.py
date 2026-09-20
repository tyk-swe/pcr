#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Generate controlled offline cases and retain a reproducible regression bundle.

No network traffic is generated. Missing observations can fail a test contract;
they do not establish that a device dropped packets. A bundle is sensitive data.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("forwarding_consumer", ROOT / "examples/consumers/forwarding.py")
CONSUMER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONSUMER)
MAX_OUTPUT = 32 * 1024 * 1024
MAX_STDERR = 1024 * 1024


def checksum(data: bytes) -> int:
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def datagram(identity: int, payload: bytes, source_port: int = 40000) -> bytes:
    source = socket.inet_aton("192.0.2.1")
    destination = socket.inet_aton("198.51.100.2")
    udp = struct.pack("!HHHH", source_port, 9000, 8 + len(payload), 0) + payload
    pseudo = source + destination + struct.pack("!BBH", 0, 17, len(udp))
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 65535) + udp[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), identity,
                     0, 64, 17, 0, source, destination)
    return ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:] + udp


def capture(frames: Iterable[bytes]) -> bytes:
    out = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 228))
    for index, frame in enumerate(frames, 1):
        out.extend(struct.pack("<IIII", index, 0, len(frame), len(frame)))
        out.extend(frame)
    return bytes(out)


def validate_capture(data: bytes) -> int:
    """Independent structural/checksum checks; not a production decoder."""
    if len(data) < 24 or struct.unpack_from("<IHHIIII", data) != (0xA1B2C3D4, 2, 4, 0, 0, 65535, 228):
        raise ValueError("unexpected generated capture header")
    cursor = 24
    count = 0
    while cursor < len(data):
        if cursor + 16 > len(data):
            raise ValueError("truncated record")
        _, micros, included, original = struct.unpack_from("<IIII", data, cursor)
        cursor += 16
        frame = data[cursor:cursor + included]
        cursor += included
        if len(frame) != included or included != original or not 28 <= included <= 65535 or micros >= 1000000:
            raise ValueError("invalid record lengths")
        if frame[0] != 0x45 or frame[9] != 17 or struct.unpack_from("!H", frame, 2)[0] != included:
            raise ValueError("invalid IPv4 fixture")
        if checksum(frame[:20]) != 0:
            raise ValueError("invalid IPv4 checksum")
        udp = frame[20:]
        if struct.unpack_from("!H", udp, 4)[0] != len(udp):
            raise ValueError("invalid UDP length")
        pseudo = frame[12:20] + struct.pack("!BBH", 0, 17, len(udp))
        if struct.unpack_from("!H", udp, 6)[0] == 0 or checksum(pseudo + udp) != 0:
            raise ValueError("invalid UDP checksum")
        count += 1
    return count


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            hasher.update(block)
    return hasher.hexdigest()


def create_cases(root: Path, large: bool = False) -> list[dict]:
    captures = {
        "before": capture([datagram(7, b"fixture")]),
        "translated": capture([datagram(7, b"fixture", 40001)]),
        "changed": capture([datagram(7, b"fixturX")]),
        "missing": capture([]),
        "many-flows": capture(datagram(i, b"fixture", 10000 + i) for i in range(8193)),
    }
    common = ["--identity", "ipv4.identification"]
    cases = [
        ("preserved", "before", "before", [*common, "--preserve", "raw.bytes"], "pass"),
        ("translated", "before", "translated", [*common, "--preserve", "raw.bytes",
                                                "--expect", "udp.source_port=40001"], "pass"),
        ("intentional-violation", "before", "changed", [*common, "--preserve", "raw.bytes"], "fail"),
        ("insufficient-evidence", "before", "missing", [*common, "--preserve", "raw.bytes"], "inconclusive"),
        ("missing-field", "before", "before", [*common, "--preserve", "tcp.sequence"], "inconclusive"),
        ("explicit-absence", "before", "before", [*common, "--expect-absent", "tcp.sequence"], "pass"),
        ("unrequested-index", "many-flows", "many-flows",
         [*common, "--preserve", "ipv4.ttl", "--ingress-filter", "ipv4.identification == 0",
          "--egress-filter", "ipv4.identification == 0", "--max-flows", "1"], "pass"),
    ]
    if large:
        captures["large-keys"] = capture(
            datagram(i, struct.pack("!H", i) + b"\xff" * 32758) for i in range(256)
        )
        for name, extra in (("bounded-details", []), ("zero-details", ["--max-details", "0"])):
            cases.append((name, "large-keys", "large-keys", ["--identity", "raw.bytes", *extra], "pass"))
    inputs = {}
    for name, data in captures.items():
        count = validate_capture(data)
        path = root / f"{name}.pcap"
        with path.open("xb") as output:
            os.chmod(path, 0o600)
            output.write(data)
        inputs[name] = {"path": path.name, "sha256": digest(path), "bytes": len(data), "frames": count}
    return [
        {"name": name, "ingress": inputs[before], "egress": inputs[after],
         "rules_and_limits": args, "expected_verdict": expected, "execution": "not_run"}
        for name, before, after, args, expected in cases
    ]


def run_bounded(argv: list[str], output: Path, errors: Path, seconds: float = 60) -> tuple[int, float]:
    """Bound elapsed time and spool sizes; use no shell and retain no output in memory."""
    start = time.monotonic()
    with output.open("xb") as stdout, errors.open("xb") as stderr:
        os.chmod(output, 0o600)
        os.chmod(errors, 0o600)
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   start_new_session=(os.name == "posix"))
        try:
            while process.poll() is None:
                if (time.monotonic() - start > seconds or output.stat().st_size > MAX_OUTPUT
                        or errors.stat().st_size > MAX_STDERR):
                    raise RuntimeError("child exceeded elapsed-time or output-spool budget")
                time.sleep(0.01)
            elapsed = time.monotonic() - start
            if (elapsed > seconds or output.stat().st_size > MAX_OUTPUT
                    or errors.stat().st_size > MAX_STDERR):
                raise RuntimeError("child exceeded elapsed-time or output-spool budget")
            return process.returncode, elapsed
        finally:
            if process.poll() is None:
                try:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                except ProcessLookupError:
                    pass  # It exited between the poll and termination request.
                process.wait()


def run_bundle(root: Path, binary: Path | None, large: bool = False) -> dict:
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    cases = create_cases(root, large)
    manifest = {
        "bundle_schema": "packetcraftr.regression/v1",
        "execution": "not_run",
        "acquisition": {
            "kind": "generated_offline_fixtures", "network_traffic": False,
            "timebase": "synthetic per-capture timestamps", "observation_window": "not_applicable",
            "capture_drop_statistics": None, "offload_settings": None,
            "note": "Unknown acquisition data is not a zero-drop guarantee; no device-loss attribution."
        },
        "cases": cases,
    }
    write_manifest(root, manifest)
    if binary is not None:
        try:
            binary = binary.resolve(strict=True)
            binary_hash = digest(binary)
            code, _ = run_bounded(
                [str(binary), "--version"], root / "version.txt", root / "version.stderr", seconds=10,
            )
            if code or (root / "version.txt").stat().st_size > 32768:
                raise RuntimeError("tool identity command failed or exceeded its identity-size limit")
            manifest["tool"] = {
                "path": str(binary), "sha256": binary_hash,
                "version": (root / "version.txt").read_text(encoding="utf-8").strip(),
            }
        except (OSError, ValueError, RuntimeError) as error:
            manifest.update(execution="failed", tool_error=str(error))
            write_manifest(root, manifest)
            return manifest
        manifest["execution"] = "complete"
        for case in cases:
            stdout = root / f'{case["name"]}.ndjson'
            stderr = root / f'{case["name"]}.stderr'
            argv = [str(binary), "--output", "ndjson", "--resource-diagnostics", "verify-forwarding",
                    str(root / case["ingress"]["path"]), str(root / case["egress"]["path"]),
                    *case["rules_and_limits"]]
            case["argv"] = argv  # Only this harness's generated, non-secret arguments.
            try:
                code, elapsed = run_bounded(argv, stdout, stderr)
                case.update(exit_code=code, elapsed_seconds=elapsed, output_bytes=stdout.stat().st_size,
                            output_sha256=digest(stdout))
                with stdout.open("rb") as source:
                    result = CONSUMER.consume(source, "ndjson", code)
                case.update(execution=result["execution"], observed_verdict=result["verdict"])
                if result["execution"] != "complete":
                    raise RuntimeError(f'execution error: {result["error"].get("code")}')
                for side in ("ingress", "egress"):
                    if digest(root / case[side]["path"]) != case[side]["sha256"]:
                        raise RuntimeError("input changed during the run")
                    if result["report"]["captures"][side]["source"]["sha256"] != case[side]["sha256"]:
                        raise RuntimeError("report does not bind to the fixture contents")
                case["test_contract"] = "pass" if result["verdict"] == case["expected_verdict"] else "fail"
                if case["test_contract"] == "fail":
                    manifest["execution"] = "failed"
            except (OSError, ValueError, KeyError, RuntimeError) as error:
                case.update(execution="error", test_contract="fail", error=str(error))
                manifest["execution"] = "failed"
            write_manifest(root, manifest)
        if digest(binary) != binary_hash:
            manifest["execution"] = "failed"
            manifest["tool_changed"] = True
    write_manifest(root, manifest)
    return manifest


def write_manifest(root: Path, manifest: dict) -> None:
    temporary = root / "manifest.json.tmp"
    with temporary.open("w", encoding="utf-8") as output:
        os.chmod(temporary, 0o600)
        json.dump(manifest, output, indent=2)
        output.write("\n")
    temporary.replace(root / "manifest.json")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new private bundle directory")
    parser.add_argument("--binary", type=Path, help="omit to generate fixtures without claiming execution")
    parser.add_argument("--large", action="store_true", help="include large identity/output-budget controls")
    args = parser.parse_args()
    try:
        result = run_bundle(args.output, args.binary, args.large)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(2, f"{error}\n")
    print(args.output / "manifest.json")
    return int(result["execution"] == "failed")


if __name__ == "__main__":
    raise SystemExit(main())
