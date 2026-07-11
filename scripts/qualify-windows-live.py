#!/usr/bin/env python3
"""Qualify an exact PacketcraftR candidate on a dedicated Windows/Npcap runner."""

# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
from pathlib import Path, PurePosixPath


class QualificationError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(
    command: list[str],
    *,
    cwd: Path,
    stdout: Path,
    stderr: Path | None = None,
    expected: tuple[int, ...] = (0,),
    timeout: int = 1800,
) -> int:
    if stderr is None:
        stderr = stdout.with_suffix(stdout.suffix + ".stderr")
    with stdout.open("wb") as output, stderr.open("wb") as errors:
        result = subprocess.run(
            command,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=errors,
            check=False,
            timeout=timeout,
        )
    if result.returncode not in expected:
        diagnostic = stderr.read_text(encoding="utf-8", errors="replace")[-4000:]
        raise QualificationError(
            f"command exited {result.returncode}, expected {expected}: {command!r}\n{diagnostic}"
        )
    return result.returncode


def extract_candidate(archive: Path, destination: Path) -> Path:
    destination_resolved = destination.resolve()
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        if not members:
            raise QualificationError("candidate archive is empty")
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or member.issym() or member.islnk():
                raise QualificationError(f"candidate archive has unsafe member {member.name!r}")
            target = (destination / Path(*name.parts)).resolve()
            if destination_resolved not in target.parents and target != destination_resolved:
                raise QualificationError(f"candidate archive escapes extraction root: {member.name!r}")
            if not (member.isfile() or member.isdir()):
                raise QualificationError(
                    f"candidate archive has unsupported member type: {member.name!r}"
                )
        source.extractall(destination)
    roots = [item for item in destination.iterdir() if item.is_dir()]
    if len(roots) != 1:
        raise QualificationError("candidate archive must contain exactly one workspace root")
    return roots[0]


def powershell(script: str, *, values: dict[str, str] | None = None) -> str:
    environment = os.environ.copy()
    if values:
        environment.update(values)
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$ErrorActionPreference='Stop';" + script,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
    )
    if result.returncode != 0:
        raise QualificationError(
            f"PowerShell setup command failed ({result.returncode}): {result.stderr[-4000:]}"
        )
    return result.stdout.strip()


def adapter_state(alias: str) -> dict[str, object]:
    output = powershell(
        """
$adapter = Get-NetAdapter -Name $env:PCR_INTERFACE
$ipv4 = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4
$ipv6 = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6
$addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
  Select-Object -ExpandProperty IPAddress)
[pscustomobject]@{
  name = $adapter.Name
  index = $adapter.ifIndex
  status = [string]$adapter.Status
  mac = $adapter.MacAddress
  mtu_ipv4 = $ipv4.NlMtu
  mtu_ipv6 = $ipv6.NlMtu
  addresses = $addresses
} | ConvertTo-Json -Compress
""",
        values={"PCR_INTERFACE": alias},
    )
    value = json.loads(output)
    if not isinstance(value, dict):
        raise QualificationError(f"adapter state for {alias!r} is not an object")
    return value


def configure_adapter(alias: str, mtu: int) -> None:
    powershell(
        """
$adapter = Get-NetAdapter -Name $env:PCR_INTERFACE
if ($adapter.Status -ne 'Up') { throw "adapter $($adapter.Name) is not Up" }
Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 `
  -NlMtuBytes ([int]$env:PCR_MTU)
Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 `
  -NlMtuBytes ([int]$env:PCR_MTU)
""",
        values={"PCR_INTERFACE": alias, "PCR_MTU": str(mtu)},
    )


def restore_adapter(alias: str, state: dict[str, object]) -> None:
    powershell(
        """
$adapter = Get-NetAdapter -Name $env:PCR_INTERFACE
Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 `
  -NlMtuBytes ([int]$env:PCR_MTU4)
Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 `
  -NlMtuBytes ([int]$env:PCR_MTU6)
""",
        values={
            "PCR_INTERFACE": alias,
            "PCR_MTU4": str(state["mtu_ipv4"]),
            "PCR_MTU6": str(state["mtu_ipv6"]),
        },
    )


def add_client_addresses(alias: str, ipv4: str, ipv6: str) -> None:
    powershell(
        """
$adapter = Get-NetAdapter -Name $env:PCR_INTERFACE
New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $env:PCR_IPV4 `
  -PrefixLength 24 -AddressFamily IPv4 -PolicyStore ActiveStore | Out-Null
New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $env:PCR_IPV6 `
  -PrefixLength 64 -AddressFamily IPv6 -PolicyStore ActiveStore | Out-Null
""",
        values={"PCR_INTERFACE": alias, "PCR_IPV4": ipv4, "PCR_IPV6": ipv6},
    )


def remove_client_addresses(alias: str, ipv4: str, ipv6: str) -> None:
    powershell(
        """
$adapter = Get-NetAdapter -Name $env:PCR_INTERFACE
Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $env:PCR_IPV4 `
  -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $env:PCR_IPV6 `
  -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
""",
        values={"PCR_INTERFACE": alias, "PCR_IPV4": ipv4, "PCR_IPV6": ipv6},
    )


def wait_for_ipv6(alias: str, address: str) -> None:
    for _ in range(60):
        state = powershell(
            """
$adapter = Get-NetAdapter -Name $env:PCR_INTERFACE
$address = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $env:PCR_IPV6 `
  -ErrorAction SilentlyContinue
if ($null -eq $address) { 'missing' } else { [string]$address.AddressState }
""",
            values={"PCR_INTERFACE": alias, "PCR_IPV6": address},
        )
        if state in {"Preferred", "Deprecated"}:
            return
        if state == "Duplicate":
            raise QualificationError(f"IPv6 address {address} failed duplicate detection")
        time.sleep(0.25)
    raise QualificationError(f"IPv6 address {address} did not become usable")


def load_output(path: Path, command: str) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("schema") != "packetcraftr.output/v1"
        or value.get("command") != command
        or value.get("status") != "success"
        or not isinstance(value.get("result"), dict)
    ):
        raise QualificationError(f"{path.name} is not a successful {command} result")
    return value["result"]


def command_json(
    binary: Path,
    workspace: Path,
    evidence: Path,
    filename: str,
    arguments: list[str],
    *,
    expected: tuple[int, ...] = (0,),
) -> int:
    path = evidence / filename
    status = run(
        [str(binary), "--output", "json", *arguments],
        cwd=workspace,
        stdout=path,
        expected=expected,
    )
    if status == 0:
        load_output(path, arguments[0])
    return status


def start_capture(
    binary: Path,
    workspace: Path,
    output: Path,
    errors: Path,
    arguments: list[str],
) -> tuple[subprocess.Popen[bytes], object, object]:
    stdout = output.open("wb")
    stderr = errors.open("wb")
    process = subprocess.Popen(
        [str(binary), *arguments],
        cwd=workspace,
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=stderr,
    )
    return process, stdout, stderr


def finish_process(
    process: subprocess.Popen[bytes], stdout: object, stderr: object, name: str
) -> None:
    try:
        status = process.wait(timeout=15)
    finally:
        stdout.close()  # type: ignore[attr-defined]
        stderr.close()  # type: ignore[attr-defined]
    if status != 0:
        raise QualificationError(f"{name} exited {status}")


def normalize_mac(value: object) -> str:
    if not isinstance(value, str):
        raise QualificationError("dedicated adapter has no six-byte MAC address")
    normalized = value.replace("-", ":").lower()
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", normalized):
        raise QualificationError(f"invalid adapter MAC address {value!r}")
    return normalized


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--client-interface", required=True)
    parser.add_argument("--peer-interface", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args()

    temporary: Path | None = None
    peer_process: subprocess.Popen[bytes] | None = None
    peer_output: object | None = None
    client_state: dict[str, object] | None = None
    peer_state: dict[str, object] | None = None
    client_addresses_added = False
    evidence: Path | None = None
    stop_file: Path | None = None
    try:
        if os.name != "nt" or platform.machine().upper() not in {"AMD64", "X86_64"}:
            raise QualificationError(
                f"Windows AMD64 is required, got {platform.system()}/{platform.machine()}"
            )
        if args.client_interface == args.peer_interface:
            raise QualificationError("client and peer adapters must be distinct")
        if not re.fullmatch(r"[0-9a-f]{40}", args.expected_commit):
            raise QualificationError("--expected-commit must be a full lowercase Git SHA")
        administrator = powershell(
            """
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
"""
        )
        if administrator.casefold() != "true":
            raise QualificationError("dedicated Npcap qualification requires Administrator")

        archive = args.archive.resolve(strict=True)
        checksums = args.checksums.resolve(strict=True)
        archive_digest = sha256(archive)
        expected_rows = {
            row.split("  ", 1)[1]: row.split("  ", 1)[0]
            for row in checksums.read_text(encoding="utf-8").splitlines()
            if "  " in row
        }
        if expected_rows.get(archive.name) != archive_digest:
            raise QualificationError("candidate archive checksum does not match SHA256SUMS")
        evidence = args.evidence.resolve()
        if evidence.exists() and any(evidence.iterdir()):
            raise QualificationError(f"evidence directory must be absent or empty: {evidence}")
        evidence.mkdir(parents=True, exist_ok=True)
        bundle = (
            args.bundle.resolve()
            if args.bundle
            else evidence.with_name(evidence.name + ".tar.gz")
        )
        bundle.parent.mkdir(parents=True, exist_ok=True)

        npcap_path = Path(os.environ["WINDIR"]) / "System32" / "Npcap" / "wpcap.dll"
        if not npcap_path.is_file():
            raise QualificationError(f"Npcap runtime is absent at {npcap_path}")
        npcap_version = powershell(
            "(Get-Item $env:PCR_NPCAP).VersionInfo.ProductVersion",
            values={"PCR_NPCAP": str(npcap_path)},
        )
        if not npcap_version.startswith("1.88"):
            raise QualificationError(f"Npcap 1.88 is required, got {npcap_version!r}")
        service_status = powershell("[string](Get-Service -Name npcap).Status")
        if service_status != "Running":
            raise QualificationError("the pinned Npcap service is not running")
        write_json(
            evidence / "npcap.json",
            {
                "runtime": "Npcap",
                "version": npcap_version,
                "dll": str(npcap_path),
                "dll_sha256": sha256(npcap_path),
                "service": "running",
                "sdk_abi": "1.16",
                "loading": "runtime-only-no-import-library",
            },
        )

        client_state = adapter_state(args.client_interface)
        peer_state = adapter_state(args.peer_interface)
        if client_state.get("status") != "Up" or peer_state.get("status") != "Up":
            raise QualificationError("both dedicated isolated-switch adapters must be Up")
        client_mac = normalize_mac(client_state.get("mac"))
        peer_mac = normalize_mac(peer_state.get("mac"))
        client_ipv4 = "10.51.1.2"
        peer_ipv4 = "10.51.1.9"
        client_ipv6 = "fd51:1::2"
        peer_ipv6 = "fd51:1::9"
        all_addresses = {
            str(address).casefold()
            for state in (client_state, peer_state)
            for address in state.get("addresses", [])
        }
        if any(
            address.casefold() in all_addresses
            for address in (client_ipv4, peer_ipv4, client_ipv6, peer_ipv6)
        ):
            raise QualificationError("qualification addresses are already assigned")

        configure_adapter(args.client_interface, 1280)
        configure_adapter(args.peer_interface, 1280)
        client_addresses_added = True
        add_client_addresses(args.client_interface, client_ipv4, client_ipv6)
        wait_for_ipv6(args.client_interface, client_ipv6)
        write_json(
            evidence / "adapter-before.json",
            {"client": client_state, "peer": peer_state},
        )

        temporary = Path(tempfile.mkdtemp(prefix="packetcraftr-windows-live-"))
        workspace = extract_candidate(archive, temporary)
        release = tomllib.loads((workspace / "RELEASE-METADATA.toml").read_text(encoding="utf-8"))
        cargo = tomllib.loads((workspace / "Cargo.toml").read_text(encoding="utf-8"))
        candidate_commit = release.get("commit")
        version = cargo["workspace"]["package"]["version"]
        if candidate_commit != args.expected_commit:
            raise QualificationError(
                f"archive commit {candidate_commit!r} differs from {args.expected_commit}"
            )
        rust_version = subprocess.run(
            ["rustc", "--version"], check=True, capture_output=True, text=True
        ).stdout.strip()
        if not rust_version.startswith("rustc 1.96.0 "):
            raise QualificationError(f"Rust 1.96.0 is required, got {rust_version}")

        run(
            [
                "cargo",
                "build",
                "--locked",
                "--release",
                "--all-features",
                "--bin",
                "packetcraftr",
                "--example",
                "live_qualification_peer",
            ],
            cwd=workspace,
            stdout=evidence / "build.log",
        )
        run(
            ["cargo", "test", "--locked", "--workspace", "--all-features"],
            cwd=workspace,
            stdout=evidence / "failure-path-tests.log",
        )
        run(
            [
                "cargo",
                "test",
                "--locked",
                "--all-features",
                "--example",
                "live_qualification_peer",
            ],
            cwd=workspace,
            stdout=evidence / "peer-tests.log",
        )
        binary = workspace / "target" / "release" / "packetcraftr.exe"
        peer_binary = workspace / "target" / "release" / "examples" / "live_qualification_peer.exe"
        if not binary.is_file() or not peer_binary.is_file():
            raise QualificationError("release candidate binaries were not built")

        ready_file = evidence / "peer.ready"
        stop_file = evidence / "peer.stop"
        peer_report = evidence / "peer-report.json"
        peer_output = (evidence / "peer.log").open("wb")
        peer_process = subprocess.Popen(
            [
                str(peer_binary),
                "--interface",
                args.peer_interface,
                "--client-mac",
                client_mac,
                "--peer-mac",
                peer_mac,
                "--client-ipv4",
                client_ipv4,
                "--peer-ipv4",
                peer_ipv4,
                "--client-ipv6",
                client_ipv6,
                "--peer-ipv6",
                peer_ipv6,
                "--ready-file",
                str(ready_file),
                "--stop-file",
                str(stop_file),
                "--report-file",
                str(peer_report),
            ],
            cwd=workspace,
            stdin=subprocess.DEVNULL,
            stdout=peer_output,
            stderr=subprocess.STDOUT,
        )
        for _ in range(100):
            if ready_file.is_file():
                break
            if peer_process.poll() is not None:
                raise QualificationError(f"native Npcap peer exited {peer_process.returncode}")
            time.sleep(0.1)
        else:
            raise QualificationError("native Npcap peer did not become ready")

        command_json(binary, workspace, evidence, "interfaces.json", ["interfaces"])
        command_json(binary, workspace, evidence, "routes.json", ["routes"])
        common = ["--max-packets", "1", "--max-bytes", "1500"]
        live_limits = [
            "--max-queue-frames",
            "64",
            "--max-captured-bytes",
            "65536",
            "--snap-length",
            "1500",
        ]
        command_json(
            binary,
            workspace,
            evidence,
            "plan-ipv4.json",
            [
                "plan",
                "--packet",
                f"ipv4(dst={peer_ipv4},identification=521)/udp(sport=40000,dport=9)",
                "--interface",
                args.client_interface,
                "--source",
                client_ipv4,
                "--link-mode",
                "layer2",
                *common,
            ],
        )
        command_json(
            binary,
            workspace,
            evidence,
            "plan-ipv6.json",
            [
                "plan",
                "--packet",
                f"ipv6(dst={peer_ipv6})/udp(sport=40001,dport=9)",
                "--interface",
                args.client_interface,
                "--source",
                client_ipv6,
                "--link-mode",
                "layer2",
                *common,
            ],
        )
        powershell(
            """
$adapter = Get-NetAdapter -Name $env:PCR_INTERFACE
Get-NetNeighbor -InterfaceIndex $adapter.ifIndex -IPAddress $env:PCR_IPV4 `
  -ErrorAction SilentlyContinue | Remove-NetNeighbor -Confirm:$false
Get-NetNeighbor -InterfaceIndex $adapter.ifIndex -IPAddress $env:PCR_IPV6 `
  -ErrorAction SilentlyContinue | Remove-NetNeighbor -Confirm:$false
""",
            values={
                "PCR_INTERFACE": args.client_interface,
                "PCR_IPV4": peer_ipv4,
                "PCR_IPV6": peer_ipv6,
            },
        )
        for family, source, target, sequence in (
            ("ipv4", client_ipv4, peer_ipv4, 522),
            ("ipv6", client_ipv6, peer_ipv6, 523),
        ):
            ip = (
                f"ipv4(dst={target},identification={sequence})"
                if family == "ipv4"
                else f"ipv6(dst={target},flow_label={sequence})"
            )
            for mode, port in (("layer2", 40100), ("layer3", 40102)):
                command_json(
                    binary,
                    workspace,
                    evidence,
                    f"send-{mode}-{family}.json",
                    [
                        "send",
                        "--packet",
                        f"{ip}/udp(sport={port},dport=9000)/raw(text={mode}-{family})",
                        "--interface",
                        args.client_interface,
                        "--source",
                        source,
                        "--link-mode",
                        mode,
                        *common,
                    ],
                )

        for family, source, target, sequence in (
            ("ipv4", client_ipv4, peer_ipv4, 524),
            ("ipv6", client_ipv6, peer_ipv6, 525),
        ):
            ip = (
                f"ipv4(dst={target},identification={sequence})"
                if family == "ipv4"
                else f"ipv6(dst={target},flow_label={sequence})"
            )
            command_json(
                binary,
                workspace,
                evidence,
                f"exchange-{family}.json",
                [
                    "exchange",
                    "--packet",
                    f"{ip}/udp(sport=4100{0 if family == 'ipv4' else 1},dport=9000)/raw(text=exchange-{family})",
                    "--interface",
                    args.client_interface,
                    "--source",
                    source,
                    "--link-mode",
                    "layer2" if family == "ipv4" else "layer3",
                    "--timeout-ms",
                    "1200",
                    "--max-responses",
                    "1",
                    "--max-unsolicited",
                    "8",
                    *common,
                    *live_limits,
                ],
            )

        capture_process, capture_out, capture_err = start_capture(
            binary,
            workspace,
            evidence / "capture.pcapng",
            evidence / "capture.stderr",
            [
                "--output",
                "pcapng",
                "capture",
                "--packet",
                f"eth(source={peer_mac},destination={client_mac},ether_type=2048)/raw(hex=00)",
                "--interface",
                args.client_interface,
                "--link-mode",
                "layer2",
                "--timeout-ms",
                "800",
                "--max-packets",
                "8",
                "--max-bytes",
                "12000",
                *live_limits,
            ],
        )
        time.sleep(0.3)
        trigger_hex = subprocess.run(
            [
                str(binary),
                "--output",
                "hex",
                "build",
                "--packet",
                f"ipv4(src={peer_ipv4},dst={client_ipv4},identification=526)/udp(sport=9000,dport=9)/raw(text=capture)",
            ],
            cwd=workspace,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        command_json(
            binary,
            workspace,
            evidence,
            "capture-trigger.json",
            [
                "send",
                "--packet",
                f"eth(source={peer_mac},destination={client_mac},ether_type=2048)/raw(hex={trigger_hex})",
                "--interface",
                args.peer_interface,
                "--link-mode",
                "layer2",
                *common,
            ],
        )
        finish_process(capture_process, capture_out, capture_err, "finite capture")
        run(
            [
                str(binary),
                "--output",
                "ndjson",
                "read",
                str(evidence / "capture.pcapng"),
                "--max-frames",
                "8",
                "--max-bytes",
                "12000",
                "--max-frame-bytes",
                "1500",
                "--max-interfaces",
                "8",
            ],
            cwd=workspace,
            stdout=evidence / "capture-read.ndjson",
        )

        stacked_packet = (
            f"eth(src={client_mac},dst={peer_mac})/qinq(vid=100)/vlan(vid=200)/"
            f"ipv4(src={client_ipv4},dst={peer_ipv4},identification=527)/"
            "udp(sport=44000,dport=9000)/raw(text=stacked-vlan)"
        )
        stacked_hex = subprocess.run(
            [str(binary), "--output", "hex", "build", "--packet", stacked_packet],
            cwd=workspace,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        (evidence / "stacked-vlan.hex").write_text(stacked_hex + "\n", encoding="utf-8")
        run(
            [
                sys.executable,
                str(workspace / "scripts" / "linux-live-peer.py"),
                "make-pcap",
                "--frame-hex",
                stacked_hex,
                "--output",
                str(evidence / "stacked-vlan-source.pcap"),
            ],
            cwd=workspace,
            stdout=evidence / "stacked-vlan-source.log",
        )
        replay_capture, replay_out, replay_err = start_capture(
            binary,
            workspace,
            evidence / "stacked-vlan-captured.pcap",
            evidence / "stacked-vlan-capture.stderr",
            [
                "--output",
                "pcap",
                "capture",
                "--packet",
                f"eth(source={client_mac},destination={peer_mac},ether_type=34984)/raw(hex=00)",
                "--interface",
                args.peer_interface,
                "--link-mode",
                "layer2",
                "--timeout-ms",
                "800",
                "--max-packets",
                "8",
                "--max-bytes",
                "12000",
                *live_limits,
            ],
        )
        time.sleep(0.3)
        command_json(
            binary,
            workspace,
            evidence,
            "stacked-vlan-replay.json",
            [
                "replay",
                str(evidence / "stacked-vlan-source.pcap"),
                "--interface",
                args.client_interface,
                "--link-mode",
                "layer2",
                "--timing",
                "immediate",
                "--max-packets",
                "1",
                "--max-bytes",
                "1500",
                "--max-frame-bytes",
                "1500",
                "--allow-malformed-live",
                "--allow-permissive-packets",
            ],
        )
        finish_process(replay_capture, replay_out, replay_err, "stacked VLAN capture")
        for name in ("source", "captured"):
            run(
                [
                    str(binary),
                    "--output",
                    "ndjson",
                    "read",
                    str(evidence / f"stacked-vlan-{name}.pcap"),
                ],
                cwd=workspace,
                stdout=evidence / f"stacked-vlan-{name}.ndjson",
            )

        tool_common = [
            "--interface",
            args.client_interface,
            "--link-mode",
            "layer3",
            *common,
            *live_limits,
        ]
        command_json(
            binary,
            workspace,
            evidence,
            "scan-ipv4.json",
            [
                "scan",
                peer_ipv4,
                "--transport",
                "tcp",
                "--ports",
                "9443",
                "--attempts",
                "1",
                "--timeout-ms",
                "700",
                "--batch-size",
                "1",
                "--rate",
                "10",
                "--max-probes",
                "1",
                "--max-duration-ms",
                "2500",
                *tool_common,
            ],
        )
        command_json(
            binary,
            workspace,
            evidence,
            "scan-ipv6.json",
            [
                "scan",
                peer_ipv6,
                "--transport",
                "icmp",
                "--family",
                "ipv6",
                "--attempts",
                "1",
                "--timeout-ms",
                "700",
                "--batch-size",
                "1",
                "--rate",
                "10",
                "--max-probes",
                "1",
                "--max-duration-ms",
                "2500",
                *tool_common,
            ],
        )
        for family, target in (("ipv4", peer_ipv4), ("ipv6", peer_ipv6)):
            family_arguments = ["--family", "ipv6"] if family == "ipv6" else []
            command_json(
                binary,
                workspace,
                evidence,
                f"traceroute-{family}.json",
                [
                    "traceroute",
                    target,
                    "--strategy",
                    "udp",
                    *family_arguments,
                    "--first-hop",
                    "1",
                    "--max-hops",
                    "1",
                    "--attempts",
                    "1",
                    "--timeout-ms",
                    "700",
                    "--rate",
                    "10",
                    "--max-probes",
                    "1",
                    "--max-duration-ms",
                    "2500",
                    *tool_common,
                ],
            )
            command_json(
                binary,
                workspace,
                evidence,
                f"dns-{family}.json",
                [
                    "dns",
                    target,
                    "www.example.test",
                    "--type",
                    "a",
                    "--port",
                    "5353",
                    "--transaction-id",
                    "21501" if family == "ipv4" else "21502",
                    "--source-port",
                    "42000" if family == "ipv4" else "42001",
                    "--attempts",
                    "1",
                    "--timeout-ms",
                    "700",
                    "--rate",
                    "10",
                    "--max-duration-ms",
                    "2500",
                    *tool_common,
                ],
            )

        fuzz_packet = (
            f"ipv4(dst={peer_ipv4},identification=528)/udp(sport=43000,dport=9000)/raw(text=hello)"
        )
        for strategy in ("boundary", "random", "bit-flip"):
            command_json(
                binary,
                workspace,
                evidence,
                f"fuzz-{strategy}.json",
                [
                    "fuzz",
                    "--packet",
                    fuzz_packet,
                    "--seed",
                    "51",
                    "--cases",
                    "1",
                    "--strategy",
                    strategy,
                    "--field",
                    "2.bytes",
                    "--live",
                    "--timeout-ms",
                    "700",
                    "--rate",
                    "10",
                    "--max-cases",
                    "1",
                    "--max-total-bytes",
                    "65536",
                    "--max-field-bytes",
                    "64",
                    "--max-list-items",
                    "8",
                    "--max-shrink-steps",
                    "2",
                    "--max-duration-ms",
                    "2500",
                    *tool_common,
                ],
            )
        command_json(
            binary,
            workspace,
            evidence,
            "fuzz-malformed.json",
            [
                "fuzz",
                "--packet",
                fuzz_packet,
                "--seed",
                "51",
                "--cases",
                "1",
                "--strategy",
                "malformed",
                "--field",
                "0.checksum",
                "--mode",
                "permissive",
                "--live",
                "--allow-malformed-live",
                "--allow-permissive-packets",
                "--timeout-ms",
                "300",
                "--rate",
                "10",
                "--max-cases",
                "1",
                "--max-total-bytes",
                "65536",
                "--max-field-bytes",
                "64",
                "--max-list-items",
                "8",
                "--max-shrink-steps",
                "2",
                "--max-duration-ms",
                "1500",
                "--interface",
                args.client_interface,
                "--link-mode",
                "layer2",
                *common,
                *live_limits,
            ],
        )

        command_json(
            binary,
            workspace,
            evidence,
            "exchange-timeout.json",
            [
                "exchange",
                "--packet",
                f"ipv4(dst={peer_ipv4},identification=529)/udp(sport=45000,dport=9001)/raw(text=timeout)",
                "--interface",
                args.client_interface,
                "--source",
                client_ipv4,
                "--link-mode",
                "layer3",
                "--timeout-ms",
                "300",
                "--max-responses",
                "1",
                "--max-unsolicited",
                "8",
                *common,
                *live_limits,
            ],
        )
        payload = "x" * 1300
        mtu_status = command_json(
            binary,
            workspace,
            evidence,
            "low-mtu.json",
            [
                "send",
                "--packet",
                f'ipv4(dst={peer_ipv4},identification=530)/udp(sport=45001,dport=9000)/raw(text="{payload}")',
                "--interface",
                args.client_interface,
                "--source",
                client_ipv4,
                "--link-mode",
                "layer3",
                "--max-packets",
                "1",
                "--max-bytes",
                "2000",
            ],
            expected=(3,),
        )
        (evidence / "low-mtu.exit").write_text(f"{mtu_status}\n", encoding="utf-8")

        stop_file.touch()
        peer_status = peer_process.wait(timeout=15)
        peer_output.close()  # type: ignore[attr-defined]
        peer_output = None
        if peer_status != 0:
            raise QualificationError(f"native Npcap peer exited {peer_status}")
        peer_process = None

        remove_client_addresses(args.client_interface, client_ipv4, client_ipv6)
        client_addresses_added = False
        restore_adapter(args.client_interface, client_state)
        restore_adapter(args.peer_interface, peer_state)
        write_json(
            evidence / "adapter-after.json",
            {
                "client": adapter_state(args.client_interface),
                "peer": adapter_state(args.peer_interface),
                "qualification_addresses_removed": True,
                "mtus_restored": True,
            },
        )
        client_state = None
        peer_state = None

        tooling_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip()
        write_json(
            evidence / "metadata.json",
            {
                "schema": "packetcraftr.qualification-input/v1",
                "platform": "windows",
                "architecture": "x86_64-msvc",
                "input_kind": "archive",
                "candidate_commit": candidate_commit,
                "tooling_commit": tooling_commit,
                "version": version,
                "archive_sha256": archive_digest,
                "binary_sha256": sha256(binary),
                "peer_binary_sha256": sha256(peer_binary),
                "rust_version": rust_version,
                "runner_image": os.environ.get("ImageOS"),
                "runner_image_version": os.environ.get("ImageVersion"),
                "topology": {
                    "kind": "dedicated-isolated-switch",
                    "client_interface": args.client_interface,
                    "peer_interface": args.peer_interface,
                    "client_mac": client_mac,
                    "peer_mac": peer_mac,
                    "client_ipv4": client_ipv4,
                    "peer_ipv4": peer_ipv4,
                    "client_ipv6": client_ipv6,
                    "peer_ipv6": peer_ipv6,
                    "mtu": 1280,
                    "peer_mode": "packetcraftr-native-npcap",
                    "peer_target_addresses": "unassigned",
                },
                "npcap_version": npcap_version,
                "npcap_dll_sha256": sha256(npcap_path),
                "npcap_sdk_abi": "1.16",
            },
        )
        verifier = Path(__file__).with_name("verify-windows-live-evidence.py")
        subprocess.run(
            [sys.executable, str(verifier), "--evidence", str(evidence)], check=True
        )
        rows = []
        for path in sorted(evidence.iterdir()):
            if path.is_file() and path.name != "SHA256SUMS":
                rows.append(f"{sha256(path)}  {path.name}")
        (evidence / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")
        for row in rows:
            digest, name = row.split("  ", 1)
            if sha256(evidence / name) != digest:
                raise QualificationError(f"evidence checksum changed for {name}")
        with tarfile.open(bundle, "w:gz") as output:
            output.add(evidence, arcname=evidence.name)
        print("Windows x86_64 MSVC Npcap live qualification passed")
        print(f"evidence={evidence}")
        print(f"bundle={bundle}")
        print(f"bundle_sha256={sha256(bundle)}")
    except (
        QualificationError,
        OSError,
        KeyError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        tarfile.TarError,
        tomllib.TOMLDecodeError,
    ) as error:
        print(f"Windows Npcap live qualification failed: {error}", file=sys.stderr)
        return 1
    finally:
        if peer_process is not None:
            if stop_file is not None:
                try:
                    stop_file.touch()
                except OSError:
                    pass
            try:
                peer_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                peer_process.kill()
                peer_process.wait(timeout=3)
        if peer_output is not None:
            peer_output.close()  # type: ignore[attr-defined]
        if client_addresses_added:
            try:
                remove_client_addresses(args.client_interface, "10.51.1.2", "fd51:1::2")
            except (QualificationError, OSError) as error:
                print(f"warning: could not remove qualification addresses: {error}", file=sys.stderr)
        if client_state is not None:
            try:
                restore_adapter(args.client_interface, client_state)
            except (QualificationError, OSError) as error:
                print(f"warning: could not restore client MTU: {error}", file=sys.stderr)
        if peer_state is not None:
            try:
                restore_adapter(args.peer_interface, peer_state)
            except (QualificationError, OSError) as error:
                print(f"warning: could not restore peer MTU: {error}", file=sys.stderr)
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
