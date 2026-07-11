#!/usr/bin/env python3
"""Qualify an exact PacketcraftR candidate on hosted Windows x86_64 MSVC."""

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


def loopback_interface(interfaces: list[object], family: int) -> tuple[str, str]:
    for value in interfaces:
        if not isinstance(value, dict):
            continue
        flags = value.get("flags")
        addresses = value.get("addresses")
        if not isinstance(flags, dict) or not flags.get("up") or not flags.get("loopback"):
            continue
        if not isinstance(addresses, list):
            continue
        for address in addresses:
            if not isinstance(address, str):
                continue
            host = address.split("/", 1)[0]
            if (family == 4 and host.startswith("127.")) or (family == 6 and host == "::1"):
                name = value.get("name")
                if isinstance(name, str) and name:
                    return name, host
    raise QualificationError(f"Windows interface inventory has no IPv{family} loopback")


def find_dumpbin() -> Path:
    direct = shutil.which("dumpbin.exe")
    if direct:
        return Path(direct)
    installer = Path(
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    ) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not installer.is_file():
        raise QualificationError("Visual Studio vswhere.exe is unavailable")
    result = subprocess.run(
        [str(installer), "-latest", "-products", "*", "-property", "installationPath"],
        check=True,
        capture_output=True,
        text=True,
    )
    installation = Path(result.stdout.strip())
    candidates = sorted(
        installation.glob("VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe"), reverse=True
    )
    if not candidates:
        raise QualificationError("the MSVC x64 dumpbin.exe is unavailable")
    return candidates[0]


def command_json(
    binary: Path,
    workspace: Path,
    evidence: Path,
    filename: str,
    arguments: list[str],
) -> dict[str, object]:
    path = evidence / filename
    run([str(binary), "--output", "json", *arguments], cwd=workspace, stdout=path)
    return load_output(path, arguments[0])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args()

    temporary: Path | None = None
    try:
        if os.name != "nt" or platform.machine().upper() not in {"AMD64", "X86_64"}:
            raise QualificationError(
                f"Windows AMD64 is required, got {platform.system()}/{platform.machine()}"
            )
        if not re.fullmatch(r"[0-9a-f]{40}", args.expected_commit):
            raise QualificationError("--expected-commit must be a full lowercase Git SHA")
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

        temporary = Path(tempfile.mkdtemp(prefix="packetcraftr-windows-hosted-"))
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
        binary = workspace / "target" / "release" / "packetcraftr.exe"
        if not binary.is_file():
            raise QualificationError("release PacketcraftR executable was not built")
        version_output = subprocess.run(
            [str(binary), "--version"], check=True, capture_output=True, text=True
        ).stdout.strip()
        if version_output != f"packetcraftr {version}":
            raise QualificationError(f"candidate binary version mismatch: {version_output!r}")

        run(
            ["cargo", "test", "--locked", "--workspace", "--all-features"],
            cwd=workspace,
            stdout=evidence / "tests.log",
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
        run(
            [
                "cargo",
                "tree",
                "--color",
                "never",
                "--locked",
                "--target",
                "x86_64-pc-windows-msvc",
                "--edges",
                "normal",
                "--all-features",
                "--prefix",
                "none",
                "--format",
                "{p}",
            ],
            cwd=workspace,
            stdout=evidence / "native-dependencies.txt",
        )
        dumpbin = find_dumpbin()
        run(
            [str(dumpbin), "/nologo", "/dependents", str(binary)],
            cwd=workspace,
            stdout=evidence / "pe-dependencies.txt",
        )

        interfaces_result = command_json(
            binary, workspace, evidence, "interfaces.json", ["interfaces"]
        )
        command_json(binary, workspace, evidence, "routes.json", ["routes"])
        interfaces = interfaces_result.get("interfaces")
        if not isinstance(interfaces, list):
            raise QualificationError("interface output omitted its interface list")
        interface4, source4 = loopback_interface(interfaces, 4)
        interface6, source6 = loopback_interface(interfaces, 6)

        command_json(
            binary,
            workspace,
            evidence,
            "plan-ipv4.json",
            [
                "plan",
                "--packet",
                f"ipv4(src={source4},dst=127.0.0.1,identification=510)/udp(sport=45100,dport=9)/raw(text=windows-ipv4)",
                "--interface",
                interface4,
                "--source",
                source4,
                "--link-mode",
                "layer3",
                "--max-packets",
                "1",
                "--max-bytes",
                "1500",
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
                f"ipv6(src={source6},dst=::1,flow_label=2051)/udp(sport=45101,dport=9)/raw(text=windows-ipv6)",
                "--interface",
                interface6,
                "--source",
                source6,
                "--link-mode",
                "layer3",
                "--max-packets",
                "1",
                "--max-bytes",
                "1500",
            ],
        )
        command_json(
            binary,
            workspace,
            evidence,
            "send-layer3-ipv4.json",
            [
                "send",
                "--packet",
                f"ipv4(src={source4},dst=127.0.0.1,identification=511)/udp(sport=45102,dport=9)/raw(text=windows-ipv4)",
                "--interface",
                interface4,
                "--source",
                source4,
                "--link-mode",
                "layer3",
                "--max-packets",
                "1",
                "--max-bytes",
                "1500",
            ],
        )
        command_json(
            binary,
            workspace,
            evidence,
            "send-layer3-ipv6.json",
            [
                "send",
                "--packet",
                f"ipv6(src={source6},dst=::1,flow_label=2052)/udp(sport=45103,dport=9)/raw(text=windows-ipv6)",
                "--interface",
                interface6,
                "--source",
                source6,
                "--link-mode",
                "layer3",
                "--max-packets",
                "1",
                "--max-bytes",
                "1500",
            ],
        )

        npcap_path = Path(os.environ["WINDIR"]) / "System32" / "Npcap" / "wpcap.dll"
        if npcap_path.exists():
            raise QualificationError(
                f"hosted boundary unexpectedly has Npcap at {npcap_path}; use the pinned dedicated runner"
            )
        missing_path = evidence / "missing-npcap.ndjson"
        missing_exit = run(
            [
                str(binary),
                "--output",
                "ndjson",
                "capture",
                "--packet",
                f"ipv4(src={source4},dst=127.0.0.1,identification=512)/udp(dport=9)",
                "--interface",
                interface4,
                "--source",
                source4,
                "--link-mode",
                "layer3",
                "--timeout-ms",
                "100",
                "--max-packets",
                "1",
                "--max-bytes",
                "1500",
                "--max-queue-frames",
                "8",
                "--max-captured-bytes",
                "12000",
                "--snap-length",
                "1500",
            ],
            cwd=workspace,
            stdout=missing_path,
            expected=(4,),
        )
        (evidence / "missing-npcap.exit").write_text(
            f"{missing_exit}\n", encoding="utf-8"
        )

        baseline_expressions = {
            "ipv4_udp": "ipv4(src=192.0.2.1,dst=198.51.100.2,identification=513)/udp(sport=40000,dport=9)/raw(hex=0001027f80ffdeadbeef)",
            "ipv6_udp": "ipv6(src=2001:db8::1,dst=2001:db8::2,flow_label=2051)/udp(sport=40001,dport=9)/raw(hex=0001027f80ffdeadbeef)",
            "stacked_vlan": "eth(src=02:51:00:00:01:02,dst=02:51:00:00:01:09)/qinq(vid=100)/vlan(vid=200)/ipv4(src=10.51.1.2,dst=10.51.1.9,identification=511)/udp(sport=44000,dport=9000)/raw(text=windows-parity)",
        }
        baseline = {}
        for name, expression in baseline_expressions.items():
            value = subprocess.run(
                [str(binary), "--output", "hex", "build", "--packet", expression],
                cwd=workspace,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            baseline[name] = {"expression": expression, "bytes_hex": value}
        write_json(evidence / "wire-baseline.json", baseline)

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
                "rust_version": rust_version,
                "runner_image": os.environ.get("ImageOS"),
                "runner_image_version": os.environ.get("ImageVersion"),
                "npcap_runtime": "absent-hosted-boundary",
                "loopback_ipv4_interface": interface4,
                "loopback_ipv6_interface": interface6,
            },
        )
        (evidence / "runner-versions.txt").write_text(
            "\n".join(
                [
                    f"windows={platform.platform()}",
                    f"architecture={platform.machine()}",
                    f"python={platform.python_version()}",
                    f"rustc={rust_version}",
                    f"runner_image={os.environ.get('ImageOS', '')}",
                    f"runner_image_version={os.environ.get('ImageVersion', '')}",
                    f"dumpbin={dumpbin}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        verifier = Path(__file__).with_name("verify-windows-hosted-evidence.py")
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
        print("Windows x86_64 MSVC hosted qualification passed")
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
        print(f"Windows hosted qualification failed: {error}", file=sys.stderr)
        return 1
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
