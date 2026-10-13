#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Collect original OS-stack evidence in disposable, isolated native fixtures.

Linux uses two fresh network namespaces and documentation-address veth links.
Other platforms exercise existing loopback capabilities without installing drivers
or changing interfaces; these runs cannot close isolated native acceptance gates.
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import select
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "packetcraftr.os-native-evidence/v1"
OPEN_PORT = 43123
OTHER_OPEN_PORT = 43124
CLOSED_PORT = 43125


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_identity() -> dict:
    try:
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        dirty = bool(subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True
        ).strip())
    except (OSError, subprocess.CalledProcessError):
        return {"revision": None, "dirty": None, "runner_sha256": sha256(Path(__file__))}
    paths = [*ROOT.glob("Cargo.*"), ROOT / "rust-toolchain.toml",
             *ROOT.glob("crates/**/src/**/*.rs"), *ROOT.glob("crates/**/Cargo.toml"),
             ROOT / "crates/packetcraftr/data/os-fingerprints.v1.json", Path(__file__)]
    digest = hashlib.sha256()
    for path in sorted(set(paths)):
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0" + path.read_bytes())
    return {"revision": revision, "dirty": dirty,
            "source_sha256": digest.hexdigest(), "runner_sha256": sha256(Path(__file__))}


def capture_driver_identity() -> dict:
    """Query the installed capture library without installing or selecting a driver."""
    name = ctypes.util.find_library("pcap")
    if platform.system() == "Windows":
        candidate = Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/Npcap/wpcap.dll"
        name = str(candidate) if candidate.is_file() else None
    if not name:
        return {"status": "unavailable", "library": None, "version": None}
    try:
        library = ctypes.CDLL(name)
        library.pcap_lib_version.restype = ctypes.c_char_p
        version = library.pcap_lib_version()
        return {"status": "queried", "library": name,
                "version": version.decode("utf-8", errors="replace") if version else None}
    except (OSError, AttributeError) as error:
        return {"status": "unavailable", "library": name, "version": None, "reason": str(error)}


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, text=True, capture_output=True,
                          timeout=30, **kwargs)


def listeners(*, isolated: bool = False) -> list[socket.socket]:
    sockets = []
    for family in (socket.AF_INET, socket.AF_INET6):
        for port in (OPEN_PORT, OTHER_OPEN_PORT):
            listener = socket.socket(family)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            address = (("0.0.0.0" if isolated else "127.0.0.1") if family == socket.AF_INET
                       else ("::" if isolated else "::1"))
            listener.bind((address, port))
            listener.listen(32)
            sockets.append(listener)
    return sockets


def peer() -> None:
    sockets = listeners(isolated=True)
    print("ready", flush=True)
    try:
        while True:
            time.sleep(1)
    finally:
        for listener in sockets:
            listener.close()


def fixture() -> subprocess.Popen:
    process = subprocess.Popen(
        ["unshare", "--net", sys.executable, str(Path(__file__)), "--peer"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if not select.select([process.stdout], [], [], 10)[0] or process.stdout.readline().strip() != "ready":
        process.kill()
        _, error = process.communicate()
        raise RuntimeError(f"peer namespace did not initialize: {error}")
    try:
        run(["ip", "link", "set", "lo", "up"])
        run(["ip", "link", "add", "os-source", "type", "veth", "peer", "name", "os-peer"])
        run(["ip", "link", "set", "os-peer", "netns", str(process.pid)])
        for prefix, interface, octet in [([], "os-source", 1),
                                        (["nsenter", "-t", str(process.pid), "-n"], "os-peer", 2)]:
            run(prefix + ["ip", "link", "set", interface, "up"])
            run(prefix + ["ip", "addr", "add", f"192.0.2.{octet}/24", "dev", interface])
            run(prefix + ["ip", "-6", "addr", "add", f"2001:db8::{octet}/64", "dev", interface, "nodad"])
            # Real kernel replies must have complete checksums in the retained
            # capture; hardware/offload placeholders cannot establish fidelity.
            run(prefix + ["ethtool", "-K", interface, "tx", "off", "rx", "off",
                          "tso", "off", "gso", "off", "gro", "off"])
        return process
    except Exception:
        process.terminate()
        process.wait(timeout=5)
        raise


def cases(binary: Path, corpus: Path | None, isolated: bool, expected_family: str | None) -> list[dict]:
    results = []
    for family, address in [("ipv4", "192.0.2.2" if isolated else "127.0.0.1"),
                            ("ipv6", "2001:db8::2" if isolated else "::1")]:
        for scenario, open_port, closed_port, outcome in [
            ("suitable", OPEN_PORT, CLOSED_PORT, None),
            ("missing_open", CLOSED_PORT, OPEN_PORT, "inconclusive"),
            ("missing_closed", OPEN_PORT, OTHER_OPEN_PORT, "inconclusive"),
        ]:
            for format_name in ("json", "ndjson"):
                command = [str(binary), "--output", format_name, "identify-os", address,
                           "--open-port", str(open_port), "--closed-port", str(closed_port),
                           "--attempts", "1", "--timeout-ms", "200", "--max-duration-ms", "10000"]
                if isolated:
                    command += ["--interface", "os-source", "--link-mode", "layer2"]
                if corpus:
                    command += ["--corpus", str(corpus)]
                try:
                    completed = subprocess.run(command, capture_output=True, text=True, timeout=20)
                except (OSError, subprocess.TimeoutExpired) as error:
                    results.append({"family": family, "scenario": scenario, "format": format_name,
                                    "command": command, "status": "failed", "reason": str(error)})
                    continue
                item = {"family": family, "scenario": scenario, "format": format_name,
                        "command": command, "returncode": completed.returncode,
                        "stderr": completed.stderr, "stdout": completed.stdout, "status": "failed"}
                try:
                    records = ([json.loads(completed.stdout)] if format_name == "json" else
                               [json.loads(line) for line in completed.stdout.splitlines()])
                    if not records or any(record["schema"] != "packetcraftr.output/v14" for record in records):
                        raise ValueError("missing or incompatible output family")
                    if format_name == "ndjson":
                        if [record["sequence"] for record in records] != list(range(len(records))):
                            raise ValueError("non-contiguous stream")
                        if records[-1].get("event") not in ("complete", "error") or any(
                            record.get("event") in ("complete", "error") for record in records[:-1]
                        ):
                            raise ValueError("invalid terminal records")
                    item["records"] = records
                    final = records[-1]
                    if completed.returncode or final["status"] != "success":
                        item["error"] = final.get("error")
                        if final.get("error", {}).get("kind") == "capability":
                            item["status"] = "unsupported"
                        raise ValueError("native execution did not complete successfully")
                    result = final["result"]
                    if not result["complete"]:
                        raise ValueError("evidence incomplete")
                    actual = result["identification"]["outcome"]
                    if outcome and actual != outcome:
                        raise ValueError(f"expected {outcome}, received {actual}")
                    if not outcome:
                        required = {"open_syn", "closed_syn", "timestamp_syn"}
                        observed = {observation["probe"] for observation in result["observations"]}
                        if not required <= observed or actual not in ("unknown", "matched", "ambiguous"):
                            raise ValueError("suitable stack did not supply required fingerprint evidence")
                    if not outcome and expected_family and (actual != "matched" or any(
                            candidate["family"] != expected_family
                            for candidate in result["identification"]["candidates"])):
                        raise ValueError(f"expected qualified {expected_family} family")
                    if final["stats"]["packets_attempted"] > 32:
                        raise ValueError("transmission ceiling exceeded")
                    item["status"] = "exercised"
                    item["outcome"] = actual
                    item["records"] = records
                except (KeyError, TypeError, ValueError) as error:
                    item["reason"] = str(error)
                results.append(item)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    filename = "packetcraftr.exe" if platform.system() == "Windows" else "packetcraftr"
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug" / filename)
    parser.add_argument("--output", type=Path, default=ROOT / "target/os-native.json")
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--expect-family", choices=("linux", "windows", "macos"))
    parser.add_argument("--source-identity", type=Path)
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--initialize-only", action="store_true")
    parser.add_argument("--reviewed-commit", help="Require an immutable clean reviewed source revision")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--parent-netns", help=argparse.SUPPRESS)
    parser.add_argument("--peer", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.peer:
        peer()
        return 0
    args.binary = args.binary.resolve()
    args.output = args.output.resolve()
    if args.corpus:
        args.corpus = args.corpus.resolve()
    linux = platform.system() == "Linux"
    identity = source_identity()
    identity_error = None
    if args.source_identity:
        try:
            identity = json.loads(args.source_identity.read_text())
            if not isinstance(identity, dict):
                raise ValueError("source identity must be an object")
        except (OSError, ValueError) as error:
            identity_error = str(error)
    corpus_path = args.corpus or ROOT / "crates/packetcraftr/data/os-fingerprints.v1.json"
    report = {"schema": SCHEMA, "source": identity, "system": platform.system(),
              "kernel": platform.release(), "architecture": platform.machine(),
              "binary_sha256": sha256(args.binary) if args.binary.is_file() else None,
              "corpus_sha256": sha256(corpus_path) if corpus_path.is_file() else None,
              "isolated": linux and args.inside, "cases": [], "status": "unavailable",
              "captured_at": datetime.now(timezone.utc).isoformat(),
              "reviewed_commit": args.reviewed_commit,
              "acceptance_complete": False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    if args.initialize_only:
        return 0
    if linux and not args.inside and os.geteuid() == 0:
        command = ["unshare", "--net", sys.executable, str(Path(__file__)),
                   *sys.argv[1:], "--inside", "--parent-netns", os.readlink("/proc/self/ns/net")]
        try:
            return subprocess.run(command, check=False, timeout=900).returncode
        except (OSError, subprocess.SubprocessError) as error:
            report["reason"] = str(error)
            args.output.write_text(json.dumps(report, indent=2) + "\n")
            return int(args.require_complete)
    report["capture_driver"] = capture_driver_identity()
    report["effective_uid"] = os.geteuid() if hasattr(os, "geteuid") else None
    report["network_namespace"] = os.readlink("/proc/self/ns/net") if Path("/proc/self/ns/net").exists() else None
    process = None
    sockets = []
    try:
        if identity_error:
            raise RuntimeError(f"invalid source identity: {identity_error}")
        if args.reviewed_commit and (len(args.reviewed_commit) != 40 or
                any(character not in "0123456789abcdef" for character in args.reviewed_commit) or
                identity.get("revision") != args.reviewed_commit or identity.get("dirty") is not False):
            raise RuntimeError("execution requires the exact clean reviewed revision")
        if not args.binary.is_file():
            raise RuntimeError("build the all-feature CLI first")
        if identity.get("runner_sha256") != sha256(Path(__file__)):
            raise RuntimeError("source identity does not identify this runner")
        if linux:
            if not args.inside or os.geteuid() != 0:
                raise RuntimeError("Linux isolated fixtures require root and fresh network namespaces")
            if os.readlink("/proc/self/ns/net") == args.parent_netns:
                raise RuntimeError("fixture namespace is not distinct from its parent")
            for tool in ("ip", "unshare", "nsenter", "ethtool"):
                if not shutil.which(tool):
                    raise RuntimeError(f"missing fixture prerequisite: {tool}")
            process = fixture()
        else:
            sockets = listeners()
        report["cases"] = cases(args.binary, args.corpus, bool(report["isolated"]), args.expect_family)
        states = {case["status"] for case in report["cases"]}
        report["status"] = ("failed" if "failed" in states else
                            "exercised" if states == {"exercised"} else
                            "unsupported" if states == {"unsupported"} else "partial")
        report["acceptance_complete"] = report["status"] == "exercised" and report["isolated"]
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report["reason"] = str(error)
        report["acceptance_complete"] = False
    finally:
        if process:
            try:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired) as error:
                report.update(status="failed", acceptance_complete=False, cleanup_error=str(error))
        for listener in sockets:
            listener.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "kernel": report["kernel"],
                      "cases": len(report["cases"]), "output": str(args.output)}))
    return int(report["status"] == "failed" or (args.require_complete and not report["acceptance_complete"]))


if __name__ == "__main__":
    raise SystemExit(main())
