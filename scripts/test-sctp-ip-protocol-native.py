#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Revision-bound M13 SCTP and IP-protocol native validation runner.

No external destinations, host interface changes, DNS, or driver installation.
"""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import time
import subprocess

from native_platform_evidence import PROFILES, status_of
import sctp_ip_protocol_native_evidence as evidence
from validation_evidence import ROOT, digest


SOURCES = (
    "scripts/test-sctp-ip-protocol-native.py",
    "scripts/sctp_ip_protocol_native_evidence.py",
    "scripts/sctp_ip_protocol_isolated_fixture.py",
    "scripts/tcp_diagnostic_isolated_fixture.py",
    "scripts/tcp_diagnostic_native_evidence.py",
    "scripts/tcp_diagnostic_corpus.py",
    "scripts/tcp_diagnostic_wire.py",
    "scripts/discovery_isolated_fixture.py",
    "scripts/benchmark-scanner.py",
    "scripts/validation_evidence.py",
    "scripts/native_platform_evidence.py",
    "docs/scanner-corpus.v1.json",
    "schemas/packetcraftr.scanner-corpus.v1.schema.json",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
)


def git(*args):
    return subprocess.check_output(
        ["git", "-c", "safe.directory=" + str(ROOT), *args],
        cwd=ROOT,
        text=True,
        timeout=30,
    ).strip()


def source_identity():
    paths = set(SOURCES)
    paths.update(
        str(path.relative_to(ROOT))
        for path in (ROOT / "crates").rglob("*")
        if path.is_file() and (path.suffix == ".rs" or path.name == "Cargo.toml")
    )
    return {path: digest(ROOT / path) for path in sorted(paths)}


def privileged():
    return (
        bool(ctypes.windll.shell32.IsUserAnAdmin())
        if platform.system() == "Windows"
        else os.geteuid() == 0
    )


def write(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


FEATURES = {"portable": ["--no-default-features"], "default": [],
            "layer2": ["--no-default-features", "--features", "native-layer2"],
            "pcap-free": ["--no-default-features", "--features", "native-layer3"],
            "full-native": ["--all-features"]}


def measurements():
    spec = importlib.util.spec_from_file_location("m13_measurements", ROOT / "scripts/benchmark-scanner.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cargo_record(command, log):
    measurement = measurements()
    measurement.PROCESS_TIMEOUT = 900
    try:
        run = measurement.measured(command)
    except Exception as error:
        write(log, dict(command=command, error=str(error)))
        raise RuntimeError("Cargo execution failed; retained " + str(log)) from error
    write(log, run)
    if run["exit_code"]:
        raise RuntimeError("Cargo execution failed; retained " + str(log))
    return run


def build(profile, args):
    command = ["cargo", "build", "--locked", "-p", "packetcraftr-cli", "--message-format=json", *FEATURES[profile]]
    if args.inside:
        command.append("--offline")
    log = args.report.parent / ("sctp-ip-protocol-build-" + profile + ".json")
    run = cargo_record(command, log)
    artifacts = [json.loads(line) for line in run["stdout"].splitlines() if line.startswith("{")]
    paths = {item["executable"] for item in artifacts if item.get("reason") == "compiler-artifact" and item.get("executable") and item.get("target", {}).get("name") == "packetcraftr"}
    if len(paths) != 1:
        raise ValueError("build lacks a unique CLI artifact")
    binary = args.report.parent / ("packetcraftr-m13-" + profile)
    shutil.copy2(paths.pop(), binary)
    return binary.resolve(), dict(path=str(log), digest_sha256=digest(log), command=command, exit_code=0)


def execute(binary, case, measurement, link_mode):
    command = evidence.command(binary, case, link_mode)
    started = time.time_ns()
    run = measurement.measured(command)
    run.update(command=command, limits=evidence.LIMITS, link_mode=link_mode,
               started_unix_ns=started, finished_unix_ns=time.time_ns())
    return run


def run_profile(profile, args, report, corpus, measurement):
    from sctp_ip_protocol_isolated_fixture import provision
    binary, build_record = build(profile["profile"], args)
    profile.update(binary=str(binary), binary_digest_sha256=digest(binary), build=build_record,
                   execution="privileged_native", privilege_granted=True,
                   isolation=dict(kind="fresh_network_namespace", parent_netns_inode=args.parent_netns,
                                  netns_inode=os.stat('/proc/self/ns/net').st_ino),
                   independent_peer=dict(requests=[], setup=[]))
    link_mode = "layer2" if profile["profile"] == "layer2" else "layer3"
    with provision(profile["independent_peer"]):
        for case in profile["cases"]:
            try:
                run = execute(binary, case, measurement, link_mode)
                case["run"] = run
                docs = evidence.documents(run, case["output"], successful=False)
                if run["exit_code"]:
                    error = docs[-1].get("error", {})
                    if (profile["profile"] in ("portable", "default", "pcap-free")
                            and error.get("code") in ("capability.unsupported", "capability.route")):
                        case.update(status="unavailable", reason="unsupported_capability", expected_refusal=True,
                                    message=error.get("message", "typed native refusal"))
                    else:
                        raise ValueError("unexpected native process failure: " + str(error))
                else:
                    run["observation"] = evidence.validate_output(run, case, corpus, profile["independent_peer"])
                    case.update(status="exercised")
                    case.pop("reason", None)
                    case.pop("message", None)
            except Exception as error:
                case.update(status="failed", message=str(error))
                case.pop("reason", None)
            profile["status"] = status_of(profile["cases"])
            write(args.report, report)
    if digest(binary) != profile["binary_digest_sha256"]:
        raise ValueError("native executable changed during execution")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviewed-commit", required=True)
    parser.add_argument("--profiles", default=",".join(PROFILES))
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "target/validation/sctp-ip-protocol-native.json",
    )
    parser.add_argument("--emit-unavailable", choices=evidence.UNAVAILABLE_REASONS)
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--parent-netns", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.report = args.report.resolve()
    profiles = args.profiles.split(",")
    if profiles != [p for p in PROFILES if p in profiles] or not profiles:
        parser.error("profiles must be unique and in supported inventory order")
    if not evidence.hexadecimal(args.reviewed_commit, 40):
        parser.error("reviewed commit must be a full lowercase immutable SHA")
    revision, dirty = git("rev-parse", "HEAD"), bool(git("status", "--porcelain"))
    corpus_path = ROOT / "docs/scanner-corpus.v1.json"
    corpus = evidence.strict_json(corpus_path.read_text(encoding="utf-8"))
    evidence.validate_corpus(corpus)
    native_platform = {
        "Darwin": "macOS",
        "Windows": "Windows",
        "Linux": "Linux",
    }.get(platform.system())
    if native_platform is None:
        parser.error("unsupported native platform")
    sources = source_identity()
    corpus_sha = digest(corpus_path)
    report = evidence.initial(
        native_platform,
        revision,
        dirty,
        corpus_sha,
        corpus["dataset_version"],
        sources,
        profiles,
    )
    report.update(
        reviewed_commit=args.reviewed_commit,
        kernel=platform.release(),
        architecture=platform.machine(),
        captured_unix_ns=time.time_ns(),
    )
    if args.emit_unavailable:
        for profile in report["profiles"]:
            for case in profile["cases"]:
                case["reason"] = args.emit_unavailable
            profile["status"] = status_of(profile["cases"])
        report["status"] = evidence.report_status(report["profiles"])
    write(args.report, report)
    try:
        if revision != args.reviewed_commit or dirty:
            raise ValueError("native execution requires the exact clean reviewed commit")
        if args.emit_unavailable:
            evidence.validate(
                report,
                corpus,
                args.reviewed_commit,
                args.require_complete,
                sources,
                corpus_sha,
            )
            return 0
        if not privileged():
            for profile in report["profiles"]:
                for case in profile["cases"]:
                    case.update(
                        reason="privilege_not_granted",
                        message="native execution requires existing root/administrator privileges",
                    )
                profile["status"] = status_of(profile["cases"])
            raise ValueError("native privilege not granted")
        if native_platform != "Linux":
            for profile in report["profiles"]:
                for case in profile["cases"]:
                    case.update(reason="isolation_unavailable", message="independent M13 link fixture requires a fresh Linux network namespace")
            raise ValueError("independent M13 native isolation is unavailable on this platform")
        if not args.inside:
            missing = [name for name in ("unshare", "ip", "ethtool") if not shutil.which(name)]
            if missing:
                for profile in report["profiles"]:
                    for case in profile["cases"]:
                        case.update(reason="isolation_unavailable", message="missing isolation prerequisites: " + ','.join(missing))
                raise ValueError("missing isolation prerequisites: " + ','.join(missing))
            cargo_record(["cargo", "fetch", "--locked"], args.report.parent / "sctp-ip-protocol-fetch.json")
            command = ["unshare", "--net", "--", sys.executable, str(Path(__file__).resolve()),
                       "--inside", "--parent-netns", str(os.stat('/proc/self/ns/net').st_ino),
                       "--reviewed-commit", args.reviewed_commit, "--profiles", args.profiles,
                       "--report", str(args.report)]
            if args.require_complete:
                command.append("--require-complete")
            try:
                result = subprocess.run(command, cwd=ROOT, timeout=3000)
            finally:
                report = evidence.strict_json(args.report.read_text())
            if result.returncode:
                raise ValueError("isolated native launcher failed with exit " + str(result.returncode))
            evidence.validate(report, corpus, args.reviewed_commit, args.require_complete, sources, corpus_sha)
            return 0
        current = os.stat('/proc/self/ns/net').st_ino
        interfaces = json.loads(subprocess.check_output(['ip', '-j', 'link'], text=True, timeout=15))
        if not args.parent_netns or args.parent_netns == current or sorted(item['ifname'] for item in interfaces) != ['lo']:
            raise ValueError("refusing execution outside a fresh parent-distinct namespace")
        measurement = measurements()
        for profile in report["profiles"]:
            try:
                run_profile(profile, args, report, corpus, measurement)
            except Exception as error:
                profile["error"] = str(error)
                for case in profile["cases"]:
                    if case["status"] == "unavailable" and case["reason"] == "runtime_evidence_missing":
                        case.update(status="failed", message="profile execution failed: " + str(error))
                profile["status"] = status_of(profile["cases"])
            write(args.report, report)
        if git('rev-parse', 'HEAD') != revision or bool(git('status', '--porcelain')) or source_identity() != sources:
            raise ValueError("source identity changed during native execution")
        report["status"] = evidence.report_status(report["profiles"])
        report["acceptance_complete"] = evidence.coverage_complete(report)
        evidence.validate(
            report,
            corpus,
            args.reviewed_commit,
            args.require_complete,
            sources,
            corpus_sha,
        )
    except Exception as error:
        report["launcher_error"] = str(error)
        report["acceptance_complete"] = False
        report["status"] = evidence.report_status(report["profiles"])
        write(args.report, report)
        print(str(error), file=sys.stderr)
        return 1
    finally:
        write(args.report, report)
    return 1 if report["status"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())
