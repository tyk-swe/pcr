#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Revision-bound M13 SCTP and IP-protocol native validation runner.

No external destinations, host interface changes, DNS, or driver installation.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import sys
import time
import subprocess

from native_platform_evidence import PROFILES, status_of
import sctp_ip_protocol_native_evidence as evidence
from validation_evidence import ROOT, digest


SOURCES = (
    "scripts/test-sctp-ip-protocol-native.py",
    "scripts/sctp_ip_protocol_native_evidence.py",
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
