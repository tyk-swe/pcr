# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""M13 SCTP and IP-protocol native evidence inventory and strict validation."""
import json
import re

from native_platform_evidence import PROFILES, UNAVAILABLE_REASONS, status_of

SCHEMA = "packetcraftr.sctp-ip-protocol-native-evidence/v1"
OUTPUT_SCHEMAS = ("packetcraftr.output/v16",)
FAMILIES = ("ipv4", "ipv6")
MODES = ("sctp-init", "sctp-cookie-echo", "ip-protocol")
OUTPUTS = ("json", "ndjson")
LIMITS = dict(
    timeout_ms=40,
    max_duration_ms=10000,
    max_probes=8,
    max_frames=64,
    max_bytes=65536,
    snap_length=1500,
    max_output_bytes=1048576,
)
TARGETS = {"ipv4": "192.0.2.2", "ipv6": "2001:db8::2"}


def hexadecimal(value, length):
    return isinstance(value, str) and bool(re.fullmatch(f"[0-9a-f]{{{length}}}", value))


def strict_json(text):
    def no_dups(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON key {key}")
            out[key] = value
        return out

    return json.loads(text, object_pairs_hook=no_dups)


def validate_corpus(corpus):
    cases = corpus.get("sctp_ip_protocol_scenarios", [])
    if [case.get("id") for case in cases] != list(MODES):
        raise ValueError("M13 SCTP/IP-protocol corpus inventory missing or reordered")
    for case in cases:
        if case.get("families") != list(FAMILIES):
            raise ValueError("M13 corpus case must cover ipv4 and ipv6")
        endpoints = case.get("endpoints", [])
        if not endpoints:
            raise ValueError("M13 corpus case lacks endpoints")
        for row in endpoints:
            if row.get("status") not in ("response", "timeout"):
                raise ValueError("invalid M13 corpus status")
            if (row.get("status") == "timeout") != (row.get("reply") is None):
                raise ValueError("silent M13 corpus row cannot carry a reply")


def inventory(profiles=PROFILES):
    out = []
    for profile in profiles:
        cases = []
        for mode in MODES:
            for family in FAMILIES:
                for output in OUTPUTS:
                    cases.append(
                        dict(
                            id=f"{mode}:{family}:{output}",
                            scenario=mode,
                            family=family,
                            output=output,
                            status="unavailable",
                            reason="runtime_evidence_missing",
                            message="native reviewed execution has not completed",
                        )
                    )
        out.append(
            dict(
                profile=profile,
                execution="unexercised",
                privilege_granted=False,
                status=status_of(cases),
                cases=cases,
            )
        )
    return out


def initial(platform_name, revision, dirty, corpus_sha256, corpus_version, sources, profiles=PROFILES):
    return dict(
        schema=SCHEMA,
        platform=platform_name,
        revision=revision,
        dirty=dirty,
        corpus_sha256=corpus_sha256,
        corpus_dataset_version=corpus_version,
        sources=sources,
        limits=LIMITS,
        status="unavailable",
        acceptance_complete=False,
        profiles=inventory(profiles),
    )


def command(binary, case, link_mode="layer3"):
    target = TARGETS[case["family"]]
    args = [
        str(binary),
        "--output",
        case["output"],
        "scan",
        target,
        "--family",
        case["family"],
        "--link-mode",
        link_mode,
        "--timeout-ms",
        str(LIMITS["timeout_ms"]),
        "--max-duration-ms",
        str(LIMITS["max_duration_ms"]),
        "--max-probes",
        str(LIMITS["max_probes"]),
        "--max-frames",
        str(LIMITS["max_frames"]),
        "--max-bytes",
        str(LIMITS["max_bytes"]),
        "--snap-length",
        str(LIMITS["snap_length"]),
    ]
    if case["scenario"] == "ip-protocol":
        args.extend(["--transport", "ip", "--ip-protocols", "47,50,112,115,254"])
    else:
        sctp_mode = "init" if case["scenario"] == "sctp-init" else "cookie-echo"
        args.extend(
            [
                "--transport",
                "sctp",
                "--sctp-scan",
                sctp_mode,
                "--ports",
                "2000-2005",
            ]
        )
    return args


def documents(run, output_mode, successful=True):
    for stream_name in ("stdout", "stderr"):
        value = run.get(stream_name)
        if not isinstance(value, str) or len(value.encode("utf-8")) > LIMITS["max_output_bytes"]:
            raise ValueError("missing or unbounded process output")
    docs = (
        [strict_json(run["stdout"])]
        if output_mode == "json"
        else [strict_json(line) for line in run["stdout"].splitlines() if line.strip()]
    )
    if not docs or any(
        doc.get("schema") not in OUTPUT_SCHEMAS or doc.get("command") != "scan"
        for doc in docs
    ):
        raise ValueError("missing or incompatible output/v16 scan envelope")
    if output_mode == "ndjson":
        if [doc.get("sequence") for doc in docs] != list(range(len(docs))):
            raise ValueError("noncontiguous NDJSON sequence")
        terminals = [doc for doc in docs if doc.get("event") in ("complete", "error")]
        if len(terminals) != 1 or terminals[0] is not docs[-1]:
            raise ValueError("invalid NDJSON terminal record")
    if successful and (
        run.get("exit_code") != 0 or any(doc.get("status") != "success" for doc in docs)
    ):
        raise ValueError("native process did not complete successfully")
    return docs


def report_status(profiles):
    statuses = [profile.get("status") for profile in profiles]
    if "failed" in statuses:
        return "failed"
    if statuses and all(status == "exercised" for status in statuses):
        return "exercised"
    return "unavailable"


def coverage_complete(report):
    for profile in report.get("profiles", []):
        for case in profile.get("cases", []):
            if profile.get("profile") in ("portable", "default", "pcap-free"):
                if not case.get("expected_refusal"):
                    return False
            elif case.get("status") != "exercised":
                return False
    return bool(report.get("profiles"))


def validate(report, corpus, reviewed_commit=None, require_complete=False, expected_sources=None, expected_corpus_sha=None):
    validate_corpus(corpus)
    if report.get("schema") != SCHEMA:
        raise ValueError("unexpected native evidence schema")
    if not hexadecimal(report.get("revision", ""), 40) or report.get("dirty") is not False:
        raise ValueError("native evidence requires a clean 40-hex revision")
    if reviewed_commit and report.get("reviewed_commit") != reviewed_commit:
        raise ValueError("reviewed commit mismatch")
    if expected_corpus_sha and report.get("corpus_sha256") != expected_corpus_sha:
        raise ValueError("corpus digest mismatch")
    if report.get("corpus_dataset_version") != corpus.get("dataset_version"):
        raise ValueError("corpus dataset_version mismatch")
    if expected_sources and report.get("sources") != expected_sources:
        raise ValueError("source digest inventory mismatch")
    for profile in report.get("profiles", []):
        if profile.get("profile") not in PROFILES:
            raise ValueError("unknown profile")
        for case in profile.get("cases", []):
            status = case.get("status")
            if status not in ("exercised", "unavailable", "failed"):
                raise ValueError("invalid case status")
            if status == "unavailable" and case.get("reason") not in UNAVAILABLE_REASONS:
                raise ValueError("unavailable case lacks a typed reason")
            if case.get("expected_refusal"):
                run = case.get("run", {})
                docs = documents(run, case["output"], successful=False)
                err = docs[-1].get("error", {})
                if (
                    run.get("exit_code") in (None, 0)
                    or err.get("code") not in ("capability.unsupported", "capability.route")
                ):
                    raise ValueError("expected_refusal requires a typed capability error")
            if status == "exercised":
                run = case.get("run", {})
                documents(run, case["output"], successful=True)
        if profile.get("status") != status_of(profile.get("cases", [])):
            raise ValueError("profile status disagrees with case statuses")
    if require_complete and not coverage_complete(report):
        raise ValueError("native evidence coverage is incomplete")
    return True
