# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""SCTP and IP-protocol native evidence inventory and strict validation."""
import json
import re

from native_platform_evidence import PROFILES, UNAVAILABLE_REASONS, status_of

SCHEMA = "packetcraftr.sctp-ip-protocol-native-evidence/v1"
OUTPUT_SCHEMAS = ("packetcraftr.output/v16",)
FAMILIES = ("ipv4", "ipv6")
MODES = ("sctp-init", "sctp-cookie-echo", "ip-protocol")
OUTPUTS = ("json", "ndjson")
LIMITS = dict(
    timeout_ms=500,
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
        raise ValueError("SCTP/IP-protocol corpus inventory missing or reordered")
    for case in cases:
        if case.get("families") != list(FAMILIES):
            raise ValueError("SCTP/IP-protocol corpus case must cover ipv4 and ipv6")
        endpoints = case.get("endpoints", [])
        if not endpoints:
            raise ValueError("SCTP/IP-protocol corpus case lacks endpoints")
        for row in endpoints:
            if row.get("status") not in ("response", "timeout"):
                raise ValueError("invalid SCTP/IP-protocol corpus status")
            if (row.get("status") == "timeout") != (row.get("reply") is None):
                raise ValueError("silent SCTP/IP-protocol corpus row cannot carry a reply")


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
        "--method", "raw",
        "--attempts", "1",
        "--max-in-flight", "1",
        "--timeout-ms",
        str(LIMITS["timeout_ms"]),
        "--max-duration-ms",
        str(LIMITS["max_duration_ms"]),
        "--max-probes",
        str(LIMITS["max_probes"]),
        "--max-queue-frames",
        str(LIMITS["max_frames"]),
        "--max-captured-bytes",
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


def validate_output(run, case, corpus, peer):
    from sctp_ip_protocol_isolated_fixture import outgoing
    from tcp_diagnostic_native_evidence import frame_bytes
    docs = documents(run, case["output"])
    if run.get("command") != command(run.get("command", [""])[0], case, run.get("link_mode")) or run.get("limits") != LIMITS:
        raise ValueError("native command changed endpoints or finite limits")
    start, end = run.get("started_unix_ns"), run.get("finished_unix_ns")
    if type(start) is not int or type(end) is not int or not 0 < end - start <= 16000000000:
        raise ValueError("missing or unbounded native process timing")
    result = docs[-1]["result"]
    if result.get("target") != TARGETS[case["family"]] or result.get("resolved_addresses") != [TARGETS[case["family"]]]:
        raise ValueError("native target resolution mismatch")
    if case["output"] == "json":
        endpoints = result["endpoints"]
        probes = [probe for endpoint in endpoints for probe in endpoint["probes"]]
        hosts = result.get("hosts", [])
    else:
        endpoints = [doc["result"]["endpoint"] for doc in docs if doc.get("event") == "endpoint"]
        probes = [doc["result"]["probe"] for doc in docs if doc.get("event") == "probe"]
        hosts = [doc["result"] for doc in docs if doc.get("event") == "host"]
    rows = next(row["endpoints"] for row in corpus["sctp_ip_protocol_scenarios"] if row["id"] == case["scenario"])
    key = "ip_protocol" if case["scenario"] == "ip-protocol" else "port"
    mode = "init" if case["scenario"] == "sctp-init" else "cookie_echo"
    metadata = dict(mode=mode, chunk_type=1 if mode == "init" else 10)
    if key == "port" and result.get("plan", {}).get("sctp_scan") != metadata:
        raise ValueError("native SCTP plan mode mismatch")
    if sorted(endpoint.get(key) for endpoint in endpoints) != sorted(row[key] for row in rows) or len(probes) != len(rows):
        raise ValueError("native endpoint/attempt inventory mismatch")
    if len(hosts) != 1 or hosts[0].get("scan") != "scanned" or hosts[0].get("discovery") != "not_requested":
        raise ValueError("native host disposition mismatch")
    requests = [entry for entry in peer.get("requests", []) if start <= entry["unix_ns"] <= end]
    if len(requests) != len(rows):
        raise ValueError("independent peer did not receive the exact probe inventory")
    sequences, retained = set(), []
    for endpoint in endpoints:
        if endpoint.get("address") != TARGETS[case["family"]] or endpoint.get("transport") != ("ip" if key == "ip_protocol" else "sctp"):
            raise ValueError("native endpoint address/transport mismatch")
        row = next(row for row in rows if row[key] == endpoint[key])
        selected = (endpoint["probes"] if case["output"] == "json" else
                    [probe for probe in probes if probe["sequence"] in endpoint["probes"]])
        if len(selected) != 1:
            raise ValueError("native endpoint lost or shared its attempt")
        probe = selected[0]
        sequence = probe["sequence"]
        if sequence in sequences or probe.get("attempt") != 1:
            raise ValueError("native attempt identity mismatch")
        sequences.add(sequence)
        if key == "port" and probe.get("sctp_scan") != metadata:
            raise ValueError("native attempt SCTP mode mismatch")
        candidates = []
        for entry in requests:
            try:
                outgoing(bytes.fromhex(entry["bytes_hex"]), entry["link_type"], case, sequence, endpoint[key])
                candidates.append(entry)
            except ValueError:
                pass
        if len(candidates) != 1:
            raise ValueError("native attempt has no unique independently verified wire request")
        for field in ("status", "classification"):
            if probe.get(field) != row[field]:
                raise ValueError("native attempt contradicts the independent fixture: " + field)
        inference = endpoint.get("inference", {})
        if endpoint.get("classification") != row["classification"] or any(inference.get(field) != row[field] for field in ("state", "rule")):
            raise ValueError("native inference contradicts the independent fixture")
        if inference.get("supporting") != [sequence] or any(inference.get(field) != [] for field in ("conflicting", "unanswered", "failed")):
            raise ValueError("native inference lost its attempt evidence")
        frame = probe.get("frame")
        if row["status"] == "response":
            raw = frame_bytes(frame or {}, True)
            # Capture link headers may differ from the peer's Ethernet envelope.
            from tcp_diagnostic_wire import network
            received = network(raw, frame["link_type"])["wire"]
            if received not in [network(bytes.fromhex(answer["bytes_hex"]), 1)["wire"] for answer in candidates[0]["replies"]]:
                raise ValueError("retained response was not emitted by the independent peer")
            stamp = frame["timestamp"]
            if not start <= stamp["unix_seconds"] * 1000000000 + stamp["nanoseconds"] <= end:
                raise ValueError("retained frame is outside its invocation")
            retained.append(raw)
        elif frame or candidates[0]["replies"]:
            raise ValueError("silent endpoint has response evidence")
    if result.get("undecoded") or result.get("unattributed") or any(doc.get("event") in ("undecoded", "unattributed") for doc in docs):
        raise ValueError("unexpected fixture evidence")
    if result.get("retained_evidence_bytes") != sum(map(len, retained)):
        raise ValueError("retained evidence byte accounting mismatch")
    stats = docs[-1].get("stats", {})
    if any(stats.get("capture", {}).get(field, 0) for field in ("dropped_frames", "dropped_bytes", "overflow_events")):
        raise ValueError("capture loss prevents native acceptance")
    if not len(rows) <= stats.get("packets_completed", 0) == stats.get("packets_attempted", -1) <= LIMITS["max_probes"]:
        raise ValueError("native transmission inventory mismatch")
    return dict(endpoints=len(rows), independently_verified_requests=len(requests))


def coverage_complete(report):
    if (report.get("dirty") is not False
            or report.get("reviewed_commit") != report.get("revision")
            or report.get("launcher_error")
            or [p.get("profile") for p in report.get("profiles", [])] != list(PROFILES)):
        return False
    for profile in report.get("profiles", []):
        isolation = profile.get("isolation", {})
        if (not valid_cases(profile) or profile.get("error")
                or report.get("platform") != "Linux"
                or profile.get("execution") != "privileged_native"
                or profile.get("privilege_granted") is not True
                or isolation.get("kind") != "fresh_network_namespace"
                or type(isolation.get("netns_inode")) is not int
                or type(isolation.get("parent_netns_inode")) is not int
                or isolation["netns_inode"] == isolation["parent_netns_inode"]
                or not profile.get("binary_digest_sha256")
                or profile.get("build", {}).get("exit_code") != 0):
            return False
        for case in profile.get("cases", []):
            if profile.get("profile") in ("portable", "default", "pcap-free"):
                if case.get("status") != "unavailable" or case.get("expected_refusal") is not True:
                    return False
            elif case.get("status") != "exercised":
                return False
    return bool(report.get("profiles"))


def valid_cases(profile):
    expected = inventory((profile.get("profile"),))[0]["cases"]
    keys = ("id", "scenario", "family", "output")
    return ([tuple(case.get(key) for key in keys) for case in profile.get("cases", [])]
            == [tuple(case[key] for key in keys) for case in expected])


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
    profiles = report.get("profiles", [])
    names = [profile.get("profile") for profile in profiles]
    if not names or names != [name for name in PROFILES if name in names]:
        raise ValueError("profile inventory is missing, duplicated or reordered")
    for profile in profiles:
        if profile.get("profile") not in PROFILES:
            raise ValueError("unknown profile")
        if not valid_cases(profile):
            raise ValueError("case inventory is missing, duplicated or changed")
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
                validate_output(run, case, corpus, profile.get("independent_peer", {}))
        if profile.get("status") != status_of(profile.get("cases", [])):
            raise ValueError("profile status disagrees with case statuses")
    if require_complete and not coverage_complete(report):
        raise ValueError("native evidence coverage is incomplete")
    return True
