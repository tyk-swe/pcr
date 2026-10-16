#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the shipped identification CLI on bounded IPv4/IPv6 loopback fixtures.

The resulting report records four HTTP/HTTPS cases across IPv4 and IPv6,
with wire exchanges and current-schema NDJSON. An unavailable family or failed build
is a failure, never a successful skip. Uses only the Python standard library;
the Rust contract suite owns full JSON-schema validation.
"""

import argparse
import datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "packetcraftr.output/v18"
FIXTURES = ROOT / "scripts/fixtures/service-identification"
PROFILES = {"all": ["--all-features"]}
HTTP = b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.2\r\n\r\n"
HTTP_REQUEST = b"HEAD / HTTP/1.0\r\n\r\n"
PEER_DISCONNECT_ERRNOS = {errno.ENOTCONN, errno.ECONNRESET, errno.ECONNABORTED}
PEER_DISCONNECT_WINERRORS = {10057, 10054, 10053}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def scenarios():
    return [
        {"name": "known-http", "probe": "http-head", "reply": HTTP,
         "outcome": "matched", "product": "nginx", "version": "1.26.2"},
        {"name": "known-https", "probe": "http-head", "reply": HTTP, "tls": True,
         "outcome": "matched", "product": "nginx", "version": "1.26.2"},
    ]


class Fixture:
    """A single original loopback service with an observable request count."""

    def __init__(self, family, scenario):
        self.scenario = scenario
        self.stop = threading.Event()
        self.requests = []
        self.replies = []
        self.errors = []
        self.connections = 0
        self.sni_names = []
        self.tls_context = None
        if scenario.get("tls"):
            self.tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.tls_context.load_cert_chain(FIXTURES / "loopback-cert.pem", FIXTURES / "loopback-key.pem")
            self.tls_context.set_servername_callback(self.observe_sni)
        self.listener = socket.socket(family, socket.SOCK_STREAM)
        try:
            if family == socket.AF_INET6:
                self.listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            self.listener.bind(("127.0.0.1" if family == socket.AF_INET else "::1", 0))
            self.listener.settimeout(0.05)
            self.listener.listen(4)
            self.address = self.listener.getsockname()
            self.thread = threading.Thread(target=self.serve, daemon=True)
            self.thread.start()
        except Exception:
            self.listener.close()
            raise

    def close(self):
        self.stop.set()
        self.thread.join(timeout=3)
        self.listener.close()
        require(not self.thread.is_alive(), "fixture worker failed to stop")
        require(not self.errors, "; ".join(self.errors))

    def observe_sni(self, _peer, name, _context):
        self.sni_names.append(name)

    def serve(self):
        try:
            while not self.stop.is_set():
                try:
                    peer, _ = self.listener.accept()
                    self.connections += 1
                    with peer:
                        peer.settimeout(2)
                        if self.tls_context:
                            with self.tls_context.wrap_socket(peer, server_side=True) as encrypted:
                                self.serve_tcp(encrypted)
                        else:
                            self.serve_tcp(peer)
                except socket.timeout:
                    continue
        except Exception as error:
            if not self.stop.is_set():
                self.errors.append(str(error))

    def serve_tcp(self, peer):
        scenario = self.scenario
        request = b""
        while b"\r\n\r\n" not in request:
            part = peer.recv(256)
            require(part, "HTTP client closed before its header")
            request += part
            require(len(request) <= 4096, "HTTP fixture request exceeded its bound")
        require(request == HTTP_REQUEST, "HTTP request differs from the reviewed HEAD bytes")
        self.requests.append(request)
        self.replies.append(scenario["reply"])
        peer.sendall(scenario["reply"])
        try:
            if scenario.get("tls"):
                # SSLSocket.unwrap sends close_notify before waiting for the
                # client's shutdown; app bytes are already retained above.
                peer.unwrap()
                extra = b""
            else:
                peer.shutdown(socket.SHUT_WR)
                extra = peer.recv(256)
        except OSError as error:
            # Closing a bounded reader with unread reply bytes may reset TCP.
            disconnected = (
                error.errno in PEER_DISCONNECT_ERRNOS
                or error.errno in PEER_DISCONNECT_WINERRORS
                or getattr(error, "winerror", None) in PEER_DISCONNECT_WINERRORS
            )
            tls_close = scenario.get("tls") and (isinstance(error, ssl.SSLEOFError) or disconnected)
            if not tls_close:
                raise
            extra = b""
        require(not extra, "the client transmitted bytes after the reviewed probe")


def fixture_documents(directory):
    corpus = json.loads((ROOT / "crates/packetcraftr/data/service-probes.json").read_text())
    # Keep the shipped HTTP probe and its reviewed match rules.
    corpus["probes"] = [probe for probe in corpus["probes"] if probe["id"] == "http-head"]
    require(len(corpus["probes"]) == 1, "HTTP probe is missing from the shipped corpus")
    corpus["matches"] = [rule for rule in corpus["matches"] if rule["probe"] == "http-head"]
    corpus_path = directory / "corpus.json"
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")
    return corpus_path, corpus


def parse_output(stdout):
    require(stdout.endswith("\n"), "NDJSON must end with a newline")
    envelopes = [json.loads(line) for line in stdout.splitlines()]
    require(len(envelopes) == 2, "NDJSON requires one endpoint and one terminal record")
    require([item.get("sequence") for item in envelopes] == [0, 1], "NDJSON sequence is not contiguous")
    require([item.get("event") for item in envelopes] == ["identify_endpoint", "complete"], "NDJSON terminal event changed")
    summary = envelopes[-1]["result"]
    require(summary["endpoints"] == 1, "NDJSON endpoint summary disagrees")
    for envelope in envelopes:
        require(envelope.get("schema") == SCHEMA, "current machine schema changed")
        require(envelope.get("mode") == "stream", "NDJSON envelope mode changed")
        require(envelope.get("command") == "identify", "machine command changed")
        require(envelope.get("status") == "success", "identification did not publish success")
        require(isinstance(envelope.get("diagnostics"), list), "diagnostics must be explicit")
    return envelopes[0]["result"], summary


def verify_result(record, summary, fixture, scenario, corpus):
    require(record["outcome"] == "matched", "unexpected endpoint outcome: " + record["outcome"])
    expected_address = f"127.0.0.1:{fixture.address[1]}" if fixture.address[0] == "127.0.0.1" else f"[::1]:{fixture.address[1]}"
    require(record["endpoint"] == {"address": expected_address, "transport": "tcp"}, "numeric endpoint provenance changed")
    require(summary["corpus"] == corpus["name"] and summary["corpus_version"] == corpus["version"], "corpus provenance changed")
    require(summary["cancelled"] is False and summary["complete"] is True, "operation did not complete")
    probes = record["probes"]
    require(len(probes) == len(fixture.requests) == fixture.connections == 1, "attempt cap did not bound I/O")
    probe = probes[0]
    require(summary["usage"]["attempts"] == 1, "attempt accounting changed")
    require(summary["usage"]["read_bytes"] == len(HTTP), "read accounting changed")
    require(summary["usage"]["write_bytes"] == len(HTTP_REQUEST), "write accounting changed")
    require(probe["probe"] == "http-head" and probe["attempt"] == 1, "undeclared probe or retry occurred")
    require(bytes.fromhex(probe["request_hex"]) == fixture.requests[0] == HTTP_REQUEST, "retained request differs from transmitted bytes")
    require(probe["bytes_written"] == len(HTTP_REQUEST), "request accounting differs from transmission")
    require(bytes.fromhex(probe["response_hex"]) == fixture.replies[0] == HTTP, "retained response differs from wire bytes")
    if scenario.get("tls"):
        verify_tls(probe, summary, fixture)
    else:
        require(probe.get("tls") is None, "cleartext probe acquired TLS evidence")
    candidates = record["candidates"]
    require(any(candidate["product"] == "nginx" and candidate["version"] == "1.26.2" for candidate in candidates), "known product/version changed")
    claims = probe["observation"]["claims"]
    for claim in claims:
        require(claim["unauthenticated"] is True, "received claims became authenticated")
        require(bytes.fromhex(claim["value_hex"]) in HTTP, "observed field is absent from retained response")
    for candidate in candidates:
        require(candidate["confidence"] == "claim", "untrusted product claim gained confidence")
        provenance = candidate["provenance"]
        require(provenance["corpus"] == corpus["name"] and provenance["version"] == corpus["version"] and provenance["probe"] == "http-head", "candidate lost corpus/probe provenance")
        rule = next((rule for rule in corpus["matches"] if rule["id"] == provenance["rule"]), None)
        require(rule is not None and rule["product"] == candidate["product"], "candidate lost its match rule")
        verify_supported_metadata(candidate, rule)
        require(provenance["field_indices"], "candidate has no response-field evidence")
        for field_index in provenance["field_indices"]:
            require(0 <= field_index < len(claims), "candidate refers to an absent response field")
            claim = claims[field_index]
            require(claim["field"] == rule["field"] and bytes.fromhex(claim["value_hex"]).startswith(rule["prefix"].encode()), "candidate provenance does not reproduce its match")


def verify_supported_metadata(candidate, rule):
    require("device_type" not in candidate, "fixture without device evidence invented a device type")
    require("hostname" not in candidate, "HTTP fixture invented an unsupported hostname")
    if rule.get("cpe"):
        value = candidate.get("cpe")
        require(isinstance(value, dict) and value["value"] == rule["cpe"], "CPE differs from the reviewed match document")
        require(value["source"] == {"kind": "match_rule", "reference": rule["metadata"]["reference"]},
                "CPE lost the declared data reference")
        require(value["value"].split(":")[5] == "*", "product CPE acquired an unverified version")
    else:
        require("cpe" not in candidate, "unsupported CPE was invented")


def verify_tls(probe, summary, fixture):
    evidence = probe.get("tls")
    require(isinstance(evidence, dict), "TLS probe omitted its handshake observation")
    require(evidence["unauthenticated"] is True, "certificate observation was presented as authenticated")
    require(evidence["server_name"] == None, "TLS SNI provenance changed")
    require(evidence["handshake_complete"] is True, "TLS handshake completion changed")
    require(evidence["wire_bytes_sent"] > 0 and evidence["steps"] > 0, "TLS wire/handshake work was omitted")
    require(evidence["wire_bytes_read"] >= 0 and evidence["steps"] <= 64, "TLS work exceeded its limit")
    usage = summary["usage"]["tls"]
    require(usage["write_bytes"] == evidence["wire_bytes_sent"] and usage["read_bytes"] == evidence["wire_bytes_read"]
            and usage["steps"] == evidence["steps"], "TLS wire/step accounting changed")
    certificates = [bytes.fromhex(value) for value in evidence["certificates_hex"]]
    require(usage["certificate_bytes"] == sum(map(len, certificates)), "TLS certificate accounting changed")
    expected = ssl.PEM_cert_to_DER_cert((FIXTURES / "loopback-cert.pem").read_text())
    require(certificates == [expected] and evidence["certificates_truncated"] is False,
            "presented certificate differs from the original fixture")
    require(evidence["protocol_version"] in ("TLSv1_2", "TLSv1_3", "TLS1.2", "TLS1.3", "TLSv1.2", "TLSv1.3"),
            "TLS negotiated version was not retained")
    require(isinstance(evidence["cipher_suite"], str) and evidence["cipher_suite"], "TLS cipher observation was omitted")
    require(fixture.sni_names == [None], "numeric endpoint SNI policy changed")


def run_case(binary, family_name, scenario):
    result = {"scenario": scenario["name"],
              "family": family_name, "format": "ndjson", "status": "failed"}
    fixture = None
    started = time.monotonic()
    try:
        family = socket.AF_INET if family_name == "ipv4" else socket.AF_INET6
        fixture = Fixture(family, scenario)
        port = fixture.address[1]
        endpoint = f"127.0.0.1:{port}" if family_name == "ipv4" else f"[::1]:{port}"
        with tempfile.TemporaryDirectory(prefix="pcr-service-") as temporary:
            corpus_path, corpus = fixture_documents(Path(temporary))
            command = [str(binary), "--output", "ndjson", "identify", endpoint,
                       "--transport", "tcp", "--corpus", str(corpus_path),
                       "--intensity", "3", "--max-attempts", "1",
                       "--host-max-attempts", "1", "--connection-max-attempts", "1", "--probe-max-attempts", "1",
                       "--max-duration-ms", "5000", "--operation-timeout-ms", "3000",
                       "--host-timeout-ms", "3000", "--connection-timeout-ms", "2000", "--probe-timeout-ms", "1000"]
            if scenario.get("tls"):
                command.append("--tls")
            result["command"] = command
            completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=15, check=False)
            result["exit_code"] = completed.returncode
            result["stderr"] = completed.stderr
            require(completed.returncode == 0, "CLI failed: " + completed.stderr + completed.stdout)
            record, summary = parse_output(completed.stdout)
            # Preserve unexpected observed outcomes in the report;
            # assertions must not turn a mismatch into missing evidence.
            result.update(record=record, summary=summary)
            fixture.close()
            verify_result(record, summary, fixture, scenario, corpus)
            result.update({"status": "passed", "record": record, "summary": summary,
                           "fixture_requests_hex": [request.hex() for request in fixture.requests],
                           "fixture_replies_hex": [reply.hex() for reply in fixture.replies]})
    except Exception as error:
        result["error"] = str(error)
    finally:
        if fixture and fixture.thread.is_alive():
            try:
                fixture.close()
            except Exception as error:
                result["status"] = "failed"
                result["fixture_error"] = str(error)
        result["elapsed_seconds"] = round(time.monotonic() - started, 6)
    return result


def run_profile(name, build_timeout):
    command = ["cargo", "build", "--locked", "-p", "packetcraftr-cli", *PROFILES[name]]
    result = {"profile": name, "build_command": command, "status": "failed", "cases": []}
    try:
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=build_timeout, check=False)
        result["build_exit_code"] = completed.returncode
        result["build_stderr"] = completed.stderr
        require(completed.returncode == 0, "CLI feature-profile build failed")
        target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
        if not target.is_absolute():
            target = ROOT / target
        binary = target / "debug" / ("packetcraftr.exe" if os.name == "nt" else "packetcraftr")
        require(binary.is_file(), "built CLI binary is missing")
        for family in ("ipv4", "ipv6"):
            for scenario in scenarios():
                case = run_case(binary, family, scenario)
                result["cases"].append(case)
                print(f"{name}/{family}/{scenario['name']}/ndjson: {case['status']}", flush=True)
        result["status"] = "passed" if all(case["status"] == "passed" for case in result["cases"]) else "failed"
    except Exception as error:
        result["error"] = str(error)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=ROOT / "target/service-identification/report.json")
    parser.add_argument("--build-timeout", type=int, default=900)
    parser.add_argument("--require-clean", action="store_true", help="fail unless revision metadata covers a clean worktree")
    args = parser.parse_args()
    require(args.build_timeout > 0, "build timeout must be positive")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    report = {"schema": "packetcraftr.service-identification-acceptance/v3", "revision": revision,
              "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "worktree_dirty": dirty,
              "platform": platform.system(), "architecture": platform.machine(),
              "python": platform.python_version(), "tls_fixture_runtime": ssl.OPENSSL_VERSION,
              "shipped_corpus_sha256": hashlib.sha256((ROOT / "crates/packetcraftr/data/service-probes.json").read_bytes()).hexdigest(),
              "profiles": []}
    if args.require_clean and dirty:
        report["error"] = "acceptance requires a clean worktree at the recorded revision"
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return 1
    for name in PROFILES:
        report["profiles"].append(run_profile(name, args.build_timeout))
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    success = all(profile["status"] == "passed" for profile in report["profiles"])
    print(f"Evidence report: {args.report}")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
