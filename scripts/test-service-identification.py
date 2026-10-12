#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the shipped identification CLI on bounded IPv4/IPv6 loopback fixtures.

The resulting report records every attempted family, feature profile, scenario,
wire exchange, and machine-output mode. An unavailable family or failed build
is a failure, never a successful skip. Uses only the Python standard library;
the Rust contract suite owns full JSON-schema validation.
"""

import argparse
import copy
import datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "packetcraftr.output/v13"
FIXTURES = ROOT / "scripts/fixtures/service-identification"
HELD_OUT_PATH = ROOT / "docs/roadmap/evidence/m09/held-out.v1.json"
HELD_OUT_SHA256 = "399ae8d919fe3ca2ac32c62962eee37e54a811c5dee30b02f9226e45be94774c"
PROFILES = {
    "portable": ["--no-default-features"],
    "default": [],
    "layer2": ["--no-default-features", "--features", "native-layer2"],
    "layer3": ["--no-default-features", "--features", "native-layer3"],
    "all": ["--all-features"],
}
HTTP = b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.2\r\n\r\n"
SSH = b"SSH-2.0-OpenSSH_9.8p1 fixture\r\n"
HTTP_REQUEST = b"HEAD / HTTP/1.0\r\n\r\n"
PEER_DISCONNECT_ERRNOS = {errno.ENOTCONN, errno.ECONNRESET, errno.ECONNABORTED}
PEER_DISCONNECT_WINERRORS = {10057, 10054, 10053}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def scenarios():
    cases = [
        {"name": "known-ssh", "probe": "ssh-banner", "reply": SSH,
         "outcome": "matched", "product": "OpenSSH", "version": "9.8p1"},
        {"name": "known-http", "probe": "http-head", "reply": HTTP,
         "outcome": "matched", "product": "nginx", "version": "1.26.2"},
        {"name": "unknown", "probe": "ssh-banner", "reply": b"unrecognized service\r\n",
         "outcome": "unknown"},
        {"name": "unknown-product", "probe": "http-head",
         "reply": b"HTTP/1.1 200 OK\r\nServer: original-fixture/42\r\n\r\n",
         "outcome": "unknown"},
        {"name": "ambiguous-products", "probe": "http-head",
         "reply": b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.2\r\nServer: Apache/2.4.62\r\n\r\n",
         "outcome": "ambiguous"},
        {"name": "ambiguous-versions", "probe": "http-head",
         "reply": b"HTTP/1.1 200 OK\r\nServer: nginx/1.28.0\r\nServer: nginx/1.27.0\r\n\r\n",
         "outcome": "ambiguous", "product": "nginx"},
        {"name": "misleading-banner", "probe": "http-head",
         "reply": b"HTTP/1.1 200 OK\r\nServer: nginx/99.0\r\n\r\n",
         "outcome": "matched", "product": "nginx", "version": "99.0"},
        {"name": "malformed", "probe": "http-head",
         "reply": b"HTTP/1.1 200 OK\r\nServer: nginx/1.28.0\x00\r\n\r\n",
         "outcome": "malformed"},
        {"name": "truncated", "probe": "http-head",
         "reply": b"HTTP/1.1 200 OK\r\nServer: nginx/", "outcome": "truncated"},
        {"name": "byte-limit", "probe": "http-head", "reply": HTTP,
         "outcome": "truncated", "read_limit": 24},
        {"name": "excluded", "probe": "http-head", "reply": HTTP,
         "outcome": "excluded", "no_io": True, "exclude": True},
        {"name": "explicit-exclusion-override", "probe": "http-head", "reply": HTTP,
         "outcome": "matched", "product": "nginx", "version": "1.26.2",
         "override": True},
        {"name": "intensity", "probe": "http-head", "reply": HTTP,
         "outcome": "unknown", "no_io": True, "intensity": 1},
        {"name": "deadline", "probe": "http-head", "reply": b"",
         "outcome": "budget_exhausted", "hold": True},
    ]
    for transport in ("tcp", "udp"):
        cases += [
            {"name": f"known-dns-{transport}", "probe": f"dns-{transport}",
             "transport": transport, "dns": True, "outcome": "matched",
             "product": "DNS service", "version": None, "confidence": "protocol"},
            {"name": f"known-dns-version-{transport}", "probe": f"dns-version-{transport}",
             "transport": transport, "dns": True, "txt": b"BIND 9.20.0",
             "outcome": "matched", "product": "BIND", "version": "9.20.0"},
        ]
    cases += [
        {"name": "known-smtp-postfix", "probe": "smtp-greeting",
         "reply": b"220 mail.example.test ESMTP Postfix 3.10.1\r\n",
         "outcome": "matched", "product": "Postfix", "version": "3.10.1"},
        {"name": "known-tls-smtp-postfix", "probe": "smtp-greeting", "tls": True,
         "reply": b"220 mail.example.test ESMTP Postfix 3.10.1\r\n",
         "outcome": "matched", "product": "Postfix", "version": "3.10.1"},
        {"name": "known-smtp-exim", "probe": "smtp-greeting",
         "reply": b"220 relay.example.test ESMTP Exim 4.98\r\n",
         "outcome": "matched", "product": "Exim", "version": "4.98"},
        {"name": "known-ftp-vsftpd", "probe": "ftp-greeting",
         "reply": b"220 (vsFTPd 3.0.5)\r\n",
         "outcome": "matched", "product": "vsftpd", "version": "3.0.5"},
        {"name": "known-ftp-proftpd", "probe": "ftp-greeting",
         "reply": b"220 ProFTPD 1.3.8 Server ready\r\n",
         "outcome": "matched", "product": "ProFTPD", "version": "1.3.8"},
        {"name": "known-https", "probe": "http-head", "reply": HTTP,
         "tls": True, "outcome": "matched", "product": "nginx", "version": "1.26.2"},
        {"name": "https-declared-name", "probe": "http-head", "reply": HTTP,
         "tls": True, "server_name": "fixture.example.test",
         "outcome": "matched", "product": "nginx", "version": "1.26.2"},
        {"name": "tls-handshake-refused", "probe": "http-head", "reply": b"",
         "tls": True, "tls_failure": "refused", "outcome": "tls_failed"},
        {"name": "tls-handshake-deadline", "probe": "http-head", "reply": b"",
         "tls": True, "tls_failure": "timeout", "hold": True,
         "outcome": "budget_exhausted"},
        {"name": "tls-wire-read-limit", "probe": "http-head", "reply": b"",
         "tls": True, "tls_failure": "wire_limit", "tls_read_limit": 64,
         "outcome": "tls_failed"},
        {"name": "tls-certificate-retention-limit", "probe": "http-head", "reply": HTTP,
         "tls": True, "tls_certificate_limit": 16,
         "outcome": "matched", "product": "nginx", "version": "1.26.2"},
    ]
    for case in cases:
        case["split"] = "training_or_acceptance"
    return cases


def held_out_scenarios():
    """Read the immutable service-instance holdout without adapting its expectations."""
    content = HELD_OUT_PATH.read_bytes()
    require(hashlib.sha256(content).hexdigest() == HELD_OUT_SHA256,
            "held-out manifest changed after it was fixed before rule authorship")
    manifest = json.loads(content)
    require(manifest["schema"] == "packetcraftr.service-identification-held-out/v1",
            "held-out schema changed")
    cases = copy.deepcopy(manifest["scenarios"])
    for case in cases:
        case["reply"] = bytes.fromhex(case.pop("reply_hex"))
        if "txt_hex" in case:
            case["txt"] = bytes.fromhex(case.pop("txt_hex"))
    return cases


def dns_reply(request, txt=None):
    require(len(request) >= 17, "DNS query is shorter than its question")
    require(request[2:4] == b"\x00\x00", "DNS request must be nonrecursive QUERY")
    require(request[4:12] == b"\x00\x01\x00\x00\x00\x00\x00\x00", "DNS request counts changed")
    question = request[12:]
    expected = b"\x07version\x04bind\x00\x00\x10\x00\x03" if txt else b"\x00\x00\x01\x00\x01"
    require(question == expected, "DNS request is not the reviewed root/CH-TXT question")
    answer = b""
    if txt:
        rdata = bytes([len(txt)]) + txt
        answer = b"\xc0\x0c\x00\x10\x00\x03\x00\x00\x00\x00" + struct.pack("!H", len(rdata)) + rdata
    return request[:2] + b"\x80\x00\x00\x01" + struct.pack("!H", bool(txt)) + b"\x00\x00\x00\x00" + question + answer


def read_exact(peer, size):
    result = bytearray()
    while len(result) < size:
        part = peer.recv(size - len(result))
        if not part:
            raise ValueError("peer closed an incomplete DNS-over-TCP frame")
        result.extend(part)
    return bytes(result)


class Fixture:
    """A single original loopback service with an observable request count."""

    def __init__(self, family, scenario):
        self.scenario = scenario
        self.transport = scenario.get("transport", "tcp")
        self.stop = threading.Event()
        self.requests = []
        self.replies = []
        self.errors = []
        self.connections = 0
        self.sni_names = []
        self.handshake_failures = []
        self.tls_context = None
        if scenario.get("tls"):
            self.tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.tls_context.load_cert_chain(FIXTURES / "loopback-cert.pem", FIXTURES / "loopback-key.pem")
            self.tls_context.set_servername_callback(self.observe_sni)
        kind = socket.SOCK_DGRAM if self.transport == "udp" else socket.SOCK_STREAM
        self.listener = socket.socket(family, kind)
        try:
            if family == socket.AF_INET6:
                self.listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            self.listener.bind(("127.0.0.1" if family == socket.AF_INET else "::1", 0))
            self.listener.settimeout(0.05)
            if self.transport == "tcp":
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
                    if self.transport == "udp":
                        request, peer = self.listener.recvfrom(65535)
                        self.requests.append(request)
                        response = dns_reply(request, self.scenario.get("txt"))
                        self.replies.append(response)
                        self.listener.sendto(response, peer)
                    else:
                        peer, _ = self.listener.accept()
                        self.connections += 1
                        with peer:
                            peer.settimeout(2)
                            if self.scenario.get("tls_failure") == "refused":
                                peer.recv(4096)
                                peer.sendall(b"This fixture does not speak TLS\r\n")
                            elif self.scenario.get("tls_failure") == "timeout":
                                self.stop.wait(2)
                            elif self.tls_context:
                                try:
                                    with self.tls_context.wrap_socket(peer, server_side=True) as encrypted:
                                        self.serve_tcp(encrypted)
                                except (ssl.SSLError, ConnectionResetError) as error:
                                    if self.scenario.get("tls_failure") != "wire_limit":
                                        raise
                                    self.handshake_failures.append(str(error))
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
        if scenario.get("dns"):
            prefix = read_exact(peer, 2)
            payload = read_exact(peer, struct.unpack("!H", prefix)[0])
            request = prefix + payload
            response = dns_reply(payload, scenario.get("txt"))
            response = struct.pack("!H", len(response)) + response
        elif scenario["probe"] == "http-head":
            while b"\r\n\r\n" not in request:
                part = peer.recv(256)
                require(part, "HTTP client closed before its header")
                request += part
                require(len(request) <= 4096, "HTTP fixture request exceeded its bound")
            require(request == HTTP_REQUEST, "HTTP request differs from the reviewed HEAD bytes")
            response = scenario["reply"]
        else:
            response = scenario["reply"]
        self.requests.append(request)
        self.replies.append(response)
        if scenario.get("hold"):
            self.stop.wait(2)
            return
        # Split a DNS frame's length prefix so native stream framing is exercised.
        if scenario.get("dns"):
            peer.sendall(response[:1])
            peer.sendall(response[1:])
        else:
            peer.sendall(response)
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
            if not tls_close and (not scenario.get("read_limit") or not disconnected):
                raise
            extra = b""
        require(not extra, "the client transmitted bytes after the reviewed probe")


def fixture_documents(directory, scenario, port):
    corpus = json.loads((ROOT / "crates/packetcraftr/data/service-probes.json").read_text())
    # Restrict scheduling to the fixture's declared probe; matching rules and
    # corpus identity stay exactly those of the shipped reviewed document.
    corpus["probes"] = [probe for probe in corpus["probes"] if probe["id"] == scenario["probe"]]
    require(len(corpus["probes"]) == 1, "scenario probe is missing from the shipped corpus")
    corpus["matches"] = [rule for rule in corpus["matches"] if rule["probe"] == scenario["probe"]]
    corpus_path = directory / "corpus.json"
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")
    exclusions_path = None
    if scenario.get("exclude"):
        exclusions = json.loads((ROOT / "crates/packetcraftr/data/service-exclusions.json").read_text())
        exclusions["name"] = "service-acceptance-exclusions"
        exclusions["entries"] = [copy.deepcopy(exclusions["entries"][0])]
        exclusions["entries"][0]["transport"] = scenario.get("transport", "tcp")
        exclusions["entries"][0]["ports"] = [port]
        exclusions_path = directory / "exclusions.json"
        exclusions_path.write_text(json.dumps(exclusions), encoding="utf-8")
    return corpus_path, exclusions_path, corpus


def parse_output(stdout, output_format):
    if output_format == "json":
        envelopes = [json.loads(stdout)]
        require(envelopes[0].get("mode") == "aggregate", "JSON envelope mode changed")
        records = envelopes[0]["result"]["records"]
        summary = envelopes[0]["result"]
    else:
        envelopes = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        require(len(envelopes) == 2, "NDJSON requires one endpoint and one terminal record")
        require([item.get("sequence") for item in envelopes] == [0, 1], "NDJSON sequence is not contiguous")
        require([item.get("event") for item in envelopes] == ["identify_endpoint", "complete"], "NDJSON terminal event changed")
        require(all(item.get("mode") == "stream" for item in envelopes), "NDJSON envelope mode changed")
        records = [envelopes[0]["result"]]
        summary = envelopes[-1]["result"]
        require(summary["endpoints"] == 1, "NDJSON endpoint summary disagrees")
    require(len(records) == 1, "scenario must produce exactly one endpoint record")
    for envelope in envelopes:
        require(envelope.get("schema") == SCHEMA, "machine schema family changed")
        require(envelope.get("command") == "identify", "machine command changed")
        require(envelope.get("status") == "success", "identification did not publish a successful terminal record")
        require(isinstance(envelope.get("diagnostics"), list), "diagnostics must be explicit")
    return records[0], summary


def verify_result(record, summary, fixture, scenario, corpus):
    require(record["outcome"] == scenario["outcome"], "unexpected endpoint outcome: " + record["outcome"])
    expected_address = f"127.0.0.1:{fixture.address[1]}" if fixture.address[0] == "127.0.0.1" else f"[::1]:{fixture.address[1]}"
    require(record["endpoint"] == {"address": expected_address, "transport": fixture.transport}, "numeric endpoint provenance changed")
    require(summary["corpus"] == corpus["name"] and summary["corpus_version"] == corpus["version"], "corpus provenance changed")
    require(summary["cancelled"] is False, "ordinary fixture was cancelled")
    require(summary["complete"] is not scenario.get("hold", False), "operation completion disagrees with its deadline")
    probes = record["probes"]
    require(summary["usage"]["attempts"] == len(probes), "attempt evidence does not match accounting")
    require(summary["usage"]["read_bytes"] == sum(len(bytes.fromhex(probe["response_hex"])) for probe in probes), "read accounting changed")
    require(summary["usage"]["write_bytes"] == sum(probe["bytes_written"] for probe in probes), "write accounting changed")
    expected_attempts = 0 if scenario.get("no_io") else 1
    expected_exchanges = 0 if scenario.get("tls_failure") else expected_attempts
    require(len(probes) == expected_attempts and len(fixture.requests) == expected_exchanges, "intensity/exclusions/attempt cap did not bound I/O")
    require(fixture.connections == (expected_attempts if fixture.transport == "tcp" else 0), "unexpected extra connection")
    candidates = record["candidates"]
    if scenario["outcome"] in ("unknown", "malformed", "truncated", "excluded", "budget_exhausted", "tls_failed"):
        require(candidates == [], "nonmatching result invented a candidate")
    elif scenario["outcome"] == "ambiguous":
        require(len(candidates) >= 2 and all(candidate["version"] is None for candidate in candidates), "ambiguous result published an exact version")
        if scenario.get("product"):
            require(all(candidate["product"] == scenario["product"] for candidate in candidates), "version ambiguity changed the product")
        if scenario.get("products"):
            require({candidate["product"] for candidate in candidates} == set(scenario["products"]),
                    "held-out product ambiguity changed the declared claims")
        if scenario["name"] == "ambiguous-products":
            require({candidate["product"] for candidate in candidates} == {"nginx", "Apache HTTP Server"}, "declared product ambiguity was not exercised")
            require({tuple(candidate["provenance"]["field_indices"]) for candidate in candidates} == {(1,), (2,)}, "product ambiguity must cite separate Server fields")
    else:
        require(any(candidate["product"] == scenario["product"] and candidate["version"] == scenario["version"] for candidate in candidates), "known fixture product/version changed")
    for candidate in candidates:
        require(candidate["confidence"] == scenario.get("confidence", "claim"), "untrusted product claim gained confidence")
        provenance = candidate["provenance"]
        require(provenance["corpus"] == corpus["name"] and provenance["version"] == corpus["version"] and provenance["probe"] == scenario["probe"], "candidate lost corpus/probe provenance")
        require(provenance["field_indices"], "candidate has no response-field evidence")
        rule = next((rule for rule in corpus["matches"] if rule["id"] == provenance["rule"]), None)
        require(rule is not None and rule["product"] == candidate["product"], "candidate lost its declared match rule")
        claims = probes[0]["observation"]["claims"]
        verify_supported_metadata(candidate, rule, claims)
        for field_index in provenance["field_indices"]:
            require(0 <= field_index < len(claims), "candidate refers to an absent response field")
            claim = claims[field_index]
            require(claim["field"] == rule["field"] and bytes.fromhex(claim["value_hex"]).startswith(rule["prefix"].encode()), "candidate provenance does not reproduce its anchored match")
    for index, probe in enumerate(probes):
        require(probe["probe"] == scenario["probe"] and probe["attempt"] == 1, "undeclared probe or retry occurred")
        request = bytes.fromhex(probe["request_hex"])
        response = bytes.fromhex(probe["response_hex"])
        if scenario.get("tls"):
            verify_tls(probe, summary, fixture, scenario)
            if scenario.get("tls_failure"):
                require(response == b"" and probe["bytes_written"] == 0,
                        "failed TLS handshake performed application I/O")
                require(request == HTTP_REQUEST, "failed TLS handshake lost its intended request evidence")
                require(probe["io_outcome"] == ("timed_out" if scenario.get("hold") else
                        "truncated" if scenario.get("tls_read_limit") else "failed"),
                        "TLS failure did not preserve its I/O outcome")
                continue
        else:
            require(probe.get("tls") is None, "cleartext probe acquired TLS evidence")
        require(request == fixture.requests[index], "retained request bytes differ from transmitted bytes")
        require(probe["bytes_written"] == len(request), "request accounting differs from transmission")
        require(response == fixture.replies[index][:len(response)], "retained response bytes differ from received wire prefix")
        if not scenario.get("read_limit"):
            require(response == fixture.replies[index], "complete response bytes were discarded")
        else:
            require(len(response) == scenario["read_limit"], "probe read limit was not exact")
        observation = probe["observation"]
        require(all(claim["unauthenticated"] is True for claim in observation["claims"]), "received claims became authenticated")
        for claim in observation["claims"]:
            if claim["field"] == "dns_rcode":
                payload = response[2:] if fixture.transport == "tcp" else response
                require(bytes.fromhex(claim["value_hex"]) == str(payload[3] & 15).encode(), "DNS code claim differs from the received header")
            else:
                require(bytes.fromhex(claim["value_hex"]) in response, "observed field is absent from retained response bytes")
        if scenario.get("hold"):
            require(probe["io_outcome"] == "timed_out", "operation deadline did not stop provider I/O")
        if scenario.get("override"):
            require(summary["exclusion_set"] == "operator-no-exclusions", "explicit exclusion override lost provenance")


def verify_supported_metadata(candidate, rule, claims):
    require("device_type" not in candidate, "fixture without device evidence invented a device type")
    if rule.get("hostname_field"):
        value = candidate.get("hostname")
        require(isinstance(value, dict), "supported SMTP hostname was omitted")
        source = value["source"]
        require(source["kind"] == "observed_field" and source["field"] == rule["hostname_field"],
                "hostname source lost the observed field")
        require(0 <= source["index"] < len(claims), "hostname source refers to an absent field")
        observed = claims[source["index"]]
        require(observed["field"] == source["field"] and observed["unauthenticated"] is True
                and value["value"].encode() == bytes.fromhex(observed["value_hex"]),
                "hostname differs from its unauthenticated observation")
    else:
        require("hostname" not in candidate, "unsupported hostname was invented")
    if rule.get("cpe"):
        value = candidate.get("cpe")
        require(isinstance(value, dict) and value["value"] == rule["cpe"], "CPE differs from the reviewed match document")
        require(value["source"] == {"kind": "match_rule", "reference": rule["metadata"]["reference"]},
                "CPE lost the declared data reference")
        require(value["value"].split(":")[5] == "*", "product CPE acquired an unverified version")
    else:
        require("cpe" not in candidate, "unsupported CPE was invented")


def verify_tls(probe, summary, fixture, scenario):
    evidence = probe.get("tls")
    require(isinstance(evidence, dict), "TLS probe omitted its handshake observation")
    require(evidence["unauthenticated"] is True, "certificate observation was presented as authenticated")
    require(evidence["server_name"] == scenario.get("server_name"), "TLS SNI provenance changed")
    complete = not scenario.get("tls_failure")
    require(evidence["handshake_complete"] is complete, "TLS handshake completion changed")
    require(evidence["wire_bytes_sent"] > 0 and evidence["steps"] > 0, "TLS wire/handshake work was omitted")
    require(evidence["wire_bytes_read"] >= 0 and evidence["steps"] <= 64, "TLS work exceeded its limit")
    usage = summary["usage"]["tls"]
    require(usage["write_bytes"] == evidence["wire_bytes_sent"] and usage["read_bytes"] == evidence["wire_bytes_read"]
            and usage["steps"] == evidence["steps"], "TLS wire/step accounting changed")
    certificates = [bytes.fromhex(value) for value in evidence["certificates_hex"]]
    require(usage["certificate_bytes"] == sum(map(len, certificates)), "TLS certificate accounting changed")
    if complete:
        expected = ssl.PEM_cert_to_DER_cert((FIXTURES / "loopback-cert.pem").read_text())
        if scenario.get("tls_certificate_limit"):
            require(certificates == [] and evidence["certificates_truncated"] is True,
                    "certificate retention cap did not omit the oversized whole certificate")
            require(usage["certificate_bytes"] <= scenario["tls_certificate_limit"],
                    "certificate retention accounting exceeded its limit")
        else:
            require(certificates == [expected] and evidence["certificates_truncated"] is False,
                    "presented certificate observation differs from the original fixture")
        require(evidence["protocol_version"] in ("TLSv1_2", "TLSv1_3", "TLS1.2", "TLS1.3", "TLSv1.2", "TLSv1.3"),
                "TLS negotiated version was not retained")
        require(isinstance(evidence["cipher_suite"], str) and evidence["cipher_suite"], "TLS cipher observation was omitted")
        require(fixture.sni_names == [scenario.get("server_name")], "numeric/declared-name SNI policy changed")
    if scenario.get("tls_read_limit"):
        require(evidence["wire_bytes_read"] <= scenario["tls_read_limit"], "TLS encrypted read budget was exceeded")


def run_case(binary, family_name, scenario, output_format):
    result = {"scenario": scenario["name"], "split": scenario.get("split", "training_or_acceptance"),
              "family": family_name, "format": output_format, "status": "failed"}
    fixture = None
    started = time.monotonic()
    try:
        family = socket.AF_INET if family_name == "ipv4" else socket.AF_INET6
        fixture = Fixture(family, scenario)
        port = fixture.address[1]
        endpoint = f"127.0.0.1:{port}" if family_name == "ipv4" else f"[::1]:{port}"
        with tempfile.TemporaryDirectory(prefix="pcr-service-") as temporary:
            corpus_path, exclusions_path, corpus = fixture_documents(Path(temporary), scenario, port)
            command = [str(binary), "--output", output_format, "identify", endpoint,
                       "--transport", scenario.get("transport", "tcp"), "--corpus", str(corpus_path),
                       "--intensity", str(scenario.get("intensity", 3)), "--max-attempts", "1",
                       "--host-max-attempts", "1", "--connection-max-attempts", "1", "--probe-max-attempts", "1",
                       "--max-duration-ms", "5000", "--operation-timeout-ms", "100" if scenario.get("hold") else "3000",
                       "--host-timeout-ms", "3000", "--connection-timeout-ms", "2000", "--probe-timeout-ms", "1000"]
            if exclusions_path:
                command += ["--exclusions", str(exclusions_path)]
            if scenario.get("override"):
                command.append("--ignore-exclusions")
            if scenario.get("read_limit"):
                for scope in ("host", "connection", "probe"):
                    command += [f"--{scope}-max-read-bytes", str(scenario["read_limit"])]
                command += ["--max-read-bytes", str(scenario["read_limit"])]
            if scenario.get("tls"):
                command.append("--tls")
            if scenario.get("server_name"):
                command += ["--server-name", scenario["server_name"]]
            if scenario.get("tls_read_limit"):
                command += ["--tls-max-wire-read-bytes", str(scenario["tls_read_limit"])]
            if scenario.get("tls_certificate_limit"):
                command += ["--tls-max-certificate-bytes", str(scenario["tls_certificate_limit"])]
            result["command"] = command
            completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=15, check=False)
            result["exit_code"] = completed.returncode
            result["stderr"] = completed.stderr
            require(completed.returncode == 0, "CLI failed: " + completed.stderr + completed.stdout)
            record, summary = parse_output(completed.stdout, output_format)
            # Preserve unexpected observed outcomes in the held-out report;
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
            for scenario in scenarios() + held_out_scenarios():
                for output_format in ("json", "ndjson"):
                    case = run_case(binary, family, scenario, output_format)
                    result["cases"].append(case)
                    print(f"{name}/{family}/{scenario['name']}/{output_format}: {case['status']}", flush=True)
        result["status"] = "passed" if all(case["status"] == "passed" for case in result["cases"]) else "failed"
        result["held_out_evaluation"] = evaluate_held_out(result["cases"])
    except Exception as error:
        result["error"] = str(error)
    return result


def evaluate_held_out(cases):
    """Report observed coverage and uncertainty, separating confidence categories."""
    inventory = {case["name"]: case for case in held_out_scenarios()}
    selected = [case for case in cases if case.get("split") == "held_out"]
    eligible = [case for case in selected if inventory[case["scenario"]].get("quality_eligible", True)]
    counts = {name: 0 for name in ("matched", "unknown", "ambiguous", "malformed", "truncated",
                                  "tls_failed", "budget_exhausted", "missing_record")}
    confidence = {"claim": 0, "protocol": 0}
    faithfully_extracted = {"claim": 0, "protocol": 0}
    misleading_claims = 0
    for case in selected:
        record = case.get("record")
        if record is None:
            counts["missing_record"] += 1
            continue
        counts[record["outcome"]] = counts.get(record["outcome"], 0) + 1
        expected = inventory[case["scenario"]]
        for candidate in record["candidates"]:
            category = candidate["confidence"]
            confidence[category] = confidence.get(category, 0) + 1
            if record["outcome"] == "matched" and candidate["product"] == expected.get("product") and candidate["version"] == expected.get("version"):
                faithfully_extracted[category] = faithfully_extracted.get(category, 0) + 1
            if expected.get("misleading"):
                misleading_claims += 1
    matched = sum(case.get("record", {}).get("outcome") == "matched" for case in eligible)
    unknown = sum(case.get("record", {}).get("outcome") == "unknown" for case in eligible)
    ambiguous = sum(case.get("record", {}).get("outcome") == "ambiguous" for case in eligible)
    denominator = len(eligible)
    return {"manifest_version": "1.0.0", "manifest_sha256": HELD_OUT_SHA256,
            "corpus": next((case["summary"]["corpus"] for case in selected if "corpus" in case.get("summary", {})), None),
            "corpus_version": next((case["summary"]["corpus_version"] for case in selected if "corpus_version" in case.get("summary", {})), None),
            "declared_service_instances": len(inventory), "attempted_case_runs": len(selected),
            "eligible_case_runs": denominator, "matched_case_runs": matched,
            "coverage": matched / denominator if denominator else None,
            "unknown_case_runs": unknown, "unknown_share": unknown / denominator if denominator else None,
            "ambiguous_case_runs": ambiguous, "ambiguous_share": ambiguous / denominator if denominator else None,
            "outcomes": counts, "candidate_confidence_counts": confidence,
            "faithful_unambiguous_presented_token_counts": faithfully_extracted,
            "misleading_claim_candidates": misleading_claims,
            "identity_accuracy": None,
            "limits": "Repeated IPv4/IPv6 and JSON/NDJSON case-runs are not additional independent service instances. Claim fidelity measures presented tokens, not actual software identity. Handshake/malformed cases are reported outside eligible service coverage. No production prevalence or confidence calibration is inferred."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", action="append", choices=PROFILES, help="repeatable; defaults to all five feature profiles")
    parser.add_argument("--report", type=Path, default=ROOT / "target/service-identification/report.json")
    parser.add_argument("--build-timeout", type=int, default=900)
    parser.add_argument("--require-clean", action="store_true", help="fail unless revision metadata covers a clean worktree")
    args = parser.parse_args()
    require(args.build_timeout > 0, "build timeout must be positive")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    report = {"schema": "packetcraftr.service-identification-acceptance/v2", "revision": revision,
              "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "worktree_dirty": dirty,
              "platform": platform.system(), "architecture": platform.machine(),
              "python": platform.python_version(), "tls_fixture_runtime": ssl.OPENSSL_VERSION,
              "shipped_corpus_sha256": hashlib.sha256((ROOT / "crates/packetcraftr/data/service-probes.json").read_bytes()).hexdigest(),
              "held_out_manifest": {"path": str(HELD_OUT_PATH.relative_to(ROOT)), "sha256": HELD_OUT_SHA256,
                                    "fixed_before_rule_commit": "97267ae4"}, "profiles": []}
    if args.require_clean and dirty:
        report["error"] = "acceptance requires a clean worktree at the recorded revision"
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return 1
    for name in args.profile or PROFILES:
        report["profiles"].append(run_profile(name, args.build_timeout))
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    success = all(profile["status"] == "passed" for profile in report["profiles"])
    print(f"Evidence report: {args.report}")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
