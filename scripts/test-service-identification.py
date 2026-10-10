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
import json
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "packetcraftr.output/v11"
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
            peer.shutdown(socket.SHUT_WR)
            extra = peer.recv(256)
        except OSError as error:
            # Closing a bounded reader with unread reply bytes may reset TCP.
            disconnected = (
                error.errno in PEER_DISCONNECT_ERRNOS
                or error.errno in PEER_DISCONNECT_WINERRORS
                or getattr(error, "winerror", None) in PEER_DISCONNECT_WINERRORS
            )
            if not scenario.get("read_limit") or not disconnected:
                raise
            extra = b""
        require(not extra, "the client transmitted bytes after the reviewed probe")


def fixture_documents(directory, scenario, port):
    corpus = json.loads((ROOT / "crates/packetcraftr/data/service-probes.json").read_text())
    corpus["name"] = "service-acceptance-" + scenario["name"]
    corpus["version"] = "1.0.0"
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
    require(len(probes) == expected_attempts and len(fixture.requests) == expected_attempts, "intensity/exclusions/attempt cap did not bound I/O")
    require(fixture.connections == (expected_attempts if fixture.transport == "tcp" else 0), "unexpected extra connection")
    candidates = record["candidates"]
    if scenario["outcome"] in ("unknown", "malformed", "truncated", "excluded", "budget_exhausted"):
        require(candidates == [], "nonmatching result invented a candidate")
    elif scenario["outcome"] == "ambiguous":
        require(len(candidates) >= 2 and all(candidate["version"] is None for candidate in candidates), "ambiguous result published an exact version")
        if scenario.get("product"):
            require(all(candidate["product"] == scenario["product"] for candidate in candidates), "version ambiguity changed the product")
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
        for field_index in provenance["field_indices"]:
            require(0 <= field_index < len(claims), "candidate refers to an absent response field")
            claim = claims[field_index]
            require(claim["field"] == rule["field"] and bytes.fromhex(claim["value_hex"]).startswith(rule["prefix"].encode()), "candidate provenance does not reproduce its anchored match")
    for index, probe in enumerate(probes):
        require(probe["probe"] == scenario["probe"] and probe["attempt"] == 1, "undeclared probe or retry occurred")
        request = bytes.fromhex(probe["request_hex"])
        response = bytes.fromhex(probe["response_hex"])
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


def run_case(binary, family_name, scenario, output_format):
    result = {"scenario": scenario["name"], "family": family_name, "format": output_format, "status": "failed"}
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
            result["command"] = command
            completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=15, check=False)
            result["exit_code"] = completed.returncode
            result["stderr"] = completed.stderr
            require(completed.returncode == 0, "CLI failed: " + completed.stderr + completed.stdout)
            record, summary = parse_output(completed.stdout, output_format)
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
                for output_format in ("json", "ndjson"):
                    case = run_case(binary, family, scenario, output_format)
                    result["cases"].append(case)
                    print(f"{name}/{family}/{scenario['name']}/{output_format}: {case['status']}", flush=True)
        result["status"] = "passed" if all(case["status"] == "passed" for case in result["cases"]) else "failed"
    except Exception as error:
        result["error"] = str(error)
    return result


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
    report = {"schema": "packetcraftr.service-identification-acceptance/v1", "revision": revision,
              "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "worktree_dirty": dirty,
              "platform": platform.system(), "architecture": platform.machine(),
              "python": platform.python_version(), "profiles": []}
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
