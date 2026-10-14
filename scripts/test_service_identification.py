#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Failure-path contracts for the service identification acceptance runner."""

import importlib.util
import errno
import json
from pathlib import Path
import subprocess
import ssl
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name("test-service-identification.py")
SPEC = importlib.util.spec_from_file_location("service_identification_acceptance", MODULE_PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class FakePeer:
    """Preserve the reviewed exchange while controlling shutdown/drain faults."""

    def __init__(self, phase=None, error=None, extra=b""):
        self.phase = phase
        self.error = error
        self.extra = extra
        self.reads = 0
        self.sent = []
        self.shutdown_modes = []

    def recv(self, _size):
        self.reads += 1
        if self.reads == 1:
            return RUNNER.HTTP_REQUEST
        if self.phase == "drain":
            raise self.error
        return self.extra

    def sendall(self, data):
        self.sent.append(data)

    def shutdown(self, mode):
        self.shutdown_modes.append(mode)
        if self.phase == "shutdown":
            raise self.error


class AcceptanceContracts(unittest.TestCase):
    def test_failed_tls_handshake_retains_intended_request_without_transmitting_it(self):
        scenario = next(case for case in RUNNER.scenarios() if case["name"] == "tls-handshake-refused")
        fixture = SimpleNamespace(address=("127.0.0.1", 12345), transport="tcp", requests=[], connections=1)
        probe = {"probe": "http-head", "attempt": 1, "request_hex": RUNNER.HTTP_REQUEST.hex(),
                 "response_hex": "", "bytes_written": 0, "io_outcome": "failed"}
        record = {"endpoint": {"address": "127.0.0.1:12345", "transport": "tcp"},
                  "outcome": "tls_failed", "probes": [probe], "candidates": []}
        summary = {"corpus": "fixture", "corpus_version": "1", "cancelled": False, "complete": True,
                   "usage": {"attempts": 1, "read_bytes": 0, "write_bytes": 0}}
        with patch.object(RUNNER, "verify_tls"):
            RUNNER.verify_result(record, summary, fixture, scenario, {"name": "fixture", "version": "1"})
            probe["bytes_written"] = summary["usage"]["write_bytes"] = 1
            with self.assertRaisesRegex(ValueError, "application I/O"):
                RUNNER.verify_result(record, summary, fixture, scenario, {"name": "fixture", "version": "1"})

    def test_unexpected_observed_outcome_is_preserved_in_report(self):
        fixture = SimpleNamespace(address=("127.0.0.1", 12345), close=lambda: None,
                                  thread=SimpleNamespace(is_alive=lambda: False))
        record = {"outcome": "unknown", "candidates": []}
        completed = subprocess.CompletedProcess(["fixture"], 0, "fixture output", "")
        scenario = RUNNER.scenarios()[0]
        with patch.object(RUNNER, "Fixture", return_value=fixture), \
                patch.object(RUNNER, "fixture_documents", return_value=(Path("corpus"), None, {})), \
                patch.object(RUNNER.subprocess, "run", return_value=completed), \
                patch.object(RUNNER, "parse_output", return_value=(record, {})), \
                patch.object(RUNNER, "verify_result", side_effect=ValueError("unexpected endpoint outcome")):
            result = RUNNER.run_case(Path("fixture-binary"), "ipv4", scenario, "json")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["record"], record)

    def test_tls_fixture_records_original_certificate_numeric_and_declared_sni(self):
        for server_name in (None, "fixture.example.test"):
            with self.subTest(server_name=server_name):
                fixture = RUNNER.Fixture(RUNNER.socket.AF_INET, {
                    "probe": "http-head", "reply": RUNNER.HTTP, "tls": True})
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with RUNNER.socket.create_connection(fixture.address, timeout=2) as raw:
                        with context.wrap_socket(raw, server_hostname=server_name) as peer:
                            expected = ssl.PEM_cert_to_DER_cert((RUNNER.FIXTURES / "loopback-cert.pem").read_text())
                            self.assertEqual(peer.getpeercert(binary_form=True), expected)
                            peer.sendall(RUNNER.HTTP_REQUEST)
                            self.assertEqual(RUNNER.read_exact(peer, len(RUNNER.HTTP)), RUNNER.HTTP)
                            peer.unwrap()
                finally:
                    fixture.close()
                self.assertEqual(fixture.sni_names, [server_name])
                self.assertEqual(fixture.connections, 1)
                self.assertEqual(fixture.requests, [RUNNER.HTTP_REQUEST])

    def test_supported_metadata_requires_original_observation_and_rule_source(self):
        claims = [{"field": "smtp_hostname", "value_hex": b"mx.example.test".hex(), "unauthenticated": True}]
        rule = {"hostname_field": "smtp_hostname", "cpe": "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*",
                "metadata": {"reference": "https://nvd.nist.gov/products/cpe"}}
        candidate = {"hostname": {"value": "mx.example.test", "source": {
            "kind": "observed_field", "field": "smtp_hostname", "index": 0}},
            "cpe": {"value": rule["cpe"], "source": {"kind": "match_rule", "reference": rule["metadata"]["reference"]}}}
        RUNNER.verify_supported_metadata(candidate, rule, claims)
        candidate["hostname"]["value"] = "invented.example.test"
        with self.assertRaisesRegex(ValueError, "hostname differs"):
            RUNNER.verify_supported_metadata(candidate, rule, claims)
        with self.assertRaisesRegex(ValueError, "unsupported hostname"):
            RUNNER.verify_supported_metadata({"hostname": candidate["hostname"]}, {}, claims)
        with self.assertRaisesRegex(ValueError, "device type"):
            RUNNER.verify_supported_metadata({"device_type": {"value": "router"}}, {}, claims)

    def test_inventory_conditions_have_matching_runtime_expectations_and_wire_claims(self):
        inventory = {case["id"]: case for case in json.loads(
            (RUNNER.ROOT / "docs/scanner-corpus.v1.json").read_text()
        )["identification_scenarios"]}
        scenarios = {case["name"]: case for case in RUNNER.scenarios()}
        names = {"unknown": "unknown-product", "known-dns": "known-dns-udp"}
        for key, declared in inventory.items():
            name = names.get(key.removeprefix("identification-"), key.removeprefix("identification-"))
            scenario = scenarios[name]
            expected = declared["expected"]
            with self.subTest(inventory=key):
                self.assertEqual(scenario["outcome"], expected["outcome"])
                if expected["outcome"] == "matched":
                    self.assertEqual(scenario["product"], expected["product"])
                    self.assertEqual(scenario["version"], expected["version"])
                    self.assertEqual(scenario.get("confidence", "claim"), expected["confidence"])
                if name in ("known-ssh", "known-http", "misleading-banner"):
                    self.assertIn(expected["version"].encode(), scenario["reply"])
        scenario = scenarios["ambiguous-products"]
        fields = [line.removeprefix(b"Server: ") for line in scenario["reply"].split(b"\r\n") if line.startswith(b"Server: ")]
        self.assertEqual(fields, [b"nginx/1.26.2", b"Apache/2.4.62"])
        self.assertTrue(all(field.decode() in inventory["identification-ambiguous-products"]["condition"] for field in fields))
        with tempfile.TemporaryDirectory() as temporary:
            _, _, corpus = RUNNER.fixture_documents(Path(temporary), scenario, 32123)
        rules = {rule["product"]: rule for rule in corpus["matches"]}
        self.assertTrue(fields[0].startswith(rules["nginx"]["prefix"].encode()))
        self.assertTrue(fields[1].startswith(rules["Apache HTTP Server"]["prefix"].encode()))

    def envelope(self, mode="aggregate", event=None, sequence=None):
        result = {"records": [{"outcome": "unknown"}]} if mode == "aggregate" else {"outcome": "unknown"}
        envelope = {"schema": RUNNER.SCHEMA, "mode": mode, "command": "identify",
                    "status": "success", "diagnostics": [], "result": result}
        if event is not None:
            envelope.update(event=event, sequence=sequence)
        return envelope

    def test_machine_family_and_terminal_sequence_are_checked(self):
        aggregate = self.envelope()
        RUNNER.parse_output(json.dumps(aggregate), "json")
        aggregate["schema"] = "packetcraftr.output/v10"
        with self.assertRaisesRegex(ValueError, "schema family"):
            RUNNER.parse_output(json.dumps(aggregate), "json")
        endpoint = self.envelope("stream", "identify_endpoint", 0)
        terminal = self.envelope("stream", "complete", 1)
        terminal["result"] = {"endpoints": 1}
        stdout = "\n".join(map(json.dumps, [endpoint, terminal]))
        RUNNER.parse_output(stdout, "ndjson")
        for invalid in ([endpoint], [terminal, endpoint], [endpoint, terminal, terminal]):
            with self.subTest(events=invalid), self.assertRaises(ValueError):
                RUNNER.parse_output("\n".join(map(json.dumps, invalid)), "ndjson")

    def test_successful_envelope_still_requires_explicit_diagnostics(self):
        envelope = self.envelope()
        del envelope["diagnostics"]
        with self.assertRaisesRegex(ValueError, "diagnostics"):
            RUNNER.parse_output(json.dumps(envelope), "json")

    def test_dns_fixture_echoes_transaction_and_rejects_unreviewed_queries(self):
        root = b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01"
        reply = RUNNER.dns_reply(root)
        self.assertEqual(reply[:2], b"\x12\x34")
        self.assertEqual(reply[12:], root[12:])
        version = root[:12] + b"\x07version\x04bind\x00\x00\x10\x00\x03"
        reply = RUNNER.dns_reply(version, b"BIND 9.20.0")
        self.assertIn(b"BIND 9.20.0", reply)
        for request in (root[:2] + b"\x01\x00" + root[4:], root[:-2] + b"\x00\x03", root[:8]):
            with self.subTest(request=request), self.assertRaises(ValueError):
                RUNNER.dns_reply(request)

    def test_ambiguous_candidate_cannot_retain_an_exact_version(self):
        fixture = SimpleNamespace(requests=[], replies=[], connections=0, transport="tcp", address=("127.0.0.1", 12345))
        scenario = {"name": "ambiguous", "probe": "http-head", "outcome": "ambiguous", "no_io": True}
        corpus = {"name": "test", "version": "1"}
        summary = {"corpus": "test", "corpus_version": "1", "cancelled": False,
                   "complete": True, "usage": {"attempts": 0, "read_bytes": 0, "write_bytes": 0}}
        record = {"outcome": "ambiguous", "endpoint": {"address": "127.0.0.1:12345", "transport": "tcp"}, "probes": [], "candidates": [
            {"product": "A", "version": "1"}, {"product": "B", "version": None}]}
        with self.assertRaisesRegex(ValueError, "exact version"):
            RUNNER.verify_result(record, summary, fixture, scenario, corpus)

    def test_unavailable_address_family_is_failure(self):
        with patch.object(RUNNER.socket, "socket", side_effect=OSError("IPv6 unavailable")):
            case = RUNNER.run_case(Path("missing-binary"), "ipv6", RUNNER.scenarios()[0], "json")
        self.assertEqual(case["status"], "failed")
        self.assertIn("IPv6 unavailable", case["error"])

    def test_feature_profile_build_failure_is_not_a_successful_skip(self):
        failed = subprocess.CompletedProcess(["cargo"], 1, "", "fixture build failure")
        with patch.object(RUNNER.subprocess, "run", return_value=failed):
            report = RUNNER.run_profile("portable", 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["build_exit_code"], 1)
        self.assertEqual(report["cases"], [])
        self.assertIn("--no-default-features", report["build_command"])

    def test_clean_revision_gate_records_failure_before_any_build(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "evidence.json"
            command = [str(MODULE_PATH), "--require-clean", "--report", str(report_path)]
            with patch.object(sys, "argv", command), \
                    patch.object(RUNNER.subprocess, "check_output", side_effect=["revision\n", " M tracked\n"]), \
                    patch.object(RUNNER, "run_profile") as build:
                self.assertEqual(RUNNER.main(), 1)
            report = json.loads(report_path.read_text())
            self.assertTrue(report["worktree_dirty"])
            self.assertEqual(report["profiles"], [])
            self.assertIn("clean worktree", report["error"])
            build.assert_not_called()

    def exchange(self, peer, capped=True):
        fixture = object.__new__(RUNNER.Fixture)
        fixture.scenario = {"probe": "http-head", "reply": RUNNER.HTTP}
        if capped:
            fixture.scenario["read_limit"] = 24
        fixture.requests = []
        fixture.replies = []
        try:
            fixture.serve_tcp(peer)
        finally:
            self.assertEqual(fixture.requests, [RUNNER.HTTP_REQUEST])
            self.assertEqual(fixture.replies, [RUNNER.HTTP])
            self.assertEqual(peer.sent, [RUNNER.HTTP])
            self.assertEqual(peer.shutdown_modes, [RUNNER.socket.SHUT_WR])

    def test_bounded_reader_accepts_only_expected_shutdown_and_drain_disconnects(self):
        for phase in ("shutdown", "drain"):
            for number in (errno.ENOTCONN, errno.ECONNRESET, errno.ECONNABORTED, 10057, 10054, 10053):
                with self.subTest(phase=phase, errno=number):
                    self.exchange(FakePeer(phase, OSError(number, "fixture disconnect")))
            error = OSError(errno.EIO, "fixture Win32 disconnect")
            error.winerror = 10057
            with self.subTest(phase=phase, winerror=10057):
                self.exchange(FakePeer(phase, error))

    def test_uncapped_disconnects_and_unexpected_errors_remain_failures(self):
        for phase in ("shutdown", "drain"):
            with self.subTest(phase=phase, uncapped=True), self.assertRaises(OSError):
                self.exchange(FakePeer(phase, OSError(errno.ENOTCONN, "fixture disconnect")), capped=False)
            with self.subTest(phase=phase, unexpected_errno=True), self.assertRaises(OSError):
                self.exchange(FakePeer(phase, OSError(errno.EIO, "fixture fault")))

    def test_connected_bounded_reader_still_rejects_extra_request_bytes(self):
        with self.assertRaisesRegex(ValueError, "after the reviewed probe"):
            self.exchange(FakePeer(extra=b"unexpected request"))


if __name__ == "__main__":
    unittest.main()
