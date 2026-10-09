#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Failure-path contracts for the service identification acceptance runner."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name("test-service-identification.py")
SPEC = importlib.util.spec_from_file_location("service_identification_acceptance", MODULE_PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class AcceptanceContracts(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
