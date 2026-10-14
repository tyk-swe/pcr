#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for M13 SCTP and IP-protocol corpus and native evidence contracts."""
import copy
import json
import struct
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import sctp_ip_protocol_native_evidence as evidence  # noqa: E402
import sctp_ip_protocol_isolated_fixture as fixture  # noqa: E402
from discovery_isolated_fixture import packet  # noqa: E402
from tcp_diagnostic_wire import network  # noqa: E402

CORPUS = json.loads((ROOT / "docs/scanner-corpus.v1.json").read_text(encoding="utf-8"))


class SctpIpProtocolEvidenceContracts(unittest.TestCase):
    def test_corpus_inventory_and_initial_report_validate(self):
        evidence.validate_corpus(CORPUS)
        self.assertEqual(CORPUS["dataset_version"], "1.8.0")
        report = evidence.initial(
            "Linux",
            "a" * 40,
            False,
            "b" * 64,
            CORPUS["dataset_version"],
            {"Cargo.toml": "c" * 64},
        )
        report["reviewed_commit"] = "a" * 40
        self.assertTrue(
            evidence.validate(
                report,
                CORPUS,
                "a" * 40,
                False,
                {"Cargo.toml": "c" * 64},
                "b" * 64,
            )
        )
        self.assertFalse(evidence.coverage_complete(report))

    def test_commands_and_typed_refusals_are_strict(self):
        report = evidence.initial(
            "Linux",
            "a" * 40,
            False,
            "b" * 64,
            CORPUS["dataset_version"],
            {"Cargo.toml": "c" * 64},
            profiles=("portable",),
        )
        case = report["profiles"][0]["cases"][0]
        cmd = evidence.command("/bin/packetcraftr", case)
        self.assertIn("--sctp-scan", cmd)
        ip_case = next(
            c for c in report["profiles"][0]["cases"] if c["scenario"] == "ip-protocol"
        )
        ip_cmd = evidence.command("/bin/packetcraftr", ip_case)
        self.assertIn("--ip-protocols", ip_cmd)

        case.update(
            expected_refusal=True,
            reason="unsupported_capability",
            run=dict(
                exit_code=2,
                stdout=json.dumps(
                    dict(
                        schema="packetcraftr.output/v16",
                        command="scan",
                        mode="aggregate",
                        status="error",
                        error=dict(code="capability.unsupported", message="disabled"),
                    )
                ),
                stderr="",
            ),
        )
        self.assertTrue(evidence.validate(report, CORPUS))

        bad = copy.deepcopy(report)
        bad["profiles"][0]["cases"][0]["run"]["exit_code"] = 0
        with self.assertRaises(ValueError):
            evidence.validate(bad, CORPUS)

    def test_empty_missing_and_duplicated_inventories_cannot_pass_acceptance(self):
        report = evidence.initial("Linux", "a" * 40, False, "b" * 64,
                                  CORPUS["dataset_version"], {"Cargo.toml": "c" * 64})
        report["reviewed_commit"] = "a" * 40
        for mutation in ("empty_profiles", "missing_profile", "duplicate_profile",
                         "empty_cases", "missing_case", "duplicate_case", "changed_family"):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(report)
                if mutation == "empty_profiles":
                    bad["profiles"] = []
                elif mutation == "missing_profile":
                    bad["profiles"].pop()
                elif mutation == "duplicate_profile":
                    bad["profiles"].append(copy.deepcopy(bad["profiles"][0]))
                elif mutation == "empty_cases":
                    for profile in bad["profiles"]:
                        profile.update(status="exercised", cases=[])
                elif mutation == "missing_case":
                    bad["profiles"][0]["cases"].pop()
                elif mutation == "duplicate_case":
                    cases = bad["profiles"][0]["cases"]
                    cases[-1] = copy.deepcopy(cases[0])
                else:
                    bad["profiles"][0]["cases"][0]["family"] = "ipv6"
                self.assertFalse(evidence.coverage_complete(bad))
                with self.assertRaises(ValueError):
                    evidence.validate(bad, CORPUS, require_complete=True)

    def test_independent_peer_emits_exact_mode_and_endpoint_replies(self):
        self.assertEqual(fixture.crc32c(b"123456789"), 0xe3069283)
        sequence, tag = 5, 5 + 0x50435231
        envelope = bytes.fromhex("00112233445566778899aabb")
        for family in evidence.FAMILIES:
            source, target = fixture.SOURCES[family], fixture.TARGETS[family]
            for scenario in CORPUS["sctp_ip_protocol_scenarios"]:
                for row in scenario["endpoints"]:
                    with self.subTest(family=family, scenario=scenario["id"], row=row):
                        if scenario["kind"] == "sctp":
                            init = scenario["id"] == "sctp-init"
                            chunk = (struct.pack('!BBHIIHHI', 1, 0, 20, tag, 65536, 10, 10, tag)
                                     if init else struct.pack('!BBHI', 10, 0, 8, tag))
                            body = fixture.sctp(struct.pack('!HHII', 40000, row["port"], 0 if init else tag, 0) + chunk)
                            proto = 132
                        else:
                            body, proto = b'', row["ip_protocol"]
                        raw = packet(source, target, proto, body)
                        wire = envelope + (b'\x08\x00' if family == 'ipv4' else b'\x86\xdd') + raw
                        answers = fixture.reply(wire)
                        self.assertEqual(len(answers), int(row["status"] == "response"))
                        if not answers:
                            continue
                        ip = network(answers[0], 1)
                        self.assertEqual((ip['source'], ip['target']), (target, source))
                        if row['condition'] in ('init-ack', 'abort', 'other'):
                            self.assertEqual(ip['proto'], 132)
                            self.assertEqual(ip['body'], fixture.sctp(ip['body']))
                            self.assertEqual(int.from_bytes(ip['body'][4:8], 'big'), tag)
                            self.assertEqual(ip['body'][12], {'init-ack': 2, 'abort': 6, 'other': 11}[row['condition']])
                        elif row['condition'] == 'reply':
                            self.assertEqual((ip['proto'], ip['body']),
                                             (47, b'') if family == 'ipv4' else
                                             (0, bytes.fromhex('3c000000000000002f00000000000000000088b5')))
                        else:
                            v4 = family == 'ipv4'
                            expected = {'prohibited': (3, 13) if v4 else (1, 1),
                                        'time-exceeded': (11, 0) if v4 else (3, 0),
                                        'protocol-unreachable': (3, 2) if v4 else (4, 1)}[row['condition']]
                            self.assertEqual(tuple(ip['body'][:2]), expected)
                            if not v4 and scenario['kind'] == 'ip_protocol' and expected[0] in (1, 3):
                                self.assertEqual(ip['body'][4:8], bytes.fromhex('10000000'))
                                self.assertEqual(ip['body'][8:48], raw)
                                self.assertEqual(ip['body'][48:136], b'\0' * 88)
                                self.assertEqual(ip['body'][136:], bytes.fromhex('2000ddb60008010100000140'))
                            else:
                                self.assertEqual(ip['body'][8:], raw)


if __name__ == "__main__":
    unittest.main()
