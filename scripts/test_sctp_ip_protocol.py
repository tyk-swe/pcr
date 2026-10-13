#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for M13 SCTP and IP-protocol corpus and native evidence contracts."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import sctp_ip_protocol_native_evidence as evidence  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
