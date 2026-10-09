#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Reference consumer contract: accepted families and v11 report fields."""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "forwarding_consumer", ROOT / "examples/consumers/forwarding.py"
)
CONSUMER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONSUMER)


def consume_stream(document: Path) -> dict:
    record = json.loads(document.read_text())
    line = (json.dumps(record) + "\n").encode("utf-8")
    return CONSUMER.consume(io.BytesIO(line), "ndjson", 0)


class Family(unittest.TestCase):
    def test_declares_v11_and_frozen_earlier_families(self):
        self.assertIn("packetcraftr.output/v11", CONSUMER.SCHEMAS)
        for family in ("v6", "v7", "v8", "v9", "v10"):
            self.assertIn(f"packetcraftr.output/{family}", CONSUMER.SCHEMAS)

    def test_accepts_the_v10_forwarding_fixture(self):
        observed = consume_stream(ROOT / "examples/consumers/fixtures/v10-forwarding.json")
        self.assertTrue(observed)

    def test_accepts_the_v11_forwarding_fixture(self):
        observed = consume_stream(ROOT / "examples/consumers/fixtures/v11-forwarding.json")
        self.assertTrue(observed)

    def test_accepts_v10_forwarding_with_scheduling_metadata(self):
        record = json.loads(
            (ROOT / "examples/consumers/fixtures/v10-forwarding.json").read_text()
        )
        record["result"]["scheduling"] = {
            "mode": "adaptive",
            "observed_peak_window": 1,
            "retries_started": 0,
            "conditions": [],
            "incomplete": [],
        }
        line = (json.dumps(record) + "\n").encode("utf-8")
        self.assertTrue(CONSUMER.consume(io.BytesIO(line), "ndjson", 0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
