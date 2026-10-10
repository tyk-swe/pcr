#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Reference consumer contract: accepted families and report fields."""
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
    def test_declares_v12_and_frozen_earlier_families(self):
        self.assertIn("packetcraftr.output/v12", CONSUMER.SCHEMAS)
        for family in ("v6", "v7", "v8", "v9", "v10", "v11"):
            self.assertIn(f"packetcraftr.output/{family}", CONSUMER.SCHEMAS)

    def test_accepts_current_and_frozen_v11_forwarding(self):
        for family in ("v11", "v12"):
            with self.subTest(family=family):
                self.assertTrue(consume_stream(ROOT / f"examples/consumers/fixtures/{family}-forwarding.json"))

    def test_accepts_the_v10_forwarding_fixture(self):
        observed = consume_stream(ROOT / "examples/consumers/fixtures/v10-forwarding.json")
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
