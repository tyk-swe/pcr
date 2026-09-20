#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Offline tests of native-smoke evidence parsing; no native runtime exercised."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("native_capture", ROOT / "scripts/check-native-capture.py")
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)
FIXTURE = json.loads((ROOT / "examples/documents/output-capture-complete.json").read_text())
FIXTURE["sequence"] = 0


class NativeEvidenceTests(unittest.TestCase):
    def terminal(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.ndjson"
            path.write_bytes(data)
            return SMOKE.terminal(path)

    def test_complete_capture_preserves_unknown_effective_settings(self):
        row = self.terminal(json.dumps(FIXTURE).encode() + b"\n")
        sources = SMOKE.completed_sources(row)
        self.assertIsNone(sources[0]["capture_settings"]["buffer_size"]["effective"])

    def test_missing_truncated_repeated_and_nonobject_envelopes_rejected(self):
        data = json.dumps(FIXTURE).encode() + b"\n"
        for invalid in (b"", data[:-1], data + data, b"[]\n"):
            with self.subTest(prefix=invalid[:20]), self.assertRaises(ValueError):
                self.terminal(invalid)

    def test_duplicate_keys_unknown_schema_and_sequence_gaps_rejected(self):
        data = json.dumps(FIXTURE).encode() + b"\n"
        invalid = data.replace(b'"sequence": 0', b'"sequence": 0, "sequence": 0')
        with self.assertRaises(ValueError):
            self.terminal(invalid)
        for field, value in (("sequence", 2), ("schema", "packetcraftr.output/v5")):
            row = copy.deepcopy(FIXTURE)
            row[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.terminal(json.dumps(row).encode() + b"\n")

    def test_unconfirmed_or_nonboolean_evidence_is_not_a_pass(self):
        for field in ("ready", "shutdown_confirmed", "metadata_valid"):
            for value in (False, None, 1, "true"):
                row = copy.deepcopy(FIXTURE)
                row["result"]["sources"][0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    SMOKE.completed_sources(row)

    def test_error_terminal_is_not_capture_completion(self):
        row = {"schema": "packetcraftr.output/v6", "command": "capture",
               "sequence": 0, "event": "error", "status": "error",
               "error": {"code": "fixture.native_error"}}
        parsed = self.terminal(json.dumps(row).encode() + b"\n")
        with self.assertRaises(ValueError):
            SMOKE.completed_sources(parsed)


if __name__ == "__main__":
    unittest.main()
