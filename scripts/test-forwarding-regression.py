#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("regression", Path(__file__).with_name("forwarding-regression.py"))
REGRESSION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REGRESSION)


class RegressionTests(unittest.TestCase):
    def test_generator_produces_valid_nonempty_and_empty_captures(self):
        for frames in ([], [REGRESSION.datagram(7, b"hello")]):
            self.assertEqual(REGRESSION.validate_capture(REGRESSION.capture(frames)), len(frames))

    def test_corrupted_checksums_and_lengths_are_detected(self):
        valid = REGRESSION.capture([REGRESSION.datagram(7, b"hello")])
        for index in (8, 24 + 8, 40 + 2, 40 + 10, 40 + 26, len(valid) - 1):
            changed = bytearray(valid)
            changed[index] ^= 1
            with self.subTest(index=index), self.assertRaises(ValueError):
                REGRESSION.validate_capture(bytes(changed))

    def test_truncated_records_are_detected(self):
        valid = REGRESSION.capture([REGRESSION.datagram(7, b"hello")])
        for keep in (0, 23, 25, 35, len(valid) - 1):
            with self.subTest(keep=keep), self.assertRaises(ValueError):
                REGRESSION.validate_capture(valid[:keep])

    def test_fixture_only_mode_never_claims_a_test_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            result = REGRESSION.run_bundle(root, None)
            self.assertEqual(result["execution"], "not_run")
            self.assertTrue(all(case["execution"] == "not_run" for case in result["cases"]))
            self.assertTrue(all("test_contract" not in case for case in result["cases"]))
            self.assertIsNone(result["acquisition"]["capture_drop_statistics"])
            self.assertEqual(json.loads((root / "manifest.json").read_text())["execution"], "not_run")
            with self.assertRaises(FileExistsError):
                REGRESSION.run_bundle(root, None)

    def test_unavailable_binary_leaves_failed_manifest_without_forged_case_results(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = REGRESSION.run_bundle(root / "bundle", root / "missing-binary")
            self.assertEqual(result["execution"], "failed")
            self.assertTrue(result["tool_error"])
            self.assertTrue(all(case["execution"] == "not_run" for case in result["cases"]))
            self.assertEqual(
                json.loads((root / "bundle/manifest.json").read_text())["execution"], "failed",
            )

    def test_child_time_budget_cleans_up_and_reports_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "budget"):
                REGRESSION.run_bounded(
                    [sys.executable, "-S", "-c", "import time; time.sleep(10)"],
                    root / "out", root / "err", seconds=0.02)

    def test_bounded_child_records_exit_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, elapsed = REGRESSION.run_bounded(
                [sys.executable, "-S", "-c", "print('fixture'); raise SystemExit(1)"],
                root / "out", root / "err")
            self.assertEqual(code, 1)
            self.assertGreaterEqual(elapsed, 0)
            self.assertEqual((root / "out").read_text().strip(), "fixture")

    def test_large_keys_fit_input_contract(self):
        frame = REGRESSION.datagram(255, struct.pack("!H", 255) + b"\xff" * 32758)
        self.assertEqual(REGRESSION.validate_capture(REGRESSION.capture([frame])), 1)
        self.assertEqual(len(frame), 32788)


if __name__ == "__main__":
    unittest.main()
