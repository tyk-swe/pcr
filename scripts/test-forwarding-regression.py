#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

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

    def test_relative_bundle_paths_are_unambiguous_child_capture_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = Path.cwd()
            os.chdir(directory)
            try:
                for name in ("bundle", "bundle space 🐙", "-bundle"):
                    with self.subTest(name=name):
                        root = Path(name)
                        current = {}

                        def child(argv, output, errors, seconds=60):
                            errors.write_bytes(b"")
                            if argv[1:] == ["--version"]:
                                output.write_text("packetcraftr fixture\n")
                            else:
                                ingress, egress = map(Path, argv[5:7])
                                self.assertFalse(str(ingress).startswith("-"), argv)
                                self.assertFalse(str(egress).startswith("-"), argv)
                                self.assertEqual(ingress.parent.resolve(), root.resolve())
                                self.assertEqual(egress.parent.resolve(), root.resolve())
                                self.assertTrue(ingress.is_file())
                                self.assertTrue(egress.is_file())
                                current.update(ingress=ingress, egress=egress, name=output.stem)
                                output.write_bytes(b"fixture\n")
                            return 0, 0.01

                        def consume(source, format, code):
                            verdict = {"intentional-violation": "fail", "insufficient-evidence": "inconclusive",
                                       "missing-field": "inconclusive"}.get(current["name"], "pass")
                            return {"execution": "complete", "verdict": verdict,
                                    "report": {"captures": {
                                        side: {"source": {"sha256": REGRESSION.digest(current[side])}}
                                        for side in ("ingress", "egress")}}}

                        with mock.patch.object(REGRESSION, "run_bounded", side_effect=child), \
                                mock.patch.object(REGRESSION.CONSUMER, "consume", side_effect=consume):
                            result = REGRESSION.run_bundle(root, Path(sys.executable))
                        self.assertEqual(result["execution"], "complete")
                        self.assertTrue(all(case["test_contract"] == "pass" for case in result["cases"]))
                        self.assertEqual(json.loads((root / "manifest.json").read_text()), result)
            finally:
                os.chdir(previous)

    def test_dangling_output_symlink_is_not_used_as_a_new_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "bundle"
            target = root / "missing"
            try:
                output.symlink_to(target, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlink fixture unavailable: {error}")
            with self.assertRaises(FileExistsError):
                REGRESSION.run_bundle(output, None)
            self.assertTrue(output.is_symlink())
            self.assertFalse(target.exists())

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
