# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from support import ROOT
import script_support
from script_support import distinct_paths, read_json, strict_json, write_json_atomic


class DigestTests(unittest.TestCase):
    def test_digest_rejects_non_regular_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'regular file'):
                script_support.digest(directory)

    def test_digest_matches_sha256(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'binary'
            path.write_bytes(b'abc')
            self.assertEqual(script_support.digest(path),
                             'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')


class StrictJsonTests(unittest.TestCase):
    def test_wide_shallow_json_is_accepted_and_deep_json_is_rejected(self):
        width = 20_000
        value = strict_json('[' + ','.join('0' for _ in range(width)) + ']')
        self.assertEqual(len(value), width)
        depth = script_support.MAX_JSON_DEPTH + 1
        with self.assertRaises(ValueError):
            strict_json('[' * depth + '0' + ']' * depth)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'named pipes require POSIX')
    def test_json_reader_rejects_fifo_without_waiting_for_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / 'report.json'
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, 'regular file'):
                script_support.read_json(fifo)

    def test_duplicate_keys_are_rejected_at_any_depth(self):
        for raw in ['{"a":1,"a":2}', '{"nested":{"a":1,"a":2}}']:
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, 'duplicate'):
                strict_json(raw)

    def test_all_nonfinite_spellings_are_rejected(self):
        for raw in ['NaN', 'Infinity', '-Infinity', '1e9999', '-1e9999']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                strict_json(raw)

    def test_input_must_be_utf8_not_auto_detected_utf16(self):
        for encoding in ['utf-16', 'utf-32']:
            with self.subTest(encoding=encoding), self.assertRaises(ValueError):
                strict_json('{"a":1}'.encode(encoding))

    def test_surrogates_in_additive_fields_and_keys_are_rejected(self):
        for raw in ['{"extra":"\\ud800"}', '{"\\udfff":1}']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                strict_json(raw)
        self.assertEqual(strict_json('"\\ud83d\\ude00"'), '\U0001f600')

    def test_depth_is_bounded_without_uncaught_recursion(self):
        for depth in [65, 2000]:
            with self.subTest(depth=depth), self.assertRaises(ValueError):
                strict_json('[' * depth + '0' + ']' * depth)

    def test_size_is_measured_in_utf8_bytes(self):
        with self.assertRaises(ValueError):
            strict_json('"é"', max_bytes=3)
        self.assertEqual(strict_json('"é"', max_bytes=4), 'é')

    def test_read_has_a_finite_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.json'
            path.write_bytes(b' ' * 10 + b'{}')
            with self.assertRaisesRegex(ValueError, 'input.json'):
                read_json(path, max_bytes=10)

    def test_invalid_json_limits_are_rejected_before_io(self):
        for limit in [0, -1, True, 1.5]:
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                read_json(Path('missing'), max_bytes=limit)


class AtomicReportTests(unittest.TestCase):
    def test_prepare_report_removes_stale_success_but_not_input(self):
        with tempfile.TemporaryDirectory() as directory:
            report, source = Path(directory) / 'report.json', Path(directory) / 'input'
            source.write_bytes(b'input')
            report.write_text('{"status":"passed"}')
            script_support.prepare_report(report, source)
            self.assertFalse(report.exists())
            with self.assertRaises(ValueError):
                script_support.prepare_report(source, source)
            self.assertEqual(source.read_bytes(), b'input')

    def test_success_creates_parents_and_utf8_newline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'nested/report.json'
            write_json_atomic(path, {'name': 'é'})
            self.assertEqual(json.loads(path.read_bytes()), {'name': 'é'})
            self.assertTrue(path.read_bytes().endswith(b'\n'))
            self.assertNotIn(b'\r', path.read_bytes())

    def test_serialization_failure_preserves_existing_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text('previous')
            with self.assertRaises(ValueError):
                write_json_atomic(path, {'number': float('nan')})
            self.assertEqual(path.read_text(), 'previous')

    def test_replace_failure_cleans_temporary_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text('previous')
            with patch('script_support.os.replace', side_effect=OSError('test failure')):
                with self.assertRaises(OSError):
                    write_json_atomic(path, {'status': 'passed'})
            self.assertEqual(path.read_text(), 'previous')
            self.assertEqual([p.name for p in path.parent.iterdir()], ['report.json'])

    def test_output_cannot_alias_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'binary'
            source.write_bytes(b'preserve')
            with self.assertRaises(ValueError):
                distinct_paths(source, source)
            alias = source.with_name('alias')
            alias.hardlink_to(source)
            with self.assertRaises(ValueError):
                distinct_paths(alias, source)
            distinct_paths(source.with_name('report.json'), source)
