# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
from contextlib import nullcontext
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import cast
import unittest
from unittest.mock import patch

from support import ROOT
import script_support
from script_support import distinct_paths, read_json, strict_json, write_json_atomic


class DigestTests(unittest.TestCase):
    def test_digest_validation_requires_the_complete_lowercase_hex_value(self) -> None:
        for width in (8, 40, 64):
            value = 'abcdef01' * (width // 8)
            self.assertTrue(script_support.valid_digest(value, width))
            for invalid in (value[:-1], value + 'a', value.upper(), value + '\n',
                            value[:-1] + 'g', value.encode(), None, width):
                with self.subTest(width=width, invalid=invalid):
                    self.assertFalse(script_support.valid_digest(invalid, width))
        self.assertTrue(script_support.valid_digest('a' * 64))
        self.assertFalse(script_support.valid_digest('a' * 40))

    def test_digest_rejects_non_regular_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'regular file'):
                script_support.digest(directory)

    def test_digest_matches_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'binary'
            path.write_bytes(b'abc')
            # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf checked 2026-10-25.
            self.assertEqual(script_support.digest(path),
                             'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
            data = bytes(range(256)) * 300 + b'final bytes'
            path.write_bytes(data)
            self.assertEqual(script_support.digest(path), hashlib.sha256(data).hexdigest())


class PortableNameTests(unittest.TestCase):
    def test_supported_names_and_reserved_components_are_distinguished(self) -> None:
        # https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file checked 2026-10-25.
        for name in ('report.json', 'name with spaces', '.hidden', 'résumé', '~'):
            self.assertTrue(script_support.portable_basename(name), name)
        invalid = ('', '.', '..', 'name ', 'name.', 'CON', 'prn.txt', 'AuX.json', 'nul',
                   'CONIN$.txt', 'conout$', 'COM1', 'lpt9.json', 'com¹.txt', 'lpt²', 'COM³', 'con .txt')
        controls = tuple(f'a{chr(value)}b' for value in (*range(32), 127))
        separators = tuple(f'a{value}b' for value in '/\\:*?"<>|')
        for name in (*invalid, *controls, *separators):
            self.assertFalse(script_support.portable_basename(name), repr(name))


class StrictJsonTests(unittest.TestCase):
    def test_wide_json_values_preserve_every_item(self) -> None:
        value = list(range(20_000))
        self.assertEqual(strict_json(json.dumps(value)), value)
        with self.assertRaises(ValueError):
            strict_json(json.dumps([*value, float('nan')]))

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'named pipes require POSIX')
    def test_json_reader_rejects_fifo_without_waiting_for_writer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / 'report.json'
            os.mkfifo(fifo)
            result = subprocess.run(
                [sys.executable, '-c',
                 'import sys\nfrom script_support import read_json\n'
                 'try:\n    read_json(sys.argv[1])\n'
                 'except ValueError as error:\n    print(error)\n    sys.exit(0)\n'
                 'sys.exit(1)', str(fifo)],
                cwd=ROOT / 'scripts', capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('regular file', result.stdout)

    def test_duplicate_keys_are_rejected_at_any_depth(self) -> None:
        for raw in ['{"a":1,"a":2}', '{"nested":{"a":1,"a":2}}']:
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, 'duplicate'):
                strict_json(raw)

    def test_all_nonfinite_spellings_are_rejected(self) -> None:
        for raw in ['NaN', 'Infinity', '-Infinity', '1e9999', '-1e9999']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                strict_json(raw)

    def test_input_must_be_utf8_not_auto_detected_utf16(self) -> None:
        for encoding in ['utf-16', 'utf-32']:
            with self.subTest(encoding=encoding), self.assertRaises(ValueError):
                strict_json('{"a":1}'.encode(encoding))

    def test_surrogates_in_additive_fields_and_keys_are_rejected(self) -> None:
        for raw in ['{"extra":"\\ud800"}', '{"\\udfff":1}']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                strict_json(raw)
        self.assertEqual(strict_json('"\\ud83d\\ude00"'), '\U0001f600')

    def test_depth_is_bounded_without_uncaught_recursion(self) -> None:
        depth = 64
        value = strict_json('[' * depth + '0' + ']' * depth)
        for _ in range(depth):
            self.assertIsInstance(value, list)
            self.assertEqual(len(value), 1)
            value = value[0]
        self.assertEqual(value, 0)
        for depth in [65, 2000]:
            with self.subTest(depth=depth), self.assertRaises(ValueError):
                strict_json('[' * depth + '0' + ']' * depth)
        raw = '{"child":' * 64 + '7' + '}' * 64
        value = strict_json(raw)
        for _ in range(64):
            self.assertIsInstance(value, dict)
            self.assertEqual(tuple(value), ('child',))
            value = value['child']
        self.assertEqual(value, 7)
        with self.assertRaises(ValueError):
            strict_json('{"child":' * 65 + '7' + '}' * 65)

    def test_nested_siblings_are_validated_after_empty_containers(self) -> None:
        expected = [[], {'nested': [[], 'retained']}, 7]
        self.assertEqual(strict_json(json.dumps(expected)), expected)
        for raw in ('[[], {"nested": [[], 1e9999]}]', '[{}, {"extra": "\\ud800"}]'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                strict_json(raw)

    def test_default_byte_budget_accepts_its_boundary_and_refuses_excess(self) -> None:
        limit = 32 * 1024 * 1024
        value = 'x' * (limit - 2)
        self.assertEqual(strict_json('"' + value + '"'), value)
        with self.assertRaises(ValueError):
            strict_json(b'0' + b' ' * limit)

    def test_size_is_measured_in_utf8_bytes(self) -> None:
        with self.assertRaises(ValueError):
            strict_json('"é"', max_bytes=3)
        self.assertEqual(strict_json('"é"', max_bytes=4), 'é')
        self.assertEqual(strict_json('"é"'.encode('utf-8'), max_bytes=5), 'é')

    def test_read_has_a_finite_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.json'
            path.write_bytes(b' ' * 10 + b'{}')
            with self.assertRaisesRegex(ValueError, 'input.json'):
                read_json(path, max_bytes=10)
            for limit in (1, 2, 9, 10, 11):
                raw = b'0' if limit == 1 else b'"' + b'x' * (limit - 2) + b'"'
                path.write_bytes(raw)
                self.assertEqual(read_json(path, max_bytes=limit), json.loads(raw))
                path.write_bytes(b'0' + b' ' * (limit + 2))
                with self.subTest(limit=limit), self.assertRaises(ValueError):
                    read_json(path, max_bytes=limit)

    def test_rejected_file_still_respects_the_available_read_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.json'
            path.write_bytes(b'0' + b' ' * 20)
            for limit in (9, 10):
                source = io.BytesIO(path.read_bytes())
                original = source.read

                def bounded_read(size: int = -1) -> bytes:
                    data = original(size)
                    if source.tell() > limit + 1:
                        raise OSError('controlled input exhausted its read budget')
                    return data

                with patch.object(source, 'read', side_effect=bounded_read), \
                        patch.object(Path, 'open', return_value=nullcontext(source)), \
                        self.subTest(limit=limit), self.assertRaises(ValueError):
                    read_json(path, max_bytes=limit)

    def test_invalid_json_limits_are_rejected_before_io(self) -> None:
        for limit in [0, -1, -2, True, 1.5]:
            with self.subTest(limit=limit), \
                    patch.object(Path, 'is_file', side_effect=AssertionError('unexpected file metadata access')), \
                    patch.object(Path, 'open', side_effect=AssertionError('unexpected file read')), \
                    self.assertRaises(ValueError):
                read_json(Path('missing'), max_bytes=cast(int, limit))
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                strict_json('0', max_bytes=cast(int, limit))
        self.assertEqual(strict_json('0', max_bytes=1), 0)


class AtomicReportTests(unittest.TestCase):
    def test_prepare_report_removes_stale_success_but_not_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, source = Path(directory) / 'report.json', Path(directory) / 'input'
            source.write_bytes(b'input')
            report.write_text('{"status":"passed"}')
            script_support.prepare_report(report, source)
            self.assertFalse(report.exists())
            script_support.prepare_report(report, source)
            self.assertFalse(report.exists())
            with self.assertRaises(ValueError):
                script_support.prepare_report(source, source)
            self.assertEqual(source.read_bytes(), b'input')

    def test_success_creates_parents_and_utf8_newline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'outer/nested/report.json'
            write_json_atomic(path, {'name': 'é'})
            self.assertEqual(json.loads(path.read_bytes()), {'name': 'é'})
            self.assertTrue(path.read_bytes().endswith(b'\n'))
            self.assertNotIn(b'\r', path.read_bytes())

    def test_serialization_failure_preserves_existing_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text('previous')
            with self.assertRaises(ValueError):
                write_json_atomic(path, {'number': float('nan')})
            self.assertEqual(path.read_text(), 'previous')
            for invalid in ({1: 'invalid key'}, {'key': '\ud800'}, {'\udfff': 'value'},
                            {'nested': [[], float('inf')]}):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    write_json_atomic(path, invalid)
                self.assertEqual(path.read_text(), 'previous')

    @unittest.skipUnless(os.name == 'posix', 'POSIX permission bits are required')
    def test_replacement_retains_the_existing_reports_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text('previous')
            path.chmod(0o640)
            write_json_atomic(path, {'status': 'passed'})
            self.assertEqual(json.loads(path.read_bytes()), {'status': 'passed'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_replace_failure_cleans_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text('previous')
            with patch('script_support.os.replace', side_effect=OSError('test failure')):
                with self.assertRaises(OSError):
                    write_json_atomic(path, {'status': 'passed'})
            self.assertEqual(path.read_text(), 'previous')
            self.assertEqual([p.name for p in path.parent.iterdir()], ['report.json'])

    def test_output_cannot_alias_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'binary'
            source.write_bytes(b'preserve')
            with self.assertRaises(ValueError):
                distinct_paths(source, source)
            alias = source.with_name('alias')
            alias.hardlink_to(source)
            with self.assertRaises(ValueError):
                distinct_paths(alias, source)
            for name in ('a-report.json', 'report.json'):
                with self.subTest(output=name):
                    distinct_paths(source.with_name(name), source)
            missing = Path(directory) / 'absent-input'
            for output in (missing, Path(directory) / 'nested/../absent-input'):
                with self.subTest(output=output), self.assertRaises(ValueError):
                    distinct_paths(output, missing)
