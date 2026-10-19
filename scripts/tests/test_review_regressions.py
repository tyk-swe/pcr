# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Regression cases found while reviewing the complete maintenance patch."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import tracemalloc
import unittest
from unittest.mock import patch

from support import ROOT, load_script
import script_support
from test_native_validation import exchange_report

native = load_script('test-native-isolated')
benchmark = load_script('benchmark-scanner')
manifest = load_script('build-manifest')


class ReviewRegressions(unittest.TestCase):
    def test_json_tree_validation_has_depth_not_width_overhead(self):
        value = list(range(20_000))
        tracemalloc.start()
        try:
            script_support._validate_tree(value)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 256 * 1024)

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

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'named pipes require POSIX')
    def test_json_reader_rejects_fifo_without_waiting_for_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / 'report.json'
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, 'regular file'):
                script_support.read_json(fifo)

    def test_unicode_line_separators_are_json_content_not_ndjson_boundaries(self):
        report = exchange_report()
        records = [json.loads(line) for line in report['stdout'].splitlines()]
        records[0]['future'] = 'a\u0085b\u2028c\u2029d'
        report['stdout'] = '\n'.join(json.dumps(record, ensure_ascii=False) for record in records) + '\n'
        native.validate_exchange(report)

    def test_native_report_alias_is_rejected_before_running_or_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'binary'
            binary.write_bytes(b'original executable')
            argv = ['native-test', '--binary', str(binary), '--report', str(binary)]
            with patch.object(sys, 'argv', argv), patch.object(native, 'run') as run:
                with self.assertRaises(SystemExit):
                    native.main()
                run.assert_not_called()
            self.assertEqual(binary.read_bytes(), b'original executable')

    def test_benchmark_report_aliases_are_rejected_before_execution(self):
        specifications = (
            ('benchmark-scanner', '--binary'),
            ('benchmark-adaptive-scenarios', '--fixture-binary'),
            ('compare-scheduling', '--baseline'),
        )
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'input'
            source.write_bytes(b'original input')
            for name, flag in specifications:
                tool = load_script(name)
                argv = [name, flag, str(source), '--report', str(source)]
                if name == 'compare-scheduling':
                    argv += ['--candidate', str(source)]
                with self.subTest(name=name), patch.object(sys, 'argv', argv), self.assertRaises(SystemExit):
                    tool.main()
                self.assertEqual(source.read_bytes(), b'original input')

    def test_version_and_compiler_payload_cannot_be_blank(self):
        from test_build_manifest import identity
        for field, value in (('version', 'packetcraftr '), ('rustc', 'rustc ')):
            document = identity()
            document[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                manifest.validate_identity(document)

    def test_failed_reader_start_cleans_up_the_child(self):
        real_thread, real_popen = threading.Thread, subprocess.Popen
        threads, children = [], []

        def make_thread(*args, **kwargs):
            if threads:
                raise RuntimeError('thread resources unavailable')
            thread = real_thread(*args, **kwargs)
            threads.append(thread)
            return thread

        def popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            children.append(process)
            return process

        with patch.object(benchmark.threading, 'Thread', side_effect=make_thread), \
                patch.object(benchmark.subprocess, 'Popen', side_effect=popen):
            with self.assertRaisesRegex(RuntimeError, 'thread resources'):
                benchmark.measured([sys.executable, '-S', '-c', 'import time; time.sleep(30)'])
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)
        self.assertTrue(all(not thread.is_alive() for thread in threads))

    def test_exchange_always_joins_responder_after_command_timeout(self):
        with patch.object(native.socket, 'socket') as sockets, \
                patch.object(native.threading, 'Thread') as worker, \
                patch.object(native.subprocess, 'run', side_effect=subprocess.TimeoutExpired('exchange', 10)):
            sockets.return_value.__enter__.return_value.getsockname.return_value = ('127.0.0.1', 12345)
            with self.assertRaises(subprocess.TimeoutExpired):
                native.exchange(Path('binary'), {})
            worker.return_value.start.assert_called_once()
            worker.return_value.join.assert_called_once_with(timeout=6)

    def test_pipe_read_failure_cannot_publish_a_measurement(self):
        real_popen = subprocess.Popen
        children = []

        class FailingPipe:
            def __init__(self, source):
                self.source = source

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.source.close()

            def read(self, size):
                raise OSError('injected pipe failure')

        def popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            process.stdout = FailingPipe(process.stdout)
            children.append(process)
            return process

        with patch.object(benchmark.subprocess, 'Popen', side_effect=popen):
            with self.assertRaises(ValueError):
                benchmark.measured([sys.executable, '-S', '-c', 'import time; time.sleep(30)'])
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdout.source.closed)

    def test_existing_archive_consumer_contract_checks(self):
        load_script('verify-archive').verify_forwarding_consumer(ROOT)


if __name__ == '__main__':
    unittest.main()
