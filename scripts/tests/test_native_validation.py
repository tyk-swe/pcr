# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from support import ROOT, load_script

native = load_script('test-native-isolated')
lifecycle = load_script('test-native-namespace-lifecycle')


def exchange_report():
    records = [json.loads((ROOT / f'examples/documents/output-exchange-{event}.json').read_text())
               for event in ('sent-event', 'response-event', 'complete')]
    records[2]['sequence'] = 2
    records[2]['result']['unanswered'] = []
    reply = '4500' + b'isolated-reply'.hex()
    records[1]['result']['response']['frame']['bytes_hex'] = reply
    return dict(exit_code=0, stdout='\n'.join(json.dumps(record) for record in records) + '\n',
                reply_bytes=reply, received_messages=[b'isolated-probe'.hex()])


class NativeExchangeTests(unittest.TestCase):
    def test_positive_exchange_evidence(self):
        native.validate_exchange(exchange_report())

    def test_execution_and_responder_failures_remain_failures(self):
        for updates in ({'exit_code': 1}, {'exit_code': False}, {'responder_error': 'socket failed'},
                        {'received_messages': []}, {'stdout': ''}, {'reply_bytes': 'wrong'}):
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                native.validate_exchange(dict(exchange_report(), **updates))

    def test_stream_identity_sequence_terminal_and_attribution(self):
        changes = {
            'schema': lambda rows: rows[0].update(schema='unknown'),
            'mode': lambda rows: rows[0].update(mode='aggregate'),
            'command': lambda rows: rows[0].update(command='scan'),
            'status': lambda rows: rows[0].update(status='error'),
            'boolean sequence': lambda rows: rows[0].update(sequence=False),
            'missing terminal': lambda rows: rows.pop(),
            'early terminal': lambda rows: rows[0].update(event='complete'),
            'unknown event': lambda rows: rows[0].update(event='unknown'),
            'no sent': lambda rows: rows[0].update(event='unsolicited'),
            'unattributed reply': lambda rows: rows[1].update(event='unsolicited'),
            'wrong request': lambda rows: rows[1]['result'].update(request_index=1),
            'boolean request': lambda rows: rows[1]['result'].update(request_index=False),
            'wrong bytes': lambda rows: rows[1]['result']['response']['frame'].update(bytes_hex='bad'),
            'unanswered': lambda rows: rows[2]['result'].update(unanswered=[0]),
        }
        for label, change in changes.items():
            report = exchange_report()
            records = [json.loads(line) for line in report['stdout'].splitlines()]
            change(records)
            report['stdout'] = '\n'.join(json.dumps(record) for record in records) + '\n'
            with self.subTest(label=label), self.assertRaises(ValueError):
                native.validate_exchange(report)

    def test_missing_ndjson_newline_is_rejected(self):
        report = exchange_report()
        report['stdout'] = report['stdout'].rstrip('\n')
        with self.assertRaises(ValueError):
            native.validate_exchange(report)

    def test_checks_are_not_python_assert_statements(self):
        import ast
        tree = ast.parse((ROOT / 'scripts/test-native-isolated.py').read_text())
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))


class NamespaceLifecycleTests(unittest.TestCase):
    def test_cargo_executable_selection_requires_library_test(self):
        record = dict(reason='compiler-artifact', target=dict(name='packetcraftr_netio', kind=['lib']),
                      profile={'test': True}, executable=str(ROOT / 'test-binary'))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cargo.json'
            args = SimpleNamespace(test_binary=None, build_report=path)
            path.write_text(json.dumps(record) + '\n')
            self.assertEqual(lifecycle.test_binary(args), ROOT / 'test-binary')
            record['target']['kind'] = ['test']
            path.write_text(json.dumps(record) + '\n')
            with self.assertRaises(ValueError):
                lifecycle.test_binary(args)

    def test_cargo_report_is_bounded_and_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cargo.json'
            args = SimpleNamespace(test_binary=None, build_report=path)
            for data in ('[]', '{"reason":1,"reason":2}', ' ' * 101):
                path.write_text(data)
                with patch.object(lifecycle, 'MAX_JSON_BYTES', 100), self.assertRaises(ValueError):
                    lifecycle.test_binary(args)

    def test_invalid_namespace_metric_identities(self):
        for metrics, namespace, parent in (([], 2, 1), ({'initial_namespace': True, 'parent_namespace': 2}, 1, 2),
                                           ({'initial_namespace': 1, 'parent_namespace': 1}, 1, 1)):
            with self.subTest(metrics=metrics), self.assertRaises(ValueError):
                lifecycle.validate_metrics(metrics, namespace, parent)

    def test_child_success_cannot_survive_launcher_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            binary, report = Path(directory) / 'binary', Path(directory) / 'report.json'
            binary.write_bytes(b'binary')
            def fail_after_child_merge(args, binary, result):
                result['status'] = 'passed'
                raise RuntimeError('launcher failed after child report')
            argv = ['test', '--test-binary', str(binary), '--report', str(report)]
            with patch.object(sys, 'argv', argv), patch.object(lifecycle, 'run', side_effect=fail_after_child_merge), \
                    patch.object(lifecycle.subprocess, 'check_output', side_effect=['a' * 40, b'']):
                self.assertEqual(lifecycle.main(), 1)
            self.assertEqual(json.loads(report.read_text())['status'], 'failed')

    def test_executable_mutation_invalidates_success(self):
        with tempfile.TemporaryDirectory() as directory:
            binary, report = Path(directory) / 'binary', Path(directory) / 'report.json'
            binary.write_bytes(b'before')
            def mutate(args, binary, result):
                binary.write_bytes(b'after')
                result['status'] = 'passed'
            argv = ['test', '--test-binary', str(binary), '--report', str(report)]
            with patch.object(sys, 'argv', argv), patch.object(lifecycle, 'run', side_effect=mutate), \
                    patch.object(lifecycle.subprocess, 'check_output', side_effect=['a' * 40, b'']):
                self.assertEqual(lifecycle.main(), 1)
            self.assertIn('changed', json.loads(report.read_text())['error'])

    def test_report_alias_never_overwrites_test_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'binary'
            binary.write_bytes(b'binary')
            argv = ['test', '--test-binary', str(binary), '--report', str(binary)]
            with patch.object(sys, 'argv', argv), self.assertRaises(SystemExit):
                lifecycle.main()
            self.assertEqual(binary.read_bytes(), b'binary')


if __name__ == '__main__':
    unittest.main()
