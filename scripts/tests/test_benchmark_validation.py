# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

from support import ROOT, load_script
from script_support import same_json

benchmark = load_script('benchmark-scanner')
comparison = load_script('compare-scheduling')
adaptive = load_script('benchmark-adaptive-scenarios')
CORPUS = ROOT / 'docs/scanner-corpus.v1.json'


def complete_report(mode='fixed'):
    report = dict(schema='packetcraftr.scanner-benchmark/v1', status='exercised',
                  scheduling_mode=mode, repetitions=1, platform='test-platform',
                  settings={'attempts': 1}, corpus_sha256='a' * 64, cases=[])
    for family in ('ipv4', 'ipv6'):
        identities = [('raw_scan', condition, transport, window)
                      for condition in benchmark.CONDITIONS
                      for transport in ('tcp', 'udp', 'icmp') for window in (1, 2)]
        identities += [('traceroute', condition, transport, 1)
                       for condition in ('responsive', 'silent') for transport in ('tcp', 'udp', 'icmp')]
        identities += [('tcp_connect', condition, None, None)
                       for condition in ('connect-responsive', 'connect-closed')]
        for workflow, identifier, transport, window in identities:
            report['cases'].append(dict(workflow=workflow, id=identifier, family=family,
                                        transport=transport, window=window, repetition=0,
                                        status='exercised', correct=True, expected={'attempts': 1},
                                        execution='native_loopback' if workflow == 'tcp_connect' else 'injected_provider',
                                        workflow_elapsed_ns=100, work_sent=1,
                                        retained_state_charged_bytes=128, peak_process_memory_bytes=1024))
    return report


def scenario_record(scenario='responsive-many', mode='adaptive', family='ipv4'):
    config = adaptive.SCENARIOS[scenario]
    oracle = adaptive.expected(scenario, mode)
    settings = dict(config, hosts=1, max_in_flight=2, max_probes=config['ports'] * config['attempts'],
                    max_evidence_bytes=1048576)
    record = dict(schema='packetcraftr.scheduling-fixture/v1', scenario=scenario, family=family,
                  scheduling_mode=mode, execution='injected_provider_real_clock', settings=settings,
                  status=oracle['status'], work_sent=oracle['work_sent'], operation_elapsed_ns=100,
                  retained_evidence_charged_bytes=100, endpoints=oracle['endpoints'],
                  incomplete=[], conditions=[], observed_peak_window=2,
                  retries_started=oracle['work_sent'] - config['ports'])
    if oracle['status'] == 'rejected':
        record.update(error_code=oracle['error_code'], error_cause='prepared byte limit', capture_sessions=0)
    return record


class CorpusTests(unittest.TestCase):
    def test_authored_corpus_is_accepted(self):
        value, digest = benchmark.load_corpus(CORPUS)
        self.assertEqual(value['schema'], 'packetcraftr.scanner-corpus/v1')
        self.assertEqual(len(digest), 64)

    def test_boolean_numbers_cannot_impersonate_hard_settings(self):
        changes = {
            'request count': lambda c: c['request'].update(attempts=True),
            'request port': lambda c: c['request'].update(ports=[1]),
            'request window': lambda c: c['request'].update(windows=[True, 2]),
            'inference attempts': lambda c: c['inference_scenarios'][0]['request'].update(attempts=True),
            'inference ordinal': lambda c: c['inference_scenarios'][0]['endpoints'][0]['expected']['attempts'][0].update(ordinal=True),
            'inference partition': lambda c: c['inference_scenarios'][0]['endpoints'][0]['expected']['partitions'].update(supporting=[True]),
            'diagnostic settings': lambda c: c['tcp_diagnostic_scenarios'][0]['request'].update(attempts=True),
            'diagnostic partitions': lambda c: c['tcp_diagnostic_scenarios'][0]['expected'][0]['partitions'].update(supporting=[True]),
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'corpus.json'
            for label, change in changes.items():
                corpus = json.loads(CORPUS.read_text())
                change(corpus)
                path.write_text(json.dumps(corpus))
                with self.subTest(label=label), self.assertRaises(ValueError):
                    benchmark.load_corpus(path)

    def test_address_inventory_cannot_be_empty_or_omit_roles(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'corpus.json'
            for addresses in ({}, {'ipv4': {}}, {'ipv4': {}, 'ipv6': {}}):
                corpus = json.loads(CORPUS.read_text())
                corpus['fixture_addresses'] = addresses
                path.write_text(json.dumps(corpus))
                with self.subTest(addresses=addresses), self.assertRaises(ValueError):
                    benchmark.load_corpus(path)

    def test_integer_bounds_and_typed_json_equality(self):
        for value in (True, -1, 2**64, 1.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                benchmark.require_integer(value, 'test')
        self.assertEqual(benchmark.require_integer(2**64 - 1, 'test'), 2**64 - 1)
        self.assertTrue(same_json({'a': [1, True, None]}, {'a': [1, True, None]}))
        self.assertFalse(same_json({'a': [1]}, {'a': [True]}))
        self.assertFalse(same_json(1, 1.0))


class SchedulingComparisonTests(unittest.TestCase):
    def test_complete_identical_cells_are_measured(self):
        result = comparison.compare(complete_report(), complete_report('adaptive'))
        self.assertEqual(result['status'], 'measured')
        self.assertEqual(len(result['cells']), 88)
        self.assertIs(result['optimization_accepted'], False)

    def test_unknown_or_missing_aggregate_status_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            for status in (None, 'passed', 'failed', 'future'):
                value = complete_report()
                value['status'] = status
                path.write_text(json.dumps(value))
                with self.subTest(status=status), self.assertRaises(ValueError):
                    comparison.load(path)

    def test_inventory_rejects_extra_and_missing_cells(self):
        for extra in (True, False):
            report = complete_report()
            if extra:
                row = dict(report['cases'][0], id='invented')
                report['cases'].append(row)
            else:
                report['cases'].pop()
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                comparison.rows(report)

    def test_identity_types_do_not_alias_declared_cells(self):
        for change in ({'window': True}, {'id': ['unhashable']}, {'workflow': None}):
            report = complete_report()
            report['cases'][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                comparison.rows(report)

    def test_accuracy_failure_is_not_downgraded_by_missing_memory(self):
        baseline, candidate = complete_report(), complete_report('adaptive')
        candidate['cases'][0].update(correct=False, peak_process_memory_bytes=None)
        result = comparison.compare(baseline, candidate)
        self.assertEqual(result['status'], 'failed')
        self.assertTrue(any(cell.get('reason') == 'fixture accuracy failed' for cell in result['cells']))

    def test_provenance_is_present_not_merely_equal(self):
        for field, value in (('corpus_sha256', 'same-but-invalid'), ('platform', ''), ('settings', {})):
            baseline, candidate = complete_report(), complete_report('adaptive')
            baseline[field] = candidate[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                comparison.compare(baseline, candidate)

    def test_settings_and_expectation_equality_preserve_numeric_types(self):
        for location in ('settings', 'expected'):
            baseline, candidate = complete_report(), complete_report('adaptive')
            if location == 'settings':
                candidate['settings']['attempts'] = True
            else:
                candidate['cases'][0]['expected']['attempts'] = True
            with self.subTest(location=location), self.assertRaises(ValueError):
                comparison.compare(baseline, candidate)

    def test_exact_u64_latency_budget_catches_one_nanosecond_overrun(self):
        baseline, candidate = complete_report(), complete_report('adaptive')
        base = 2**63
        baseline['cases'][0]['workflow_elapsed_ns'] = base
        candidate['cases'][0]['workflow_elapsed_ns'] = base * 3 // 2 + 1_000_000
        self.assertEqual(comparison.compare(baseline, candidate)['status'], 'measured')
        candidate['cases'][0]['workflow_elapsed_ns'] += 1
        self.assertEqual(comparison.compare(baseline, candidate)['status'], 'failed')
        self.assertEqual(benchmark.median_twice([2**63, 2**63 + 1]), 2**64 + 1)
        with self.assertRaises(ValueError):
            benchmark.median_twice([])

    def test_repetitions_cannot_be_missing_duplicated_or_boolean(self):
        for changes in ({'repetitions': True}, {'repetitions': 2}):
            report = dict(complete_report(), **changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                comparison.rows(report)
        report = complete_report()
        report['cases'].append(copy.deepcopy(report['cases'][0]))
        with self.assertRaises(ValueError):
            comparison.rows(report)


class AdaptiveScenarioTests(unittest.TestCase):
    def test_all_authored_scenarios_and_modes_validate(self):
        for scenario in adaptive.SCENARIOS:
            for mode in ('fixed', 'adaptive'):
                with self.subTest(scenario=scenario, mode=mode):
                    adaptive.validate(scenario_record(scenario, mode), scenario, 'ipv4', mode)

    def test_non_object_and_boolean_fixture_fields_are_rejected(self):
        with self.assertRaises(ValueError):
            adaptive.validate([], 'responsive-many', 'ipv4', 'adaptive')
        for label in ('settings', 'attempt'):
            record = scenario_record()
            if label == 'settings': record['settings']['hosts'] = True
            else: record['endpoints']['9000']['attempts'] = [True]
            with self.subTest(label=label), self.assertRaises(ValueError):
                adaptive.validate(record, 'responsive-many', 'ipv4', 'adaptive')
        record = scenario_record('plan-retention', 'fixed')
        record['capture_sessions'] = False
        with self.assertRaises(ValueError):
            adaptive.validate(record, 'plan-retention', 'ipv4', 'fixed')

    def test_timeouts_are_retained_for_every_case(self):
        with patch.object(adaptive.measurements, 'digest', return_value='a' * 64), \
                patch.object(adaptive.measurements, 'measured', side_effect=subprocess.TimeoutExpired('fixture', 15)):
            result = adaptive.run(Path('fixture'), 1)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(len(result['cases']), 12)
        self.assertTrue(all('timed out' in row['error'] for row in result['cases']))

    def test_invalid_rss_is_a_case_failure(self):
        with patch.object(adaptive.measurements, 'digest', return_value='a' * 64), \
                patch.object(adaptive.measurements, 'measured', return_value={'peak_process_memory_bytes': True}):
            result = adaptive.run(Path('fixture'), 1)
        self.assertEqual(result['status'], 'failed')
        self.assertTrue(all('peak RSS' in row['error'] for row in result['cases']))

    def test_repetitions_are_validated_before_measurement(self):
        for repetitions in (0, 11, True):
            with patch.object(adaptive.measurements, 'digest') as digest:
                with self.subTest(repetitions=repetitions), self.assertRaises(ValueError):
                    adaptive.run(Path('fixture'), repetitions)
                digest.assert_not_called()


class ProcessMeasurementTests(unittest.TestCase):
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

    def test_exact_process_exit_stdout_stderr_and_memory(self):
        result = benchmark.measured([sys.executable, '-c', 'import sys; print("ok"); print("err", file=sys.stderr); sys.exit(7)'])
        self.assertEqual(result['exit_code'], 7)
        self.assertEqual(result['stdout'], 'ok\n')
        self.assertEqual(result['stderr'], 'err\n')
        if hasattr(os, 'wait4'):
            self.assertGreater(result['peak_process_memory_bytes'], 0)

    def test_timeout_preserves_partial_output(self):
        with patch.object(benchmark, 'PROCESS_TIMEOUT', 0.5):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                benchmark.measured([sys.executable, '-S', '-c', 'import time; print("partial", flush=True); time.sleep(10)'])
        self.assertIn('partial', caught.exception.output)

    def test_output_limit_fails_closed(self):
        with patch.object(benchmark, 'OUTPUT_LIMIT', 64), self.assertRaises(ValueError):
            benchmark.measured([sys.executable, '-c', 'print("x" * 10000)'])

    @unittest.skipUnless(os.name == 'posix', 'process groups require POSIX')
    def test_inherited_pipes_are_closed_by_descendant_cleanup(self):
        before = {thread.ident for thread in threading.enumerate()}
        command = 'import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"])'
        with self.assertRaises(ValueError):
            benchmark.measured([sys.executable, '-c', command])
        self.assertEqual({thread.ident for thread in threading.enumerate()}, before)

    def test_non_utf8_output_is_rejected(self):
        with self.assertRaises(UnicodeDecodeError):
            benchmark.measured([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(b"\\xff")'])


class ConnectComparatorTests(unittest.TestCase):
    def test_nmap_disagreement_marks_the_case_incorrect(self):
        corpus = json.loads(CORPUS.read_text())
        case = corpus['native_connect_scenarios'][0]
        fixture = MagicMock()
        fixture.__enter__.return_value.getsockname.return_value = ('127.0.0.1', 12345)
        product = dict(schema='packetcraftr.output/v1', status='success', command='scan', mode='aggregate',
                       result=dict(scheduling={'mode': 'fixed'}, method='tcp_connect', endpoints=[dict(
                           address='127.0.0.1', port=12345, classification=case['expected_classification'],
                           probes=[dict(attempted=True, outcome=case['expected_outcome'])])],
                           socket_stats=dict(connections_scheduled=1, connections_attempted=1,
                                             connections_succeeded=1, retained_evidence_bytes=100,
                                             elapsed=dict(secs=0, nanos=1))))
        xml = (f'<nmaprun version="{corpus["nmap"]["version"]}"><host><address addrtype="ipv4" addr="127.0.0.1"/>'
               '<ports><port protocol="tcp" portid="12345"><state state="closed"/></port></ports></host></nmaprun>')
        outputs = [dict(exit_code=0, stdout=json.dumps(product), stderr=''), dict(exit_code=0, stdout=xml, stderr='')]
        with patch.object(benchmark, 'fixture_socket', return_value=fixture), \
                patch.object(benchmark, 'measured', side_effect=outputs):
            result = benchmark.connect_case('binary', corpus, case, 'ipv4', 'nmap')
        self.assertIs(result['correct'], False)
        self.assertIs(result['nmap']['agrees_with_fixture'], False)
        product['mode'] = 'stream'
        with patch.object(benchmark, 'fixture_socket', return_value=fixture), \
                patch.object(benchmark, 'measured', return_value=dict(exit_code=0, stdout=json.dumps(product), stderr='')):
            with self.assertRaises(ValueError):
                benchmark.connect_case('binary', corpus, case, 'ipv4', None)


if __name__ == '__main__':
    unittest.main()
