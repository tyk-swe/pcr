# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic validator regressions; these tests do not establish native coverage."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from discovery_isolated_fixture import packet, transport
from native_platform_evidence import PROFILES
from tcp_diagnostic_corpus import validate as validate_corpus
import tcp_diagnostic_native_evidence as evidence
import tcp_diagnostic_isolated_fixture as isolated
from tcp_diagnostic_isolated_fixture import reply
from tcp_diagnostic_wire import network, outgoing, response, tcp

ROOT = Path(__file__).resolve().parents[1]
CORPUS = json.loads((ROOT / 'docs/scanner-corpus.v1.json').read_text())
SPEC = importlib.util.spec_from_file_location('m12_runner', ROOT / 'scripts/test-tcp-diagnostics-native.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def wire(family, flags, port, identity):
    source, target = (('192.0.2.1', '192.0.2.2') if family == 'ipv4' else ('2001:db8::1', '2001:db8::2'))
    acknowledgment = (identity + 0x50435201) & 0xffffffff if flags & 16 else 0
    segment = struct.pack('!HHIIHHHH', 50000, port, identity, acknowledgment, 0x5000 | flags, 0, 0, 0)
    return bytes.fromhex('00112233445566778899aabb') + (b'\x08\x00' if family == 'ipv4' else b'\x86\xdd') + packet(source, target, 6, transport(source, target, 6, segment, 16))


def fixture_run(family='ipv4', mode='window', output='json'):
    case = next(case for case in evidence.inventory() if case['id'] == f'scripted/{family}/{mode}/1/{output}')
    target = evidence.SCRIPTED_TARGETS[family == 'ipv6']
    endpoints, probes, requests = [], [], []
    for condition in CORPUS['tcp_diagnostic_scenarios']:
        port, identity = condition['port'], condition['port'] - 1000
        sent = wire(family, case['flags'], port, identity)
        answers = reply(sent)
        row = evidence.expectation(CORPUS, condition['id'], mode)
        probe = dict(sequence=identity, stage='scan', protocol='tcp', destination=target,
                     destination_port=port, attempt=1, tcp_scan=dict(mode=mode, flags=case['flags']),
                     status=row['status'], classification=row['classification'])
        if answers:
            # Contradictory reset/error case keeps the reset as its decisive response.
            probe.update(tcp_window=row['tcp_window'], frame=dict(bytes_hex=answers[0].hex(), link_type=1,
                captured_length=len(answers[0]), original_length=len(answers[0]),
                timestamp=dict(unix_seconds=1, nanoseconds=0)))
        endpoints.append(dict(address=target, transport='tcp', port=port, classification=row['classification'],
            inference=dict(state=row['state'], rule=row['rule'], supporting=[identity], conflicting=[], unanswered=[], failed=[]),
            probes=[probe] if output == 'json' else [identity]))
        probes.append(probe)
        requests.append(dict(bytes_hex=sent.hex(), link_type=1, unix_ns=1000000000, monotonic_ns=20,
            replies=[dict(bytes_hex=answer.hex(), link_type=1, unix_ns=1000000001, monotonic_ns=21) for answer in answers]))
    result = dict(target=target, resolved_addresses=[target], plan=dict(tcp_scan=dict(mode=mode, flags=case['flags'])),
                  hosts=[dict(scan='scanned', discovery='not_requested')], endpoints=endpoints,
                  undecoded=[], retained_evidence_bytes=sum(len(item['frame']['bytes_hex']) // 2 for item in probes if 'frame' in item))
    stats = dict(packets_attempted=8, packets_completed=8, bytes=320 if family=='ipv4' else 480, capture=dict(dropped_frames=0, dropped_bytes=0, overflow_events=0))
    document = dict(schema='packetcraftr.output/v15', command='scan', mode='aggregate', status='success', result=result, diagnostics=[], stats=stats)
    if output == 'json':
        stdout = json.dumps(document)
    else:
        docs = [dict(schema=document['schema'], command='scan', mode='stream', status='success', event='probe', result=dict(target=target, probe=probe), diagnostics=[]) for probe in probes]
        docs += [dict(schema=document['schema'], command='scan', mode='stream', status='success', event='endpoint', result=dict(target=target, endpoint=endpoint), diagnostics=[]) for endpoint in endpoints]
        docs.append(dict(schema=document['schema'], command='scan', mode='stream', status='success', event='host', result=result['hosts'][0], diagnostics=[]))
        result.pop('endpoints')
        docs.append(dict(document, mode='stream', event='complete'))
        for sequence, doc in enumerate(docs):
            doc['sequence'] = sequence
        stdout = '\n'.join(map(json.dumps, docs)) + '\n'
    run = dict(command=evidence.command('/synthetic/packetcraftr', case, target, list(range(1000, 1008))),
               stdout=stdout, stderr='', exit_code=0, limits=evidence.LIMITS, link_mode='layer3', platform='Linux',
               started_unix_ns=999999999, finished_unix_ns=1000000002)
    run['observation'] = evidence.validate_output(run, case, CORPUS)
    return case, run, dict(requests=requests, setup=[dict(exit_code=0)], cleanup=dict(exit_code=0))


def kernel_run():
    case, run, _ = fixture_run()
    case = next(item for item in evidence.inventory() if item['id'] == 'kernel/ipv4/window/1/json')
    doc = json.loads(run['stdout'])
    doc['result']['target'] = '198.51.100.2'
    doc['result']['resolved_addresses'] = ['198.51.100.2']
    doc['result']['endpoints'] = [copy.deepcopy(doc['result']['endpoints'][0]) for _ in range(2)]
    capture = dict(cleanup_complete=True, backend_version='synthetic-only', filter='synthetic fixture filter',
                   frames=[], statistics=dict(received=2, dropped=0, interface_dropped=0))
    for identity, endpoint in enumerate(doc['result']['endpoints']):
        port = 43123 if identity == 0 else 43125
        source, target = '198.51.100.1', '198.51.100.2'
        segment = struct.pack('!HHIIHHHH', 50000, port, identity, identity + 0x50435201, 0x5010, 0, 0, 0)
        raw = bytes.fromhex('00112233445566778899aabb0800') + packet(source, target, 6, transport(source, target, 6, segment, 16))
        capture['frames'].append(dict(bytes_hex=raw.hex(), link_type=1, unix_ns=1000000000, monotonic_ingress_ns=20))
        reset = struct.pack('!HHIIHHHH', port, 50000, identity + 0x50435201, 0, 0x5004, 0, 0, 0)
        answer = bytes.fromhex('66778899aabb0011223344550800') + packet(target, source, 6, transport(target, source, 6, reset, 16))
        endpoint.update(address=target, port=port)
        endpoint['inference']['supporting'] = [identity]
        probe = endpoint['probes'][0]
        probe.update(sequence=identity, destination=target, destination_port=port)
        probe['frame'].update(bytes_hex=answer.hex(), captured_length=len(answer), original_length=len(answer))
    doc['result']['retained_evidence_bytes'] = 108
    doc['stats'].update(packets_attempted=2, packets_completed=2, bytes=80)
    run.update(stdout=json.dumps(doc), command=evidence.command('/synthetic/packetcraftr', case, '198.51.100.2', [43123, 43125]))
    run['observation'] = evidence.validate_output(run, case, CORPUS)
    return case, run, capture


def synthetic_report():
    report = evidence.initial('Linux', 'a' * 40, False, 'b' * 64, RUNNER.source_identity(), PROFILES,
                              'runtime_evidence_missing', 'synthetic unexecuted case')
    report['status'] = 'incomplete'
    return report


class CorpusContracts(unittest.TestCase):
    def test_complete_independent_inventory(self):
        validate_corpus(CORPUS)
        self.assertEqual(CORPUS['dataset_version'], '1.7.0')

    def test_missing_reordered_unknown_and_unbounded_rejected(self):
        for mutation in ('missing', 'reorder', 'unknown', 'budget', 'partition', 'flags'):
            corpus = copy.deepcopy(CORPUS)
            cases = corpus['tcp_diagnostic_scenarios']
            if mutation == 'missing':
                cases.pop()
            elif mutation == 'reorder':
                cases.reverse()
            elif mutation == 'unknown':
                cases[0]['unknown'] = True
            elif mutation == 'budget':
                cases[0]['request']['max_duration_ms'] = 0
            elif mutation == 'partition':
                cases[0]['expected'][0]['partitions']['supporting'] = [2]
            else:
                cases[0]['expected'][0]['flags'] = 0
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_corpus(corpus)


class IndependentWireContracts(unittest.TestCase):
    def test_all_authored_packets_both_families(self):
        for family in ('ipv4', 'ipv6'):
            for mode, flags in evidence.MODES.items():
                for condition in CORPUS['tcp_diagnostic_scenarios']:
                    port = condition['port']
                    sent = wire(family, flags, port, 0xffffffff)
                    target = evidence.SCRIPTED_TARGETS[family == 'ipv6']
                    decoded = outgoing(sent, 1, mode, flags, 0xffffffff, target, port)
                    answers = reply(sent)
                    self.assertEqual(len(answers), 0 if port == 1002 else 2 if port == 1005 else 1)
                    row = evidence.expectation(CORPUS, condition['id'], mode)
                    if answers:
                        observed, window = response(answers[0], 1, target, port, 0xffffffff, flags, decoded)
                        if observed == 'tcp_syn_ack':
                            observed = 'tcp_other'
                        self.assertEqual((observed, window), (row['reply'], row['tcp_window']))

    def test_wrong_identity_checksum_and_truncation_rejected(self):
        sent = wire('ipv4', 16, 1000, 1)
        answer = reply(sent)[0]
        for packet, identity in ((answer, 2), (answer[:-1], 1), (answer[:-1] + bytes([answer[-1] ^ 1]), 1)):
            with self.assertRaises(ValueError):
                response(packet, 1, '192.0.2.2', 1000, identity, 16)
        with self.assertRaises(ValueError):
            outgoing(sent, 1, 'ack', 0, 1, '192.0.2.2', 1000)

    def test_kernel_resets_never_create_a_reply_loop(self):
        self.assertEqual(reply(wire('ipv4', 4, 1004, 1)), [])


class EvidenceContracts(unittest.TestCase):
    def test_both_formats_and_families(self):
        for family in ('ipv4', 'ipv6'):
            for output in ('json', 'ndjson'):
                case, run, peer = fixture_run(family, output=output)
                evidence.validate_peer(dict(independent_peer=peer), case, run)
                self.assertEqual(len(run['observation']['observations']), 8)

    def test_missing_wire_partition_mode_and_budget_rejected(self):
        case, run, _ = fixture_run()
        for mutation in ('frame', 'partition', 'window', 'rule', 'flags', 'budget', 'loss', 'timestamp'):
            bad = copy.deepcopy(run)
            doc = json.loads(bad['stdout'])
            endpoint = doc['result']['endpoints'][0]
            probe = endpoint['probes'][0]
            if mutation == 'frame':
                probe.pop('frame')
            elif mutation == 'partition':
                endpoint['inference']['supporting'] = []
            elif mutation == 'window':
                probe['tcp_window'] = 9
            elif mutation == 'rule':
                endpoint['inference']['rule'] = 'tcp_window.reset_nonzero'
            elif mutation == 'flags':
                probe['tcp_scan']['flags'] = 0
            elif mutation == 'budget':
                doc['stats']['packets_attempted'] = 33
            elif mutation == 'loss':
                doc['stats']['capture']['dropped_frames'] = 1
            else:
                probe['frame'].pop('timestamp')
            bad['stdout'] = json.dumps(doc)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                evidence.validate_output(bad, case, CORPUS)

    def test_stream_sequence_and_terminal_required(self):
        case, run, _ = fixture_run(output='ndjson')
        for mutation in ('sequence', 'terminal', 'duplicate'):
            bad = copy.deepcopy(run)
            docs = [json.loads(line) for line in bad['stdout'].splitlines()]
            if mutation == 'sequence':
                docs[0]['sequence'] = 9
            elif mutation == 'terminal':
                docs.pop()
            else:
                docs.append(docs[-1])
            bad['stdout'] = '\n'.join(map(json.dumps, docs))
            with self.assertRaises(ValueError):
                evidence.validate_output(bad, case, CORPUS)

    def test_incomplete_inventory_and_false_completion_rejected(self):
        report = synthetic_report()
        self.assertFalse(evidence.validate(report, CORPUS))
        for mutation in ('inventory', 'commit', 'dirty', 'sources', 'digest', 'complete'):
            bad = copy.deepcopy(report)
            if mutation == 'inventory':
                bad['profiles'][0]['cases'].pop()
            elif mutation == 'commit':
                bad['source_revision'] = 'invalid'
            elif mutation == 'dirty':
                bad['source_dirty'] = 'false'
            elif mutation == 'sources':
                bad['sources'].pop('scripts/tcp_diagnostic_wire.py')
            elif mutation == 'digest':
                bad['corpus_digest_sha256'] = 'wrong'
            else:
                bad['acceptance_complete'] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                evidence.validate(bad, CORPUS)
        with self.assertRaises(ValueError):
            evidence.validate(report, CORPUS, require_complete=True)

    def test_independent_peer_omissions_and_changed_probes_rejected(self):
        case, run, peer = fixture_run()
        for mutation in ('missing', 'reply', 'identity', 'cleanup'):
            bad = copy.deepcopy(peer)
            if mutation == 'missing':
                bad['requests'].pop()
            elif mutation == 'reply':
                bad['requests'][0]['replies'] = []
            elif mutation == 'identity':
                bad['requests'][0]['bytes_hex'] = wire('ipv4', 0, 1000, 0).hex()
            else:
                bad['cleanup']['exit_code'] = 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                evidence.validate_peer(dict(independent_peer=bad), case, run)

    def test_timeouts_and_typed_refusals_are_not_success(self):
        case, run, _ = fixture_run()
        class Timeout:
            @staticmethod
            def measured(command):
                import subprocess
                raise subprocess.TimeoutExpired(command, 15, output=b'partial', stderr=b'bounded failure')
        result = RUNNER.execute(Path('/synthetic/packetcraftr'), case, CORPUS, Timeout())
        self.assertTrue(result['timed_out'])
        self.assertEqual(result['stdout'], 'partial')
        bad = dict(run, timed_out=True)
        with self.assertRaises(ValueError):
            evidence.validate_output(bad, case, CORPUS)
        report = synthetic_report()
        report['profiles'][0]['cases'][0]['expected_refusal'] = True
        with self.assertRaises(ValueError):
            evidence.validate(report, CORPUS)

    def test_kernel_capture_requires_every_probe_loss_free_stats_and_cleanup(self):
        case, run, capture = kernel_run()
        evidence.validate_kernel_capture(dict(kernel_capture=capture), case, run)
        self.assertEqual(run['observation']['divergences'], [dict(port=43123, socket_truth='open', inferred_state='closed', rule='tcp_window.reset_zero')])
        for mutation in ('missing', 'loss', 'cleanup', 'flags', 'identity'):
            bad = copy.deepcopy(capture)
            if mutation == 'missing':
                bad['frames'].pop()
            elif mutation == 'loss':
                bad['statistics']['dropped'] = 1
            elif mutation == 'cleanup':
                bad['cleanup_complete'] = False
            else:
                segment = tcp(network(bytes.fromhex(bad['frames'][0]['bytes_hex']), 1))
                segment['flags' if mutation == 'flags' else 'sequence'] = 0 if mutation == 'flags' else 3
                body = struct.pack('!HHIIHHHH', 50000, 43123, segment['sequence'], segment['ack'], 0x5000 | segment['flags'], 0, 0, 0)
                bad['frames'][0]['bytes_hex'] = (bytes.fromhex('00112233445566778899aabb0800') + packet('198.51.100.1', '198.51.100.2', 6, transport('198.51.100.1', '198.51.100.2', 6, body, 16))).hex()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                evidence.validate_kernel_capture(dict(kernel_capture=bad), case, run)

    def test_exact_source_and_corpus_bindings(self):
        report = synthetic_report()
        self.assertFalse(evidence.validate(report, CORPUS, expected_sources=report['sources'], expected_corpus_digest=report['corpus_digest_sha256']))
        with self.assertRaises(ValueError):
            evidence.validate(report, CORPUS, expected_sources={})
        with self.assertRaises(ValueError):
            evidence.validate(report, CORPUS, expected_corpus_digest='c' * 64)

    def test_failed_case_cannot_be_complete_with_a_stale_refusal_flag(self):
        report = synthetic_report()
        for profile in report['profiles']:
            for case in profile['cases']:
                case['expected_refusal'] = True
        # Even before proof validation, a retained failure must disqualify completion.
        case = report['profiles'][0]['cases'][0]
        case.update(status='failed', message='actual execution failed after a prior refusal')
        self.assertFalse(evidence.coverage_complete(report))

    def test_only_verified_typed_refusals_count_as_expected_coverage(self):
        report = synthetic_report()
        profile = report['profiles'][0]
        profile.update(binary='/synthetic/packetcraftr', binary_digest_sha256='d' * 64,
                       execution='privileged_native', privilege_granted=True)
        case = profile['cases'][0]
        _, run, _ = fixture_run(mode='ack')
        run.pop('observation')
        run.update(exit_code=2, stdout=json.dumps(dict(schema='packetcraftr.output/v15', command='scan', mode='aggregate', status='error', error=dict(code='capability.unsupported', message='synthetic disabled capability'))))
        case.update(run=run, expected_refusal=True, reason='unsupported_capability')
        self.assertFalse(evidence.validate(report, CORPUS))
        for mutation in ('exit', 'code', 'command', 'digest', 'privilege', 'label'):
            bad = copy.deepcopy(report)
            profile, case = bad['profiles'][0], bad['profiles'][0]['cases'][0]
            if mutation == 'exit':
                case['run']['exit_code'] = 0
            elif mutation == 'code':
                doc = json.loads(case['run']['stdout']);doc['error']['code']='io.capture_open';case['run']['stdout']=json.dumps(doc)
            elif mutation == 'command':
                case['run']['command'][4] = '192.0.2.99'
            elif mutation == 'digest':
                profile['binary_digest_sha256'] = 'invalid'
            elif mutation == 'privilege':
                profile['privilege_granted'] = False
            else:
                case['expected_refusal'] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                evidence.validate(bad, CORPUS)

    def test_partial_fixture_setup_always_deletes_the_created_link(self):
        calls = []
        def command(*args):
            calls.append(args)
            if args[:4] == ('ip', 'link', 'set', isolated.SCANNER):
                raise RuntimeError('injected setup failure')
            return dict(command=list(args), exit_code=0, stdout='', stderr='')
        trace = dict(requests=[], setup=[])
        with patch.object(isolated, 'command', side_effect=command), self.assertRaises(RuntimeError):
            with isolated.provision(trace):
                self.fail('partial provision must not become ready')
        self.assertIn(('ip', 'link', 'delete', isolated.SCANNER), calls)
        self.assertEqual(trace['error'], 'injected setup failure')
        self.assertEqual(trace['cleanup']['exit_code'], 0)

    def test_build_timeout_retains_partial_diagnostics(self):
        class Timeout:
            @staticmethod
            def measured(command):
                raise subprocess.TimeoutExpired(command, 900, output='partial compiler', stderr='build deadline')
        with tempfile.TemporaryDirectory() as directory, patch.object(RUNNER, 'measurements', return_value=Timeout):
            report_path = Path(directory) / 'report.json'
            with self.assertRaises(RuntimeError):
                RUNNER.build('layer2', report_path)
            record = json.loads((report_path.parent / 'tcp-diagnostics-build-layer2.json').read_text())
            self.assertTrue(record['timed_out'])
            self.assertEqual(record['stdout'], 'partial compiler')
            self.assertEqual(record['stderr'], 'build deadline')
            self.assertIn('--locked', record['command'])

    def test_dirty_revision_and_missing_privilege_preserve_unavailable_inventory(self):
        for dirty, reason in ((True, 'runtime_evidence_missing'), (False, 'privilege_not_granted')):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'native.json'
                def git(*args):
                    return 'a' * 40 if args == ('rev-parse', 'HEAD') else 'modified' if dirty else ''
                args = ['runner', '--reviewed-commit', 'a' * 40, '--report', str(path)]
                with patch.object(sys, 'argv', args), patch.object(RUNNER, 'git', side_effect=git), patch.object(RUNNER, 'privileged', return_value=False), patch.object(RUNNER, 'run_profile') as execute:
                    self.assertEqual(RUNNER.main(), 1)
                    execute.assert_not_called()
                report = json.loads(path.read_text())
                self.assertEqual(report['source_dirty'], dirty)
                self.assertFalse(report['acceptance_complete'])
                self.assertTrue(report.get('launcher_error'))
                self.assertTrue(all(case['status'] == 'unavailable' and case['reason'] == reason for profile in report['profiles'] for case in profile['cases']))

    def test_heuristic_divergence_keeps_socket_truth_separate(self):
        row = evidence.observed_expectation(CORPUS, 'window', 'tcp_reset', 0)
        self.assertEqual(row['state'], 'closed')
        self.assertEqual(row['rule'], 'tcp_window.reset_zero')
        self.assertEqual(evidence.observed_expectation(CORPUS, 'fin', None, None)['state'], 'open_or_filtered')
        with self.assertRaises(ValueError):
            evidence.observed_expectation(CORPUS, 'syn', None, None)


if __name__ == '__main__':
    unittest.main()
