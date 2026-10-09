# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Regression tests for discovery fixture admission and evidence closure."""
import copy
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from discovery_isolated_fixture import checksum, packet, transport
from discovery_native_evidence import inventory, validate
from discovery_native_fixture import measurements, run, validate_router_evidence
from validation_evidence import ROOT

spec = importlib.util.spec_from_file_location('discovery_launcher', pathlib.Path(__file__).with_name('test-host-discovery-native.py'))
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class DiscoveryEvidenceContracts(unittest.TestCase):
    def test_unexercised_inventory_is_honest_and_cannot_close_acceptance(self):
        report = launcher.initial_report(['portable', 'default', 'layer2', 'pcap-free', 'full-native'])
        validate(report)
        self.assertEqual(len(inventory()), 16)
        with self.assertRaises(ValueError):
            validate(report, require_complete=True)
        for mutation in ('duplicate', 'missing', 'fake_exercised', 'wrong_commit'):
            changed = copy.deepcopy(report)
            if mutation == 'duplicate':
                changed['profiles'][0]['scenarios'][1] = changed['profiles'][0]['scenarios'][0]
            elif mutation == 'missing':
                changed['profiles'][0]['scenarios'].pop()
            elif mutation == 'fake_exercised':
                changed['profiles'][0]['status'] = 'exercised'
            else:
                changed['commit'] = 'bad'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate(changed)

    def test_exercised_socket_contract_checks_targets_modes_and_evidence(self):
        report = launcher.initial_report(['portable'])
        profile = report['profiles'][0]
        profile.update(execution='privileged_native', privilege_granted=True, binary_sha256='0' * 64,
                       isolation=dict(kind='fresh_network_namespace', namespace=2, parent_namespace=1))
        case = next(row for row in profile['scenarios']
                    if row['name'] == 'connect-responsive' and row['family'] == 'ipv4')
        case.clear()
        case.update(name='connect-responsive', family='ipv4', status='exercised', runs=[])
        for mode in ('only', 'before', 'before_all'):
            scan = 'not_requested' if mode == 'only' else 'scanned'
            output = dict(schema='packetcraftr.output/v10', status='success', result=dict(
                hosts=[dict(address='127.0.0.1', discovery='responded', scan=scan,
                            reasons=[dict(kind='tcp_connected', evidence='socket', basis='direct')])],
                endpoints=[] if mode == 'only' else [{}]))
            case['runs'].append(dict(mode=mode, exit_code=0, stderr='', stdout=json.dumps(output),
                command=['fixture', '--output', 'json', 'scan', '127.0.0.1'],
                observation=dict(discovery='responded', scan=scan, reasons=['tcp_connected'],
                                 hosts=1, endpoints=0 if mode == 'only' else 1)))
        validate(report)
        for mutation in ('target', 'command', 'evidence', 'modes', 'exit'):
            changed = copy.deepcopy(report)
            observed = next(row for row in changed['profiles'][0]['scenarios']
                            if row['name'] == 'connect-responsive' and row['family'] == 'ipv4')
            output = json.loads(observed['runs'][0]['stdout'])
            if mutation == 'target':
                output['result']['hosts'][0]['address'] = '203.0.113.9'
            elif mutation == 'command':
                observed['runs'][0]['command'][4] = '203.0.113.9'
            elif mutation == 'evidence':
                output['result']['hosts'][0]['reasons'][0]['evidence'] = 'wire'
            elif mutation == 'modes':
                observed['runs'].pop()
            else:
                observed['runs'][0]['exit_code'] = None
            observed['runs'][0]['stdout'] = json.dumps(output)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate(changed)

    def test_review_binding_rejects_a_different_or_dirty_revision(self):
        report = launcher.initial_report(['full-native'])
        with self.assertRaises(ValueError):
            validate(report, expected_commit='0' * 40)
        report['dirty'] = True
        with self.assertRaises(ValueError):
            validate(report, expected_commit=report['commit'])

    def test_a_failed_or_contradictory_run_preserves_process_output(self):
        for output in ({'status': 'error', 'error': {'code': 'capability.unsupported'}},
                       {'status': 'success', 'result': {'hosts': [], 'endpoints': []}}):
            measured = dict(command=['fixture'], stdout=json.dumps(output), stderr='retained diagnostic',
                            exit_code=1 if output['status'] == 'error' else 0)
            with patch.object(measurements, 'measured', return_value=measured):
                observed = run('fixture', ['127.0.0.1'], 'only', ['--connect'], 'responded', {'tcp_refused'})
            self.assertIn('error', observed)
            self.assertEqual(observed['stdout'], json.dumps(output))
            self.assertEqual(observed['stderr'], 'retained diagnostic')

    def test_changed_sources_cannot_close_a_native_execution(self):
        report = launcher.initial_report(['portable'])
        report['dirty'] = False
        settled = copy.deepcopy(report)
        settled['fixture_sha256'] = '1' * 64
        with tempfile.TemporaryDirectory() as directory:
            destination = pathlib.Path(directory) / 'report.json'
            arguments = ['discovery', '--reviewed-commit', report['commit'], '--profiles', 'portable',
                         '--report', str(destination)]
            with patch.object(sys, 'argv', arguments), patch.object(launcher, 'execute'), \
                    patch.object(launcher, 'initial_report', side_effect=[report, settled]):
                self.assertEqual(launcher.main(), 1)
            observed = json.loads(destination.read_text())
            self.assertIn('sources or revision changed', observed['error'])

    def test_timeouts_preserve_diagnostics_without_becoming_exercised(self):
        failure = subprocess.TimeoutExpired(['fixture'], 15, output='partial stdout', stderr='partial stderr')
        with patch.object(measurements, 'measured', side_effect=failure):
            observed = run('fixture', ['127.0.0.1'], 'only', ['--connect'], 'responded', {'tcp_refused'})
        self.assertEqual(observed['stdout'], 'partial stdout')
        self.assertEqual(observed['stderr'], 'partial stderr')
        self.assertIsNone(observed['exit_code'])
        self.assertEqual(observed['error']['code'], 'fixture.timeout')
        with patch.object(launcher.subprocess, 'run', side_effect=failure):
            observed = launcher.captured(['fixture'], timeout=15)
        self.assertEqual(observed['stdout'], 'partial stdout')
        self.assertEqual(observed['stderr'], 'partial stderr')
        self.assertIsNone(observed['exit_code'])

    def test_discovery_corpus_rejects_missing_duplicate_and_single_family_conditions(self):
        corpus, _ = measurements.load_corpus(ROOT / 'docs/scanner-corpus.v1.json')
        for mutation in ('missing', 'duplicate', 'single_family'):
            changed = copy.deepcopy(corpus)
            if mutation == 'missing':
                changed['discovery_scenarios'].pop()
            elif mutation == 'duplicate':
                changed['discovery_scenarios'][1] = changed['discovery_scenarios'][0]
            else:
                changed['discovery_scenarios'][0]['families'] = ['ipv4']
            with tempfile.TemporaryDirectory() as directory:
                path = pathlib.Path(directory) / 'corpus.json'
                path.write_text(json.dumps(changed))
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    measurements.load_corpus(path)

    def test_router_silence_cannot_replace_expected_blocked_evidence(self):
        for v4, router, target, protocol in ((True, '192.0.2.254', '192.0.2.1', 1),
                                            (False, '2001:db8::ffff', '2001:db8::1', 58)):
            body = bytes((3, 13, 0, 0, 0, 0, 0, 0)) if v4 else bytes((1, 1, 0, 0, 0, 0, 0, 0))
            wire = bytes(14) + packet(router, target, protocol, transport(router, target, protocol, body, 2))
            probes = [dict(sequence=index, protocol=kind, status='response', responder=router,
                           frame=dict(link_type=1, bytes_hex=wire.hex()))
                      for index, kind in enumerate(('icmpv4' if v4 else 'icmpv6', 'tcp', 'udp'))]
            output = dict(result=dict(hosts=[dict(probes=probes)]))
            validate_router_evidence(output, v4, True)
            for field, value in (('status', 'timeout'), ('responder', target), ('protocol', 'udp')):
                changed = copy.deepcopy(output)
                changed['result']['hosts'][0]['probes'][0][field] = value
                with self.subTest(v4=v4, field=field), self.assertRaises(ValueError):
                    validate_router_evidence(changed, v4, True)
            with self.assertRaises(ValueError):
                validate_router_evidence(output, v4, False)

    def test_independent_wire_fixture_generates_valid_dual_stack_checksums(self):
        for source, destination, protocol in (('192.0.2.2', '192.0.2.1', 1),
                                               ('2001:db8::2', '2001:db8::1', 58)):
            body = transport(source, destination, protocol, bytes.fromhex('0000000000010001'), 2)
            wire = packet(source, destination, protocol, body)
            if protocol == 1:
                self.assertEqual(checksum(wire[:20]), 0)
                self.assertEqual(checksum(body), 0)
            else:
                pseudo = wire[8:40] + len(body).to_bytes(4, 'big') + bytes((0, 0, 0, 58))
                self.assertEqual(checksum(pseudo + body), 0)


if __name__ == '__main__':
    unittest.main()
