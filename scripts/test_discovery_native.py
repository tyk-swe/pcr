# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Regression tests for discovery fixture admission and evidence closure."""
import copy
import importlib.util
import json
import pathlib
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
