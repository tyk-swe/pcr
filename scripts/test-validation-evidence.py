#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Failure-path contracts for release evidence and architecture checks."""
import copy
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import shlex
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from validation_evidence import (
    DECODE_FIELDS, DECODE_PROFILES, EVIDENCE_VERSION, NATIVE_SCENARIOS,
    checksum, digest, provenance, tshark_matches,
)

ROOT = pathlib.Path(__file__).resolve().parent
COMMIT = 'a' * 40
DECODER = 'decode-oracle-evidence'
NATIVE = 'native-isolated-evidence'


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f'{name}.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


release = module('check-release-evidence')
architecture = module('check-architecture')
oracle = module('check-decode-oracle')
native = module('test-native-isolated')
manifest = module('build-manifest')


def provenance_report():
    return dict(schema_version=EVIDENCE_VERSION, commit=COMMIT, dirty=False,
                binary_sha256='c' * 64, binary_version='packetcraftr 0.5.0-beta.3')


def base_report():
    return dict(provenance_report(), status='passed')


def native_report():
    return dict(base_report(), namespace=2, parent_namespace=1, native_test_sha256='d' * 64,
                namespace_launcher=dict(exit_code=0),
                scenarios=[dict(name=name, status='passed', exit_code=0) for name in NATIVE_SCENARIOS])


def decoder_report(profile='pull-request'):
    return dict(base_report(), expected_tshark='4.6.4', tshark='TShark (Wireshark) 4.6.4.',
                tshark_sha256='e' * 64, profile=profile, fields=[field[2] for field in DECODE_FIELDS],
                captures=[dict(name=name, frames=count, sha256='f' * 64, status='passed', mismatches=0)
                          for name, count in DECODE_PROFILES[profile].items()], mismatches=[],
                tls_ja3=dict(capture='tls-handshake', expected=['1' * 32], observed=['1' * 32]))


def physical_frames(data):
    """Count records in the producer's little-endian PCAP/PCAPNG fixtures only."""
    pcap = data[:4] == bytes.fromhex('d4c3b2a1')
    if not pcap and data[:4] != bytes.fromhex('0a0d0d0a'):
        raise AssertionError('unexpected fixture format')
    cursor, count = (24, 0) if pcap else (0, 0)
    while cursor < len(data):
        if pcap:
            size = 16 + struct.unpack_from('<I', data, cursor + 8)[0]
            count += 1
        else:
            kind, size = struct.unpack_from('<II', data, cursor)
            assert size >= 12 and size % 4 == 0
            assert struct.unpack_from('<I', data, cursor + size - 4)[0] == size
            count += kind in (2, 3, 6)
        assert cursor + size <= len(data)
        cursor += size
    assert cursor == len(data)
    return count


class EvidenceTests(unittest.TestCase):
    def reject(self, report, kind):
        with self.assertRaises(ValueError):
            release.validate(report, COMMIT, kind)

    def test_complete_reports_and_reordered_inventories_pass(self):
        for kind, report in [(NATIVE, native_report()), (DECODER, decoder_report()),
                             (DECODER, decoder_report('full'))]:
            with self.subTest(kind=kind, profile=report.get('profile')):
                release.validate(report, COMMIT, kind)
                report['scenarios' if kind == NATIVE else 'captures'].reverse()
                if kind == DECODER:
                    report['fields'].reverse()
                release.validate(report, COMMIT, kind)

    def test_common_fields_are_required_and_typed(self):
        for kind, factory in [(NATIVE, native_report), (DECODER, decoder_report)]:
            for key in ['schema_version', 'status', 'commit', 'dirty', 'binary_sha256']:
                with self.subTest(kind=kind, missing=key):
                    report = factory()
                    del report[key]
                    self.reject(report, kind)
            for key, values in {
                'schema_version': [None, True, '1', 1.0, 0, 2],
                'status': [None, 'failed', 'skipped', 'unsupported'],
                'commit': [None, 'b' * 40],
                'dirty': [None, True, 0, 'false'],
                'binary_sha256': [None, [], 1, '', 'c' * 63, 'c' * 65, 'g' * 64],
            }.items():
                for value in values:
                    with self.subTest(kind=kind, key=key, value=value):
                        self.reject(dict(factory(), **{key: value}), kind)
            for invalid in [None, [], '', 1, True]:
                with self.subTest(kind=kind, report=invalid):
                    self.reject(invalid, kind)
        self.reject(base_report(), 'unknown-evidence')

    def test_native_namespace_ids_must_both_be_positive_distinct_integers(self):
        for key in ['namespace', 'parent_namespace']:
            report = native_report()
            del report[key]
            self.reject(report, NATIVE)
            for value in [None, False, True, 0, -1, 2.0, '2', [], {}]:
                with self.subTest(key=key, value=value):
                    self.reject(dict(native_report(), **{key: value}), NATIVE)
        report = native_report()
        report['namespace'] = report['parent_namespace']
        self.reject(report, NATIVE)

    def test_native_scenarios_cannot_be_missing_duplicated_skipped_or_failed(self):
        valid = native_report()
        scenarios = valid['scenarios']
        for value in [None, {}, [], scenarios[:-1], scenarios + scenarios[:1],
                      scenarios[:-1] + scenarios[:1], [None] * len(scenarios)]:
            with self.subTest(scenarios=value):
                self.reject(dict(valid, scenarios=value), NATIVE)
        report = native_report()
        del report['scenarios']
        self.reject(report, NATIVE)
        for index in range(len(scenarios)):
            for key, values in {'name': [None, [], 'unrecognized'],
                                'status': [None, 'not_exercised', 'failed'],
                                'exit_code': [None, False, '0', 0.0, 1]}.items():
                report = native_report()
                del report['scenarios'][index][key]
                self.reject(report, NATIVE)
                for value in values:
                    with self.subTest(index=index, key=key, value=value):
                        report = native_report()
                        report['scenarios'][index][key] = value
                        self.reject(report, NATIVE)

    def test_native_requires_test_identity_and_successful_launcher(self):
        for key, values in {
            'native_test_sha256': [None, False, 'bad', []],
            'namespace_launcher': [None, [], {}, dict(exit_code=1), dict(exit_code=False),
                                   dict(exit_code=0.0), dict(exit_code='0')],
        }.items():
            report = native_report()
            del report[key]
            self.reject(report, NATIVE)
            for value in values:
                with self.subTest(key=key, value=value):
                    self.reject(dict(native_report(), **{key: value}), NATIVE)

    def test_decoder_top_level_contract_is_complete(self):
        for key in ['expected_tshark', 'tshark', 'tshark_sha256', 'profile', 'fields',
                    'captures', 'mismatches', 'tls_ja3']:
            with self.subTest(missing=key):
                report = decoder_report()
                del report[key]
                self.reject(report, DECODER)
        for key, values in {
            'expected_tshark': [None, 'other', '4.6.40'],
            'tshark': [None, 123, 'Wireshark 4.6.4', 'TShark (Wireshark) 4.6.40.',
                       'TShark (Wireshark) 4.6.5 (mentions 4.6.4)', 'TShark (Wireshark) 4.6.4rc1'],
            'tshark_sha256': [None, [], 'bad'],
            'profile': [None, [], {}, 'unknown'],
            'fields': [None, {}, [], [None] * len(DECODE_FIELDS)],
            'captures': [None, {}, [], [dict(status='passed')]],
            'mismatches': [None, False, {}, [dict(field='tcp.seq_raw')]],
            'tls_ja3': [None, [], {}],
        }.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    self.reject(dict(decoder_report(), **{key: value}), DECODER)

    def test_decoder_fields_cannot_be_omitted_duplicated_or_replaced(self):
        report = decoder_report()
        fields = report['fields']
        for index in range(len(fields)):
            for value in [fields[:index] + fields[index + 1:], fields + [fields[index]],
                          fields[:index] + ['unexpected'] + fields[index + 1:]]:
                with self.subTest(index=index, fields=value):
                    self.reject(dict(report, fields=value), DECODER)
        self.reject(dict(report, fields=fields[:-1] + fields[:1]), DECODER)

    def test_every_capture_in_each_profile_requires_complete_consistent_results(self):
        for profile in DECODE_PROFILES:
            valid = decoder_report(profile)
            for index in range(len(valid['captures'])):
                with self.subTest(profile=profile, index=index):
                    report = decoder_report(profile)
                    report['captures'].pop(index)
                    self.reject(report, DECODER)
                    report = decoder_report(profile)
                    report['captures'].append(copy.deepcopy(report['captures'][index]))
                    self.reject(report, DECODER)
                for key, values in {
                    'name': [None, [], 'unexpected'], 'status': [None, 'failed', 'not_exercised'],
                    'sha256': [None, [], 'bad'], 'frames': [None, True, 0, -1, '9', 9.0, 999999],
                    'mismatches': [None, False, '0', 0.0, -1, 1],
                }.items():
                    report = decoder_report(profile)
                    del report['captures'][index][key]
                    self.reject(report, DECODER)
                    for value in values:
                        with self.subTest(profile=profile, index=index, key=key, value=value):
                            report = decoder_report(profile)
                            report['captures'][index][key] = value
                            self.reject(report, DECODER)
            report = decoder_report(profile)
            report['captures'][-1] = copy.deepcopy(report['captures'][0])
            self.reject(report, DECODER)
        self.reject(dict(decoder_report(), profile='full'), DECODER)

    def test_ja3_comparison_must_be_named_nonempty_well_formed_and_equal(self):
        for key, values in {
            'capture': [None, 'spec-vectors'],
            'expected': [None, [], '', ['bad'], ['1' * 32, '1' * 32], [None]],
            'observed': [None, [], '1' * 32, ['2' * 32], ['1' * 32, '1' * 32]],
        }.items():
            report = decoder_report()
            del report['tls_ja3'][key]
            self.reject(report, DECODER)
            for value in values:
                with self.subTest(key=key, value=value):
                    report = decoder_report()
                    report['tls_ja3'][key] = value
                    self.reject(report, DECODER)
        for values in [[], ['bad'], ['1' * 32, '1' * 32]]:
            report = decoder_report()
            report['tls_ja3'].update(expected=values, observed=values)
            self.reject(report, DECODER)

    def test_tshark_version_matches_the_product_version_not_incidental_text(self):
        for identity in ['TShark (Wireshark) 4.6.4', 'TShark (Wireshark) 4.6.4.',
                         'TShark (Wireshark) 4.6.4 (Git v4.6.4 packaged as 4.6.4-1).']:
            self.assertTrue(tshark_matches(identity))
        for identity in ['not-tshark 4.6.4', 'TShark (Wireshark) 4.6.40',
                         'TShark (Wireshark) 4.6.4.1', 'TShark (Wireshark) 4.6.4rc1',
                         'TShark (Wireshark) 4.6.5 (4.6.4)', None, [], 123]:
            with self.subTest(identity=identity):
                self.assertFalse(tshark_matches(identity))

    def test_provenance_versions_both_producers_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = pathlib.Path(directory) / 'fixture-binary'
            binary.write_bytes(b'evidence-fixture')
            with mock.patch('validation_evidence.subprocess.check_output',
                            side_effect=[COMMIT + '\n', b'', 'packetcraftr fixture\n']):
                report = provenance(binary)
        self.assertEqual(report['schema_version'], EVIDENCE_VERSION)
        self.assertIs(report['dirty'], False)
        self.assertTrue(release.valid_digest(report['binary_sha256']))
        self.assertEqual(report['commit'], COMMIT)

    def test_generated_corpus_matches_declared_profile_frame_counts(self):
        for full, profile in [(False, 'pull-request'), (True, 'full')]:
            with self.subTest(profile=profile):
                captures = oracle.capture_inputs(full)
                self.assertEqual(len(captures), len(DECODE_PROFILES[profile]))
                self.assertEqual({name: physical_frames(data) for name, data in captures},
                                 DECODE_PROFILES[profile])
        self.assertEqual(len(DECODE_FIELDS), 21)
        self.assertEqual(len({field[2] for field in DECODE_FIELDS}), 21)

    def test_decoder_producer_emits_accepted_reports_with_mocked_tools(self):
        """Exercise report production, not decoder correctness or live tools."""
        for full in [False, True]:
            def output(command, **kwargs):
                if command[-1] == '--version':
                    return 'TShark (Wireshark) 4.6.4.\n'
                if 'ndjson' in command:
                    count = physical_frames(pathlib.Path(command[-2]).read_bytes())
                    frame = dict(event='frame', result=dict(decoded=dict(packet=dict(layers=[
                        dict(protocol='ipv4', fields={
                            'source': dict(value='192.0.2.1'),
                            'more_fragments': dict(value=False), 'fragment_offset': dict(value=0),
                        }),
                    ]))))
                    return b'\n'.join(json.dumps(record).encode() for record in [frame] * count + [dict(event='complete')])
                return json.dumps(dict(result=dict(sessions=[dict(client=dict(ja3='1' * 32))]))).encode()

            def tshark(data, fields, binary='tshark'):
                if fields == ['tls.handshake.ja3']:
                    return ['1' * 32]
                row = '\t'.join('192.0.2.1' if field == 'ip.src' else '0' if field == 'ip.frag_offset' else ''
                                for field in fields)
                return [row] * physical_frames(data)

            with self.subTest(full=full), tempfile.TemporaryDirectory() as directory:
                report_path = pathlib.Path(directory) / 'report.json'
                argv = ['check-decode-oracle', '--binary', 'fixture-binary', '--report', str(report_path)]
                if full:
                    argv.append('--full')
                with (mock.patch('sys.argv', argv), mock.patch.object(oracle, 'provenance', return_value=provenance_report()),
                      mock.patch.object(oracle, 'digest', return_value='d' * 64), mock.patch.object(oracle, 'tshark', side_effect=tshark),
                      mock.patch.object(oracle.subprocess, 'check_output', side_effect=output), mock.patch('builtins.print')):
                    self.assertEqual(oracle.main(), 0)
                report = json.loads(report_path.read_text())
                release.validate(report, COMMIT, DECODER)

    def test_producers_mark_incomplete_success_reports_failed_before_publication(self):
        for producer, factory, key in [(oracle, decoder_report, 'fields'),
                                       (oracle, decoder_report, 'tls_ja3'),
                                       (native, native_report, 'parent_namespace'),
                                       (native, native_report, 'namespace_launcher')]:
            with self.subTest(producer=producer.__name__, missing=key), tempfile.TemporaryDirectory() as directory:
                path = pathlib.Path(directory) / 'report.json'
                report = factory()
                del report[key]

                def produce(args, destination):
                    destination.update(report)
                    destination.pop(key, None)

                argv = ['producer', '--binary', 'fixture-binary', '--report', str(path)]
                action = 'compare' if producer is oracle else 'run'
                with (mock.patch('sys.argv', argv), mock.patch.object(producer, action, side_effect=produce),
                      mock.patch('builtins.print')):
                    self.assertEqual(producer.main(), 1)
                written = json.loads(path.read_text())
                self.assertEqual(written['status'], 'failed')
                self.assertIn('error', written)

    def test_explicit_local_decoder_version_does_not_weaken_release_pin(self):
        report = decoder_report()
        report.update(expected_tshark='4.6.5', tshark='TShark (Wireshark) 4.6.5.')
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'report.json'
            argv = ['oracle', '--binary', 'fixture-binary', '--report', str(path), '--tshark-version', '4.6.5']
            with (mock.patch('sys.argv', argv), mock.patch.object(oracle, 'compare',
                  side_effect=lambda args, destination: destination.update(report)), mock.patch('builtins.print')):
                self.assertEqual(oracle.main(), 0)
            self.reject(json.loads(path.read_text()), DECODER)

    def test_native_producer_emits_accepted_report_with_mocked_namespace_and_tools(self):
        """Exercise parent/child report handoff without invoking unshare or networking."""
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'native.json'
            argv = ['native', '--binary', 'fixture-binary', '--native-test-binary', 'fixture-tests', '--report', str(path)]
            original_stat = native.os.stat
            namespaces = iter([mock.Mock(st_ino=1), mock.Mock(st_ino=2)])

            def run(command, **kwargs):
                if command[0] == 'unshare':
                    child = copy.deepcopy(argv)
                    child += ['--parent-namespace', '1', '--run-id', command[command.index('--run-id') + 1]]
                    with mock.patch('sys.argv', child):
                        self.assertEqual(native.main(), 0)
                return subprocess.CompletedProcess(command, 0, stdout='', stderr='')

            def output(command, **kwargs):
                if command[0] == 'ip':
                    return '[{"ifname":"lo"}]'
                return '\n'.join(f'{name}: test' for name in native.SCENARIOS)

            def exchange(binary, scenario):
                scenario.update(status='passed', exit_code=0)

            with (mock.patch('sys.argv', argv), mock.patch.object(native, 'provenance', return_value=provenance_report()),
                  mock.patch.object(native, 'digest', return_value='d' * 64), mock.patch.object(native, 'exchange', side_effect=exchange),
                  mock.patch.object(native.platform, 'system', return_value='Linux'), mock.patch.object(native.os, 'geteuid', return_value=1000),
                  mock.patch.object(native.os, 'stat', side_effect=lambda *args, **kwargs: original_stat(*args, **kwargs)
                                    if str(args[0]) != '/proc/self/ns/net' else next(namespaces)),
                  mock.patch.object(native.subprocess, 'check_output', side_effect=output),
                  mock.patch.object(native.subprocess, 'run', side_effect=run), mock.patch('builtins.print')):
                self.assertEqual(native.main(), 0)
            release.validate(json.loads(path.read_text()), COMMIT, NATIVE)

    def test_release_preflight_validates_downloaded_reports_before_publishing(self):
        for invalid in [False, True]:
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as directory:
                output = pathlib.Path(directory)
                for kind, report in [(DECODER, decoder_report()), (NATIVE, native_report())]:
                    if invalid and kind == NATIVE:
                        del report['parent_namespace']
                    artifact = output / kind
                    artifact.mkdir()
                    (artifact / release.REQUIRED[kind]).write_text(json.dumps(report))
                argv = ['release', '--repository', 'owner/repo', '--commit', COMMIT, '--output', str(output)]
                runs = json.dumps(dict(workflow_runs=[dict(id=1, html_url='ci-run-1'), dict(id=2, html_url='ci-run-2')]))
                with (mock.patch('sys.argv', argv), mock.patch.object(release.subprocess, 'check_output', return_value=runs) as listing,
                      mock.patch.object(release.subprocess, 'run') as download, mock.patch('builtins.print')):
                    if invalid:
                        with self.assertRaises(ValueError):
                            release.main()
                        self.assertFalse((output / 'VALIDATION-EVIDENCE.json').exists())
                    else:
                        release.main()
                        evidence = json.loads((output / 'VALIDATION-EVIDENCE.json').read_text())
                        self.assertEqual(evidence['commit'], COMMIT)
                        self.assertEqual(evidence['ci_run'], 'ci-run-2')
                        self.assertEqual(set(evidence['reports']), set(release.REQUIRED))
                    self.assertIn(f'head_sha={COMMIT}', listing.call_args.args[0])
                    self.assertIn('event=push', listing.call_args.args[0])
                    self.assertIn('status=success', listing.call_args.args[0])
                    self.assertEqual(download.call_count, 2)
                    self.assertTrue(all(call.args[0][3] == '2' for call in download.call_args_list))

    def test_metadata_checks_optional_and_target_specific_production_edges(self):
        metadata = dict(workspace_members=['core'], packages=[dict(id='core', name='packetcraftr-core',
            dependencies=[dict(name='serde', kind=None)])])
        self.assertEqual(architecture.validate(metadata), [])
        for child in ['packetcraftr-netio', 'packetcraftr', 'pcap', 'tokio']:
            changed = copy.deepcopy(metadata)
            changed['packages'][0]['dependencies'].append(dict(name=child, kind=None, optional=True, target='cfg(unix)'))
            self.assertTrue(architecture.validate(changed))

    def test_cargo_metadata_is_time_bounded(self):
        with mock.patch.object(architecture.subprocess, 'check_output',
                               side_effect=subprocess.TimeoutExpired('cargo metadata', 60)):
            with self.assertRaises(SystemExit) as raised:
                architecture.main()
        self.assertIn('cargo metadata', str(raised.exception))
        with mock.patch.object(architecture.subprocess, 'check_output',
                               side_effect=subprocess.CalledProcessError(1, 'cargo metadata')):
            with self.assertRaises(subprocess.CalledProcessError):
                architecture.main()

    def test_release_gh_calls_are_time_bounded(self):
        expired = subprocess.TimeoutExpired('gh api', 60)
        argv = ['release', '--repository', 'owner/repo', '--commit', COMMIT, '--output', 'unused']
        with (mock.patch('sys.argv', argv),
              mock.patch.object(release.subprocess, 'check_output', side_effect=expired)):
            with self.assertRaises(SystemExit) as raised:
                release.main()
        self.assertIn('run lookup', str(raised.exception))
        runs = json.dumps(dict(workflow_runs=[dict(id=1, html_url='ci-run-1')]))
        with tempfile.TemporaryDirectory() as directory:
            argv[-1] = directory
            with (mock.patch('sys.argv', argv),
                  mock.patch.object(release.subprocess, 'check_output', return_value=runs),
                  mock.patch.object(release.subprocess, 'run',
                                    side_effect=subprocess.TimeoutExpired('gh run download', 300))):
                with self.assertRaises(SystemExit) as raised:
                    release.main()
        self.assertIn('decode-oracle-evidence', str(raised.exception))

    def test_provenance_git_calls_are_time_bounded(self):
        with mock.patch('validation_evidence.subprocess.check_output',
                        side_effect=subprocess.TimeoutExpired('git', 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                provenance(pathlib.Path('unused'))
        with mock.patch('validation_evidence.subprocess.check_output',
                        side_effect=subprocess.CalledProcessError(128, 'git rev-parse')):
            with self.assertRaises(subprocess.CalledProcessError):
                provenance(pathlib.Path('unused'))

    def test_checksum_matches_rfc_1071_and_folds_valid_headers_to_zero(self):
        self.assertEqual(checksum(bytes.fromhex('0001f203f4f5f6f7')), 0x220d)
        self.assertEqual(checksum(b''), 0xffff)
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20, 7, 0, 64, 17, 0,
                             bytes([192, 0, 2, 1]), bytes([198, 51, 100, 2]))
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
        self.assertEqual(checksum(header), 0)

    def test_checksum_pads_odd_length_input_with_a_zero_byte(self):
        self.assertEqual(checksum(b'\x01\x02\x03'), checksum(b'\x01\x02\x03\x00'))

    def test_digest_hashes_files_larger_than_one_read_block(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'large'
            data = bytes(range(256)) * 1000 + b'tail'
            path.write_bytes(data)
            self.assertEqual(digest(path), hashlib.sha256(data).hexdigest())
            path.write_bytes(b'')
            self.assertEqual(digest(path), hashlib.sha256().hexdigest())


def fake_versions(command, **kwargs):
    if command[0] == 'rustc':
        return 'rustc 1.98.1 (fixture 2026-09-01)\n'
    return 'packetcraftr 9.9.9\n'


class ManifestTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='manifest fixture ')
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.binary = self.root / 'fixture binary'
        self.binary.write_bytes(b'fixture binary bytes')
        self.document = dict(
            commit=COMMIT, target='x86_64-fixture', feature_variant='pcap-free',
            rustc='rustc 1.98.1 (fixture 2026-09-01)', version='packetcraftr 9.9.9',
            binary=self.binary.name, binary_sha256=digest(self.binary))
        self.path = self.root / 'BUILD-METADATA.json'

    def run_manifest(self, *args):
        manifest.main([str(arg) for arg in args])

    def write_manifest(self, document=None):
        self.path.write_text(json.dumps(self.document if document is None else document),
                             encoding='utf-8')
        return self.path

    def test_import_performs_no_parsing_io_or_subprocess(self):
        with (mock.patch('sys.argv', ['build-manifest.py', '--binary', '/nonexistent',
                                      '--output', '/nonexistent/out.json']),
              mock.patch('subprocess.check_output') as calls):
            module('build-manifest')
        calls.assert_not_called()

    def test_write_emits_complete_identity_document_with_bounded_commands(self):
        output = self.root / 'nested out' / 'BUILD-METADATA.json'
        output.parent.mkdir()
        with mock.patch.object(manifest.subprocess, 'check_output',
                               side_effect=fake_versions) as calls:
            self.run_manifest('--binary', self.binary, '--output', output,
                              '--commit', COMMIT, '--target', 'x86_64-fixture',
                              '--variant', 'pcap-free')
        self.assertEqual(json.loads(output.read_text(encoding='utf-8')), self.document)
        self.assertEqual({call.kwargs.get('timeout') for call in calls.call_args_list},
                         {manifest.COMMAND_TIMEOUT})

    def test_write_requires_complete_release_metadata(self):
        with mock.patch('sys.stderr', io.StringIO()):
            for args in [
                ('--commit', COMMIT, '--target', 't', '--variant', 'v'),
                ('--output', self.root / 'm.json', '--target', 't', '--variant', 'v'),
            ]:
                with self.assertRaises(SystemExit) as raised:
                    self.run_manifest('--binary', self.binary, *args)
                self.assertEqual(raised.exception.code, 2)

    def test_output_and_verify_modes_are_mutually_exclusive(self):
        with (mock.patch('sys.stderr', io.StringIO()),
              self.assertRaises(SystemExit) as raised):
            self.run_manifest('--binary', self.binary, '--output', self.root / 'a.json',
                              '--verify', self.root / 'b.json')
        self.assertEqual(raised.exception.code, 2)

    def test_verify_accepts_matching_metadata_with_or_without_expectations(self):
        path = self.write_manifest()
        with mock.patch.object(manifest.subprocess, 'check_output', side_effect=fake_versions):
            self.run_manifest('--binary', self.binary, '--verify', path,
                              '--commit', COMMIT, '--target', 'x86_64-fixture',
                              '--variant', 'pcap-free')
            self.run_manifest('--binary', self.binary, '--verify', path)

    def test_verify_rejects_wrong_expected_metadata(self):
        path = self.write_manifest()
        for flag, value in [('--commit', 'b' * 40), ('--target', 'other'),
                            ('--variant', 'all-features')]:
            with self.subTest(flag=flag):
                with (mock.patch.object(manifest.subprocess, 'check_output',
                                        side_effect=fake_versions),
                      self.assertRaises(SystemExit) as raised):
                    self.run_manifest('--binary', self.binary, '--verify', path, flag, value)
                self.assertIn('does not match release metadata', str(raised.exception))

    def test_verify_rejects_digest_and_version_drift(self):
        path = self.write_manifest()
        with mock.patch.object(manifest.subprocess, 'check_output', side_effect=fake_versions):
            self.binary.write_bytes(b'other bytes')
            with self.assertRaises(SystemExit) as raised:
                self.run_manifest('--binary', self.binary, '--verify', path)
            self.assertIn('binary does not match', str(raised.exception))
            self.binary.write_bytes(b'fixture binary bytes')
        with (mock.patch.object(manifest.subprocess, 'check_output',
                                return_value='packetcraftr 0.0.0\n'),
              self.assertRaises(SystemExit) as raised):
            self.run_manifest('--binary', self.binary, '--verify', path)
        self.assertIn('version does not match', str(raised.exception))

    def test_verify_reports_malformed_missing_and_mistyped_metadata(self):
        missing = dict(self.document)
        del missing['binary_sha256']
        cases = [
            ('{', 'not valid JSON'),
            ('[1]', 'must contain a JSON object'),
            (json.dumps(missing), 'missing required field binary_sha256'),
            (json.dumps(dict(self.document, version=123)), 'field version must be a string'),
        ]
        for text, message in cases:
            self.path.write_text(text, encoding='utf-8')
            with self.subTest(message=message), self.assertRaises(SystemExit) as raised:
                self.run_manifest('--binary', self.binary, '--verify', self.path)
            self.assertIn(message, str(raised.exception))

    def test_unreadable_binary_reports_a_diagnostic(self):
        with self.assertRaises(SystemExit) as raised:
            self.run_manifest('--binary', self.root / 'missing', '--verify', self.write_manifest())
        self.assertIn('cannot read binary', str(raised.exception))


class ExternalConsumerManifestTests(unittest.TestCase):
    def test_checkout_paths_roundtrip_through_utf8_toml(self):
        import tomllib

        consumer = module('check-external-consumer')
        checkouts = ['plain checkout', 'checkout é', 'checkout \U0001f980',
                     'checkout \x7f\U0001f980']
        if os.name != 'nt':
            checkouts.append('checkout "\\u007f" \U0001f980')
        for checkout in checkouts:
            with self.subTest(checkout=checkout):
                with tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory) / checkout
                    source = root / 'examples/consumers/rust/composition.rs'
                    source.parent.mkdir(parents=True)
                    source.write_text('// consumer fixture\n', encoding='utf-8')
                    (root / 'rust-toolchain.toml').write_text(
                        '[toolchain]\nchannel = "fixture"\n', encoding='utf-8')

                    def inspect_manifest(command, *, cwd, **kwargs):
                        document = tomllib.loads((cwd / 'Cargo.toml').read_text(encoding='utf-8'))
                        for name in ('packetcraftr', 'packetcraftr-core', 'packetcraftr-netio'):
                            self.assertEqual(document['dependencies'][name], {
                                'path': str(root / 'crates' / name), 'default-features': False,
                            })
                        self.assertEqual((cwd / 'composition.rs').read_bytes(), source.read_bytes())
                        return subprocess.CompletedProcess(command, 0)

                    with (mock.patch.object(consumer, 'ROOT', root),
                          mock.patch.object(sys, 'argv', ['check-external-consumer.py']),
                          mock.patch.object(consumer.shutil, 'which', return_value=sys.executable),
                          mock.patch.object(consumer.subprocess, 'run', side_effect=inspect_manifest) as run):
                        self.assertEqual(consumer.main(), 0)
                    self.assertEqual(run.call_count, 2)


@unittest.skipIf(os.name == 'nt', 'fixture uses a Unix executable script')
class ExternalConsumerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='external consumer fixture ')
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.wrapper = self.bin / 'cargo-wrapper'
        source = (
            'import json, os, pathlib, sys\n'
            'with open(os.environ["CONSUMER_TEST_LOG"], "a") as log:\n'
            '    log.write(json.dumps(dict(args=sys.argv[1:], cwd=os.getcwd(), '
            'manifest=pathlib.Path("Cargo.toml").is_file(), '
            'source=pathlib.Path("composition.rs").is_file())) + "\\n")\n'
            'sys.exit(int(os.environ.get("CONSUMER_TEST_EXIT", "0")))\n')
        self.wrapper.write_text(
            '#!/bin/sh\n'
            f'exec {shlex.quote(sys.executable)} -c {shlex.quote(source)} "$@"\n',
            encoding='utf-8')
        self.wrapper.chmod(0o755)
        self.log = self.root / 'calls.jsonl'

    def run_consumer(self, cargo, **environment):
        env = dict(os.environ, CONSUMER_TEST_LOG=str(self.log))
        env.update(environment)
        return subprocess.run([
            sys.executable, str(ROOT / 'check-external-consumer.py'), '--cargo', cargo,
        ], cwd=self.root, env=env, capture_output=True, text=True, timeout=30)

    def test_relative_cargo_and_path_entries_survive_detached_working_directory(self):
        for cargo, path in (('./bin/cargo-wrapper', ''), ('cargo-wrapper', 'bin'),
                            (str(self.wrapper), '')):
            with self.subTest(cargo=cargo):
                self.log.unlink(missing_ok=True)
                result = self.run_consumer(cargo, PATH=path)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = [json.loads(line) for line in self.log.read_text().splitlines()]
                self.assertEqual([call['args'] for call in calls], [
                    ['generate-lockfile', '--offline'], ['test', '--locked', '--offline'],
                ])
                self.assertEqual(calls[0]['cwd'], calls[1]['cwd'])
                self.assertNotEqual(pathlib.Path(calls[0]['cwd']), self.root)
                self.assertTrue(all(call['manifest'] and call['source'] for call in calls))

    def test_cargo_failure_stops_before_running_tests(self):
        result = self.run_consumer(str(self.wrapper), CONSUMER_TEST_EXIT='7')
        self.assertNotEqual(result.returncode, 0)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([call['args'] for call in calls], [['generate-lockfile', '--offline']])

    def test_missing_cargo_reports_unexecuted_validation(self):
        result = self.run_consumer('missing-cargo', PATH=str(self.bin))
        self.assertEqual(result.returncode, 2)
        self.assertIn('Cargo is required; external-consumer validation was not executed.', result.stderr)
        self.assertFalse(self.log.exists())


if __name__ == '__main__':
    unittest.main()
