#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Failure-path contracts for release evidence and architecture checks."""
import copy
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f'{name}.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


release = module('check-release-evidence')
architecture = module('check-architecture')


class EvidenceTests(unittest.TestCase):
    def native(self):
        return dict(status='passed', commit='a' * 40, dirty=False, binary_sha256='c' * 64, namespace=2, parent_namespace=1,
                    scenarios=[dict(name=name, status='passed') for name in release.NATIVE])

    def test_success_requires_clean_exact_commit(self):
        valid = self.native()
        release.validate(valid, 'a' * 40, 'native-isolated-evidence')
        for key, value in [('status', 'skipped'), ('dirty', True), ('commit', 'b' * 40)]:
            altered = dict(valid, **{key: value})
            with self.assertRaises(ValueError): release.validate(altered, 'a' * 40, 'native-isolated-evidence')

    def test_skipped_missing_and_unisolated_native_are_not_success(self):
        for mode in ['skipped', 'missing', 'unisolated']:
            report = self.native()
            if mode == 'skipped': report['scenarios'][0]['status'] = 'not_exercised'
            elif mode == 'missing': report['scenarios'].pop()
            else: report['namespace'] = report['parent_namespace']
            with self.assertRaises(ValueError): release.validate(report, 'a' * 40, 'native-isolated-evidence')

    def test_decoder_mismatch_or_empty_corpus_cannot_release(self):
        report = dict(status='passed', commit='a' * 40, dirty=False, binary_sha256='c' * 64, expected_tshark='4.6.4',
                      captures=[dict(status='passed')], mismatches=[])
        release.validate(report, 'a' * 40, 'decode-oracle-evidence')
        for change in [dict(captures=[]), dict(mismatches=[dict(field='tcp.seq_raw')]), dict(expected_tshark='other')]:
            with self.assertRaises(ValueError): release.validate(dict(report, **change), 'a' * 40, 'decode-oracle-evidence')

    def test_metadata_checks_optional_and_target_specific_production_edges(self):
        metadata = dict(workspace_members=['core'], packages=[dict(id='core', name='packetcraftr-core',
            dependencies=[dict(name='serde', kind=None)])])
        self.assertEqual(architecture.validate(metadata), [])
        for child in ['packetcraftr-netio', 'packetcraftr', 'pcap', 'tokio']:
            changed = copy.deepcopy(metadata)
            changed['packages'][0]['dependencies'].append(dict(name=child, kind=None, optional=True, target='cfg(unix)'))
            self.assertTrue(architecture.validate(changed))


if __name__ == '__main__':
    unittest.main()
