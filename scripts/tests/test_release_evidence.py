# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from support import load_script

release = load_script('check-release-evidence')
assets = load_script('release_assets')
evidence = load_script('validation_evidence')
SHA = 'a' * 40


def run(identifier=1, **changes):
    return dict(dict(id=identifier, head_sha=SHA, event='push', status='completed',
                     conclusion='success', html_url=f'https://github.com/owner/repo/actions/runs/{identifier}'),
                **changes)


def native_report():
    return dict(schema_version=1, commit=SHA, dirty=False, status='passed',
                binary_sha256='b' * 64, binary_version='packetcraftr 0.5.0-beta.3',
                namespace=2, parent_namespace=1, namespace_launcher={'exit_code': 0},
                scenarios=[dict(name='loopback_exchange', status='passed', exit_code=0)])


class ReleaseEvidenceTests(unittest.TestCase):
    def test_exact_successful_push_run_is_selected(self):
        result = release.select_run({'workflow_runs': [run(1), run(9, head_sha='b' * 40), run(3)]}, 'owner/repo', SHA)
        self.assertEqual(result['id'], 3)
        for changes in ({'head_sha': 'b' * 40}, {'event': 'pull_request'}, {'status': 'in_progress'},
                        {'conclusion': 'failure'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                release.select_run({'workflow_runs': [run(**changes)]}, 'owner/repo', SHA)

    def test_invalid_and_duplicate_run_ids_are_rejected(self):
        for records in ([run(True)], [run(-1)], [run(1), run(1)]):
            with self.subTest(records=records), self.assertRaises(ValueError):
                release.select_run({'workflow_runs': records}, 'owner/repo', SHA)

    def test_api_inventory_and_run_url_are_validated(self):
        for document in ([], {}, {'workflow_runs': {}}, {'workflow_runs': [run(html_url='https://example.test')]}):
            with self.subTest(document=document), self.assertRaises(ValueError):
                release.select_run(document, 'owner/repo', SHA)

    def test_repository_names_are_ascii_and_not_dot_segments(self):
        for repository in ('own\u00e9r/repo', '../repo', 'owner/..'):
            with patch.object(release.subprocess, 'check_output') as command:
                with self.subTest(repository=repository), self.assertRaises(SystemExit):
                    release.main(['--repository', repository, '--commit', SHA, '--output', 'unused'])
                command.assert_not_called()

    def test_success_cannot_retain_error_or_omit_version(self):
        release.validate(native_report(), SHA, 'native-isolated-evidence')
        for changes in ({'error': 'child failed'}, {'binary_version': None}, {'binary_version': 'packetcraftr '},
                        {'binary_version': 'packetcraftr 1\nother'}):
            report = dict(native_report(), **changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                release.validate(report, SHA, 'native-isolated-evidence')

    def test_failed_attempt_removes_stale_success(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'VALIDATION-EVIDENCE.json'
            marker.write_text('previous success')
            with patch.object(release.subprocess, 'check_output', return_value=b'not json'):
                with self.assertRaises(SystemExit):
                    release.main(['--repository', 'owner/repo', '--commit', SHA, '--output', directory])
            self.assertFalse(marker.exists())

    def test_success_is_published_only_after_both_valid_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            def download(command, **kwargs):
                folder = Path(command[command.index('--dir') + 1])
                folder.mkdir(parents=True)
                filename = release.REQUIRED[command[command.index('--name') + 1]]
                (folder / filename).write_text(json.dumps(native_report()))
            with patch.object(release.subprocess, 'check_output', return_value=json.dumps({'workflow_runs': [run()]}).encode()), \
                    patch.object(release.subprocess, 'run', side_effect=download), \
                    patch.object(release, 'validate') as validate:
                release.main(['--repository', 'owner/repo', '--commit', SHA, '--output', directory])
            self.assertEqual(validate.call_count, 2)
            self.assertEqual(len(json.loads((Path(directory) / 'VALIDATION-EVIDENCE.json').read_text())['reports']), 2)


class ReleaseAssetTests(unittest.TestCase):
    def test_repository_inventory_is_valid(self):
        assets.validate_manifest(assets.MANIFEST)

    def test_inventory_shape_is_explicit(self):
        for value in ([], {}, {'schema': 'packetcraftr.release-assets/v1', 'source_assets': 'LICENSE'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                assets.validate_manifest(value)

    def test_paths_are_safe_portable_and_canonical(self):
        for entry in ('../escape', '/absolute', 'C:file', 'a\\b', 'a//b', './a', '.', 'a/../b', 'a\nb', ''):
            manifest = copy.deepcopy(assets.MANIFEST)
            manifest['source_assets'][0] = entry
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                assets.validate_manifest(manifest)

    def test_duplicates_and_source_generated_collisions_are_rejected(self):
        for category in ('source_assets', 'generated_assets'):
            manifest = copy.deepcopy(assets.MANIFEST)
            manifest[category].append(manifest['source_assets'][0])
            with self.subTest(category=category), self.assertRaises(ValueError):
                assets.validate_manifest(manifest)


class ValidationSupportTests(unittest.TestCase):
    def test_checksum_known_vectors_and_odd_buffers(self):
        for data, expected in ((b'', 0xffff), (bytes.fromhex('0001f203f4f5f6f7'), 0x220d), (b'\x01', 0xfeff)):
            self.assertEqual(evidence.checksum(data), expected)
            mutable = bytearray(data)
            self.assertEqual(evidence.checksum(mutable), expected)
            self.assertEqual(mutable, data)
            self.assertEqual(evidence.checksum(memoryview(data)), expected)

    def test_checksum_random_vectors_match_simple_reference(self):
        import random
        rng = random.Random(0)
        for size in range(130):
            data = rng.randbytes(size)
            padded = data + b'\0' * (size % 2)
            total = sum(int.from_bytes(padded[i:i + 2], 'big') for i in range(0, len(padded), 2))
            while total >> 16:
                total = (total & 65535) + (total >> 16)
            self.assertEqual(evidence.checksum(data), ~total & 65535)

    def test_native_success_cannot_hide_scenario_errors(self):
        for field in ('error', 'responder_error'):
            report = native_report()
            report['scenarios'][0][field] = 'failed'
            with self.subTest(field=field), self.assertRaises(ValueError):
                evidence.validate_native(report)

    def test_provenance_executes_the_hashed_absolute_path(self):
        with patch.object(evidence, 'digest', return_value='b' * 64), \
                patch.object(evidence.subprocess, 'check_output', side_effect=['packetcraftr 1', SHA, b'']) as command:
            evidence.provenance(Path('binary'))
            self.assertEqual(command.call_args_list[0].args[0], [str(Path('binary').absolute()), '--version'])

    def test_provenance_detects_mutation(self):
        with patch.object(evidence, 'digest', side_effect=['a' * 64, 'b' * 64]), \
                patch.object(evidence.subprocess, 'check_output', return_value='packetcraftr 1'):
            with self.assertRaisesRegex(ValueError, 'changed'):
                evidence.provenance('binary')

    def test_digest_rejects_non_regular_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'regular file'):
                evidence.digest(directory)


if __name__ == '__main__':
    unittest.main()
