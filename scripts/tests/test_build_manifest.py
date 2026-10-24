# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from support import load_script

manifest = load_script('build-manifest')


def identity():
    return dict(binary='packetcraftr', binary_sha256='a' * 64,
                version='packetcraftr 0.5.0-beta.3', commit='b' * 40,
                target='x86_64-unknown-linux-gnu', feature_variant='all-features',
                rustc='rustc 1.98.1\nbinary: rustc')


class BuildManifestTests(unittest.TestCase):
    def test_version_and_compiler_payload_cannot_be_blank(self):
        for field, value in (('version', 'packetcraftr '), ('rustc', 'rustc ')):
            document = identity()
            document[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                manifest.validate_identity(document)

    def test_complete_provenance_is_required(self):
        for field in manifest.REQUIRED_FIELDS:
            document = identity()
            del document[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                manifest.validate_identity(document)

    def test_binary_digest_must_be_sha256(self):
        document = identity()
        document['binary_sha256'] = 'not-a-digest'
        with self.assertRaises(ValueError):
            manifest.validate_identity(document)

    def test_binary_name_is_not_an_archive_path(self):
        for name in ['../packetcraftr', 'a/b', r'a\b', 'C:binary', '..', 'bad\nname',
                     'bad*name', 'bad?name', 'bad"name', 'bad<name', 'bad>name',
                     'bad|name', 'name.', 'name ', 'CON.exe', 'lPt1', 'NUL', 'PRN  .x']:
            document = identity()
            document['binary'] = name
            with self.subTest(name=name), self.assertRaises(ValueError):
                manifest.validate_identity(document)

    def test_compiler_identity_preserves_multiline_but_rejects_controls(self):
        document = identity()
        document['rustc'] = 'rustc 1.98.1\r\nbinary:\trustc\nhost: test'
        manifest.validate_identity(document)
        for control in ('\x00', '\x1b', '\x7f', '\x85'):
            document['rustc'] = 'rustc 1.98.1' + control
            with self.subTest(control=control), self.assertRaisesRegex(ValueError, 'control'):
                manifest.validate_identity(document)

    def test_version_is_an_unambiguous_product_line(self):
        for version in ['other 1', 'packetcraftr 1\npacketcraftr 2', 'packetcraftr \x1b[0m']:
            document = identity()
            document['version'] = version
            with self.subTest(version=version), self.assertRaises(ValueError):
                manifest.validate_identity(document)

    def test_invalid_metadata_has_a_contextual_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'BUILD-METADATA.json'
            for data in [b'\xff', b'{}', b'{"binary":1,"binary":2}', b' ' * (manifest.MAX_MANIFEST_BYTES + 1)]:
                path.write_bytes(data)
                with self.assertRaisesRegex(SystemExit, 'cannot load build metadata'):
                    manifest.load_manifest(path)

    def test_mode_is_required_before_binary_access(self):
        with patch.object(manifest, 'digest') as digest:
            with self.assertRaises(SystemExit):
                manifest.main(['--binary', 'missing'])
            digest.assert_not_called()

    def test_invalid_release_inputs_do_not_execute_binary(self):
        with patch.object(manifest.subprocess, 'check_output') as command:
            with self.assertRaises(SystemExit):
                manifest.main(['--binary', 'missing', '--verify', 'metadata', '--commit', 'short'])
            command.assert_not_called()

    def test_binary_mutation_during_version_query_is_rejected(self):
        with patch.object(manifest.subprocess, 'check_output', return_value='packetcraftr 1\n'):
            with patch.object(manifest, 'digest', return_value='changed'):
                with self.assertRaisesRegex(ValueError, 'changed'):
                    manifest.binary_version(Path('/binary'), 'original')

    def test_missing_binary_is_a_clean_failure(self):
        with self.assertRaisesRegex(SystemExit, '1'):
            manifest.main(['--binary', '/missing/binary', '--verify', '/missing/metadata'])
