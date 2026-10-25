# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
from pathlib import Path
import hashlib
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from support import load_script

manifest = load_script('build-manifest')


def identity() -> dict[str, str]:
    return dict(binary='packetcraftr', binary_sha256='a' * 64,
                version='packetcraftr 0.5.0-beta.3', commit='b' * 40,
                target='x86_64-unknown-linux-gnu', feature_variant='all-features',
                rustc='rustc 1.98.1\nbinary: rustc')


class BuildManifestTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'fixture executables use POSIX shebangs')
    def test_write_and_verify_preserve_supplied_identity_and_detect_binary_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, compiler, output = root / 'packetcraftr', root / 'rustc', root / 'metadata.json'
            binary.write_text(f'#!{sys.executable}\nprint("packetcraftr fixture")\n')
            compiler.write_text(f'#!{sys.executable}\nprint("rustc fixture\\nhost: fixture")\n')
            binary.chmod(0o755)
            compiler.chmod(0o755)
            supplied = ['--binary', str(binary), '--commit', 'a' * 40,
                        '--target', 'fixture-target', '--variant', 'fixture-mode']
            with patch.dict(os.environ, {'PATH': str(root) + os.pathsep + os.environ.get('PATH', '')}):
                manifest.main([*supplied, '--output', str(output)])
                self.assertEqual(json.loads(output.read_text()), {
                    'binary': binary.name,
                    'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                    'version': 'packetcraftr fixture', 'commit': 'a' * 40,
                    'target': 'fixture-target', 'feature_variant': 'fixture-mode',
                    'rustc': 'rustc fixture\nhost: fixture',
                })
                manifest.main([*supplied, '--verify', str(output)])
                document = json.loads(output.read_text())
                for version in ('packetcraftr earlier', 'packetcraftr later'):
                    output.write_text(json.dumps(document | {'version': version}))
                    with self.subTest(version=version), self.assertRaisesRegex(SystemExit, 'packaged version'):
                        manifest.main([*supplied, '--verify', str(output)])
                output.write_text(json.dumps(document))
                binary.write_text(binary.read_text() + 'changed = True\n')
                with self.assertRaisesRegex(SystemExit, 'packaged binary'):
                    manifest.main([*supplied, '--verify', str(output)])

    def test_version_and_compiler_payload_cannot_be_blank(self) -> None:
        for field, value in (('version', 'packetcraftr '), ('rustc', 'rustc ')):
            document = identity()
            document[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                manifest.validate_identity(document)

    def test_complete_provenance_is_required(self) -> None:
        for field in manifest.REQUIRED_FIELDS:
            document = identity()
            del document[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                manifest.validate_identity(document)

    def test_binary_digest_must_be_sha256(self) -> None:
        document = identity()
        document['binary_sha256'] = 'not-a-digest'
        with self.assertRaises(ValueError):
            manifest.validate_identity(document)

    def test_binary_name_is_not_an_archive_path(self) -> None:
        for name in ['../packetcraftr', 'a/b', r'a\b', 'C:binary', '..', 'bad\nname',
                     'bad*name', 'bad?name', 'bad"name', 'bad<name', 'bad>name',
                     'bad|name', 'name.', 'name ', 'CON.exe', 'lPt1', 'NUL', 'PRN  .x']:
            document = identity()
            document['binary'] = name
            with self.subTest(name=name), self.assertRaises(ValueError):
                manifest.validate_identity(document)

    def test_compiler_identity_preserves_multiline_but_rejects_controls(self) -> None:
        document = identity()
        document['rustc'] = 'rustc 1.98.1\r\nbinary:\trustc\nhost: test'
        manifest.validate_identity(document)
        for control in ('\x00', '\x1b', '\x7f', '\x85'):
            document['rustc'] = 'rustc 1.98.1' + control
            with self.subTest(control=control), self.assertRaisesRegex(ValueError, 'control'):
                manifest.validate_identity(document)

    def test_version_is_an_unambiguous_product_line(self) -> None:
        for version in ['other 1', 'packetcraftr 1\npacketcraftr 2', 'packetcraftr \x1b[0m']:
            document = identity()
            document['version'] = version
            with self.subTest(version=version), self.assertRaises(ValueError):
                manifest.validate_identity(document)

    def test_invalid_metadata_has_a_contextual_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'BUILD-METADATA.json'
            for data in [b'\xff', b'{}', b'{"binary":1,"binary":2}', b' ' * (manifest.MAX_MANIFEST_BYTES + 1)]:
                path.write_bytes(data)
                with self.assertRaisesRegex(SystemExit, 'cannot load build metadata'):
                    manifest.load_manifest(path)

    def test_mode_is_required_before_binary_access(self) -> None:
        with patch.object(manifest, 'digest') as digest:
            with self.assertRaises(SystemExit):
                manifest.main(['--binary', 'missing'])
            digest.assert_not_called()

    def test_invalid_release_inputs_do_not_execute_binary(self) -> None:
        with patch.object(manifest.subprocess, 'check_output') as command:
            with self.assertRaises(SystemExit):
                manifest.main(['--binary', 'missing', '--verify', 'metadata', '--commit', 'short'])
            command.assert_not_called()

    def test_binary_mutation_during_version_query_is_rejected(self) -> None:
        with patch.object(manifest.subprocess, 'check_output', return_value='packetcraftr 1\n'):
            with patch.object(manifest, 'digest', return_value='changed'):
                with self.assertRaisesRegex(ValueError, 'changed'):
                    manifest.binary_version(Path('/binary'), 'original')

    def test_missing_binary_is_a_clean_failure(self) -> None:
        with self.assertRaisesRegex(SystemExit, '1'):
            manifest.main(['--binary', '/missing/binary', '--verify', '/missing/metadata'])
