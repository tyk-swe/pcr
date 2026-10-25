# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
from pathlib import Path
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from support import ROOT, load_script

manifest = load_script('build-manifest')


def identity() -> dict[str, str]:
    return dict(binary='packetcraftr', binary_sha256='a' * 64,
                version='packetcraftr fixture-version', commit='b' * 40,
                target='x86_64-unknown-linux-gnu', feature_variant='all-features',
                rustc='rustc fixture-version\nbinary: rustc')


def executable(path: Path, source: str) -> None:
    path.write_text('#!/bin/sh\nexec ' + shlex.join((sys.executable, '-c', source)) + ' "$@"\n')
    path.chmod(0o755)


class BuildManifestTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'fixture executables use POSIX shebangs')
    def test_command_failures_have_a_clean_diagnostic_and_no_success_report(self) -> None:
        for failed in ('binary', 'compiler'):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary, compiler, output = root / 'packetcraftr', root / 'rustc', root / 'metadata.json'
                for path, label, version in ((binary, 'binary', 'packetcraftr fixture'),
                                             (compiler, 'compiler', 'rustc fixture')):
                    body = 'import sys\nsys.exit(7)' if failed == label else f'print({version!r})'
                    executable(path, body)
                result = subprocess.run(
                    [sys.executable, str(ROOT / 'scripts/build-manifest.py'),
                     '--binary', str(binary), '--output', str(output), '--commit', 'a' * 40,
                     '--target', 'fixture-target', '--variant', 'fixture-mode'],
                    env=os.environ | {'PATH': str(root) + os.pathsep + os.environ.get('PATH', '')},
                    capture_output=True, text=True, timeout=5, check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, '')
                failed_command = ([str(binary), '-V'] if failed == 'binary'
                                  else ['rustc', '--version', '--verbose'])
                cause = subprocess.CalledProcessError(7, failed_command)
                self.assertEqual(result.stderr, f'build metadata failed: {cause}\n')
                self.assertFalse(output.exists())

    @unittest.skipUnless(os.name == 'posix', 'fixture executables use POSIX shebangs')
    def test_write_and_verify_preserve_supplied_identity_and_detect_binary_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, compiler, output = root / 'packetcraftr', root / 'rustc', root / 'metadata.json'
            executable(binary,
                       'import sys\n'
                       'versions = {"-V": "packetcraftr fixture", '
                       '"--version": "packetcraftr fixture\\nnative features: supplied-native"}\n'
                       'print(versions[sys.argv[1]])')
            executable(compiler, 'print("rustc fixture\\nhost: fixture")')
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
                for field, values, diagnostic in (
                    ('commit', ('0' * 40, 'f' * 40), 'packaged commit'),
                    ('target', ('aaa-target', 'zzz-target'), 'packaged target'),
                    ('feature_variant', ('aaa-mode', 'zzz-mode'), 'packaged feature_variant'),
                    ('binary', ('aaa-binary', 'zzz-binary'), 'packaged binary'),
                    ('binary_sha256', ('0' * 64, 'f' * 64), 'packaged binary'),
                ):
                    for value in values:
                        output.write_text(json.dumps(document | {field: value}))
                        with self.subTest(field=field, value=value), self.assertRaisesRegex(SystemExit, diagnostic):
                            manifest.main([*supplied, '--verify', str(output)])
                for version in ('packetcraftr earlier', 'packetcraftr later'):
                    output.write_text(json.dumps(document | {'version': version}))
                    with self.subTest(version=version), self.assertRaisesRegex(SystemExit, 'packaged version'):
                        manifest.main([*supplied, '--verify', str(output)])
                output.write_text(json.dumps(document))
                binary.write_text(binary.read_text() + '\n')
                with self.assertRaisesRegex(SystemExit, 'packaged binary'):
                    manifest.main([*supplied, '--verify', str(output)])

    def test_version_and_compiler_payload_cannot_be_blank(self) -> None:
        for field, value in (('version', 'packetcraftr '), ('rustc', 'rustc ')):
            document = identity()
            document[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                manifest.validate_identity(document)

    def test_complete_provenance_is_required(self) -> None:
        for field in identity():
            document = identity()
            del document[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                manifest.validate_identity(document)
            for invalid in ('', ' ', None, True, 7):
                invalid_document: dict[str, object] = identity() | {field: invalid}
                with self.subTest(field=field, invalid=invalid), self.assertRaisesRegex(ValueError, field):
                    manifest.validate_identity(invalid_document)

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
        document['rustc'] = 'rustc fixture-version~\r\nbinary:\trustc\nhost: test\u00a0λ'
        manifest.validate_identity(document)
        for control in ('\x00', '\x1b', '\x1f', '\x7f', '\x85', '\x9f'):
            document['rustc'] = 'rustc fixture-version' + control
            with self.subTest(control=control), self.assertRaisesRegex(ValueError, 'control'):
                manifest.validate_identity(document)

    def test_version_is_an_unambiguous_product_line(self) -> None:
        for version in ('packetcraftr fixture~', 'packetcraftr fixture-λ'):
            manifest.validate_identity(identity() | {'version': version})
        controls = tuple('packetcraftr fixture' + chr(value) for value in (*range(32), 127))
        for version in ('other 1', 'packetcraftr 1\npacketcraftr 2',
                        'packetcraftr 1\u2028packetcraftr 2', *controls):
            document = identity()
            document['version'] = version
            with self.subTest(version=version), self.assertRaises(ValueError):
                manifest.validate_identity(document)

    def test_invalid_metadata_has_a_contextual_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'BUILD-METADATA.json'
            for data in [b'\xff', b'{}', b'{"binary":1,"binary":2}']:
                path.write_bytes(data)
                with self.assertRaisesRegex(SystemExit, 'cannot load build metadata'):
                    manifest.load_manifest(path)
            encoded = json.dumps(identity()).encode()
            limit = 64 * 1024
            path.write_bytes(encoded + b' ' * (limit - len(encoded)))
            self.assertEqual(manifest.load_manifest(path), identity())
            path.write_bytes(path.read_bytes() + b' ')
            with self.assertRaisesRegex(SystemExit, 'cannot load build metadata'):
                manifest.load_manifest(path)

    def test_mode_is_required_before_binary_access(self) -> None:
        for arguments in ([], ['--binary', 'missing'], ['--verify', 'metadata.json']):
            with self.subTest(arguments=arguments), \
                    patch.object(Path, 'is_file', side_effect=AssertionError('unexpected binary access')), \
                    self.assertRaises(SystemExit) as rejected:
                manifest.main(arguments)
            self.assertNotEqual(rejected.exception.code, 0)
        result = subprocess.run([sys.executable, '-c',
                                 'import runpy\nrunpy.run_path("build-manifest.py")\nprint("loaded")\n'],
                                cwd=ROOT / 'scripts', capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'loaded\n')

    def test_invalid_release_inputs_do_not_execute_binary(self) -> None:
        with patch.object(manifest.subprocess, 'check_output') as command:
            with self.assertRaises(SystemExit):
                manifest.main(['--binary', 'missing', '--verify', 'metadata', '--commit', 'short'])
            command.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'binary'
            binary.write_bytes(b'controlled input')
            for option, field in (('target', 'target'), ('variant', 'feature_variant')):
                for invalid in ('bad/name', 'with space', '-leading', 'trailing\n', 'é'):
                    document = identity() | {field: invalid}
                    with self.subTest(field=field, value=invalid):
                        with self.assertRaisesRegex(ValueError, field):
                            manifest.validate_identity(document)
                        with patch.object(manifest.subprocess, 'check_output') as command:
                            with self.assertRaises(SystemExit) as refused:
                                manifest.main(['--binary', str(binary), '--verify', str(root / 'metadata.json'),
                                               '--commit', 'a' * 40, f'--{option}={invalid}'])
                            self.assertEqual(refused.exception.code, 2)
                            command.assert_not_called()

    def test_binary_mutation_during_version_query_is_rejected(self) -> None:
        with patch.object(manifest.subprocess, 'check_output', return_value='packetcraftr 1\n'):
            for changed in ('0' * 64, 'f' * 64):
                with self.subTest(changed=changed), patch.object(manifest, 'digest', return_value=changed):
                    with self.assertRaisesRegex(ValueError, 'changed'):
                        manifest.binary_version(Path('/binary'), '8' * 64)

    def test_missing_binary_is_a_clean_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(SystemExit) as failure:
                manifest.main(['--binary', str(root / 'missing-binary'), '--verify', str(root / 'metadata.json')])
            self.assertEqual(failure.exception.code, 1)
