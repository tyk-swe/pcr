#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Verifier failure fixtures and optional real-binary archive smoke on each CI OS."""
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name('verify-archive.py')
SPEC = importlib.util.spec_from_file_location('verify_archive', SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

# A real child process exercises exit-code handling, cwd and output parsing.
CHILD = r'''
import json, pathlib, sys
args = sys.argv[1:]
mode = pathlib.Path('fixture-mode').read_text()
expected = '450000210000000040118e95c0000201c633640230390009000d9f8868656c6c6f'
command = next((x for x in ('--version', 'protocols', 'build', 'dissect', 'read', 'tls') if x in args), '')
if mode == 'exit-' + command or (mode == 'exit-recipe' and '--packet-file' in args):
    sys.exit(7)
if command == '--version':
    print('packetcraftr 1.2.3')
elif command in ('protocols', 'tls'):
    print('' if mode == 'empty-' + command else 'fixture')
elif command == 'build' and '--packet-file' in args:
    assert pathlib.Path(args[-1]).is_file()
    print('{' if mode == 'bad-recipe' else '{}')
elif command in ('build', 'dissect'):
    print('00' if mode == 'bytes-' + command else expected)
elif command == 'read':
    assert pathlib.Path('examples/captures/tls-handshake.pcapng').is_file()
    records = [dict(schema='packetcraftr.output/v4', sequence=0, event='frame'),
               dict(schema='packetcraftr.output/v4', sequence=1, event='complete')]
    if mode == 'bad-schema': records[0]['schema'] = 'wrong'
    if mode == 'bad-sequence': records[1]['sequence'] = 3
    if mode == 'boolean-sequence': records[0]['sequence'] = False
    if mode == 'no-completion': records.pop()
    if mode == 'early-completion': records[0]['event'] = 'complete'
    if mode == 'early-error': records[0]['event'] = 'error'
    if mode == 'unknown-event': records[0]['event'] = 'unknown'
    if mode == 'missing-event': del records[0]['event']
    if mode == 'non-object': records[0] = []
    output = '\n'.join(json.dumps(r) for r in records) + '\n'
    if mode == 'unterminated': output = output.rstrip('\n')
    if mode == 'malformed': output = '{\n'
    if mode == 'empty-read': output = ''
    sys.stdout.write(output)
'''


@unittest.skipIf(os.name == 'nt', 'fixtures use Unix executable scripts')
class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='archive fixture ')
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        for asset in VERIFIER.ASSETS:
            path = self.root / asset
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture', encoding='utf-8')
        self.mode('ok')
        self.binary = self.root / 'packetcraftr'
        self.binary.write_text(f'#!{sys.executable}\n' + CHILD, encoding='utf-8')
        self.binary.chmod(0o755)
        self.target = 'x86_64-unknown-linux-gnu'
        self.manifest()

    def mode(self, mode):
        (self.root / 'fixture-mode').write_text(mode, encoding='utf-8')

    def manifest(self, **changes):
        document = dict(binary=self.binary.name,
                        binary_sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                        version='packetcraftr 1.2.3', commit='abc', target=self.target,
                        feature_variant='pcap-free')
        document.update(changes)
        (self.root / 'BUILD-METADATA.json').write_text(json.dumps(document), encoding='utf-8')

    def check(self, success=False, version='1.2.3'):
        result = subprocess.run([
            sys.executable, str(SCRIPT), '--root', str(self.root), '--version', version,
            '--commit', 'abc', '--target', self.target, '--variant', 'pcap-free',
        ], capture_output=True, text=True, timeout=30)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('archive verification failed', result.stderr)

    def test_valid_unix_and_windows_layouts(self):
        self.check(success=True)
        self.binary = self.binary.rename(self.root / 'packetcraftr.exe')
        self.target = 'x86_64-pc-windows-msvc'
        self.manifest()
        self.check(success=True)

    def test_missing_and_empty_assets(self):
        for asset in (*VERIFIER.ASSETS, self.binary.name):
            with self.subTest(asset=asset):
                path = self.root / asset
                original = path.read_bytes()
                path.write_bytes(b'')
                self.check()
                path.unlink()
                self.check()
                path.write_bytes(original)
                if path == self.binary:
                    path.chmod(0o755)

    def test_corrupt_identity(self):
        for field in ('binary', 'binary_sha256', 'version', 'commit', 'target', 'feature_variant'):
            with self.subTest(field=field):
                self.manifest(**{field: 'corrupt'})
                self.check()
        (self.root / 'BUILD-METADATA.json').write_text('{', encoding='utf-8')
        self.check()

    def test_wrong_release_version(self):
        self.check(version='9.9.9')

    def test_nonzero_commands(self):
        for command in ('--version', 'protocols', 'build', 'dissect', 'read', 'tls'):
            with self.subTest(command=command):
                self.mode('exit-' + command)
                self.check()

    def test_invalid_outputs(self):
        for mode in ('empty-protocols', 'empty-tls', 'bytes-build', 'bytes-dissect', 'exit-recipe',
                     'bad-recipe', 'bad-schema', 'bad-sequence', 'boolean-sequence',
                     'no-completion', 'early-completion', 'early-error', 'unknown-event',
                     'missing-event', 'non-object',
                     'unterminated', 'malformed', 'empty-read'):
            with self.subTest(mode=mode):
                self.mode(mode)
                self.check()


@unittest.skipUnless(os.environ.get('PACKETCRAFTR_ARCHIVE_BINARY'),
                     'set PACKETCRAFTR_ARCHIVE_BINARY to smoke-test a native archive')
class NativeArchiveTests(unittest.TestCase):
    def test_extracted_archive(self):
        repository = SCRIPT.resolve().parent.parent
        binary = pathlib.Path(os.environ['PACKETCRAFTR_ARCHIVE_BINARY']).resolve()
        variant = os.environ.get('PACKETCRAFTR_ARCHIVE_VARIANT', 'all-features')
        self.assertIn(variant, ('all-features', 'pcap-free'))
        metadata = json.loads(subprocess.check_output(
            ['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1'],
            cwd=repository, text=True, timeout=60))
        version = next(package['version'] for package in metadata['packages']
                       if package['name'] == 'packetcraftr-cli')
        rustc = subprocess.check_output(['rustc', '--version', '--verbose'], text=True, timeout=30)
        target = next(line.removeprefix('host: ') for line in rustc.splitlines()
                      if line.startswith('host: '))
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repository,
                                         text=True, timeout=30).strip()
        with tempfile.TemporaryDirectory(prefix='native archive smoke ') as directory:
            temporary = pathlib.Path(directory)
            staging = temporary / 'staging' / 'packetcraftr-package'
            staging.mkdir(parents=True)
            shutil.copy2(binary, staging / binary.name)
            for asset in VERIFIER.ASSETS:
                if asset == 'BUILD-METADATA.json':
                    continue
                destination = staging / asset
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(repository / asset, destination)
            subprocess.run([
                sys.executable, str(SCRIPT.with_name('build-manifest.py')),
                '--binary', str(staging / binary.name), '--output', str(staging / 'BUILD-METADATA.json'),
                '--commit', commit, '--target', target, '--variant', variant,
            ], check=True, timeout=60)
            archive = shutil.make_archive(str(temporary / 'archive'),
                                          'zip' if os.name == 'nt' else 'gztar',
                                          root_dir=staging.parent)
            extracted = temporary / 'extracted'
            shutil.unpack_archive(archive, extracted)
            subprocess.run([
                sys.executable, str(SCRIPT), '--root', str(extracted / staging.name),
                '--version', version, '--commit', commit, '--target', target,
                '--variant', variant,
            ], check=True, timeout=300)


if __name__ == '__main__':
    unittest.main()
