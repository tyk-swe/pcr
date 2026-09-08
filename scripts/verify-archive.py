#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Smoke-test an extracted release archive using only the Python standard library."""
import argparse
import json
import pathlib
import subprocess
import sys

ASSETS = (
    'LICENSE', 'README.md', 'CHANGELOG.md',
    'docs/migration-beta.3.md', 'docs/migration-unreleased.md', 'docs/analysis-resources.md',
    'BUILD-METADATA.json', 'schemas/packetcraftr.packet.v1.schema.json',
    'schemas/packetcraftr.output.v3.schema.json',
    'examples/captures/tls-handshake.pcapng',
    'examples/documents/packet-ipv4-udp.json',
)
EXPECTED = '450000210000000040118e95c0000201c633640230390009000d9f8868656c6c6f'


def run(command, cwd):
    result = subprocess.run(command, cwd=cwd, check=True, capture_output=True,
                            text=True, encoding='utf-8', timeout=60)
    if not result.stdout.strip():
        raise ValueError(f'empty output from {command}')
    return result.stdout


def verify(root, version, commit, target, variant):
    root = root.resolve()
    binary = root / ('packetcraftr.exe' if 'windows' in target else 'packetcraftr')
    for asset in (*ASSETS, binary.name):
        path = root / asset
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f'packaged {asset} is missing or empty')
    # Keep manifest writing and verification under one identity implementation.
    subprocess.run([
        sys.executable, str(pathlib.Path(__file__).resolve().with_name('build-manifest.py')),
        '--binary', str(binary), '--verify', str(root / 'BUILD-METADATA.json'),
        '--commit', commit, '--target', target, '--variant', variant,
    ], cwd=root, check=True, timeout=60)

    def cli(*args):
        return run([str(binary), *args], root)

    if cli('--version').splitlines()[0] != f'packetcraftr {version}':
        raise ValueError('unexpected packaged version')
    cli('protocols')
    built = cli('--output', 'hex', 'build', '--packet',
                'ipv4(src=192.0.2.1,dst=198.51.100.2)/udp(sport=12345,dport=9)/raw(text=hello)')
    if built.strip() != EXPECTED:
        raise ValueError('unexpected build bytes')
    if cli('--output', 'hex', 'dissect', '--link-type', '228', '--hex', EXPECTED).strip() != EXPECTED:
        raise ValueError('dissect did not preserve exact bytes')
    output = cli('--output', 'ndjson', 'read',
                 'examples/captures/tls-handshake.pcapng', '--max-frames', '100')
    if not output.endswith('\n'):
        raise ValueError('unterminated NDJSON output')
    records = [json.loads(line) for line in output.splitlines()]
    if not records or not all(isinstance(record, dict) for record in records):
        raise ValueError('expected NDJSON objects')
    if records[-1].get('event') != 'complete':
        raise ValueError('stream has no terminal completion')
    for index, record in enumerate(records):
        if (record.get('schema') != 'packetcraftr.output/v3'
                or type(record.get('sequence')) is not int
                or record['sequence'] != index
                or record.get('event') != ('complete' if index == len(records) - 1 else 'frame')):
            raise ValueError('stream has invalid schema, sequence or completion')
    cli('tls', 'examples/captures/tls-handshake.pcapng')
    json.loads(cli('--output', 'json', 'build', '--packet-file',
                   'examples/documents/packet-ipv4-udp.json'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=pathlib.Path, required=True)
    for field in ('version', 'commit', 'target', 'variant'):
        parser.add_argument(f'--{field}', required=True)
    args = parser.parse_args()
    try:
        verify(args.root, args.version, args.commit, args.target, args.variant)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'archive verification failed: {error}\n')


if __name__ == '__main__':
    main()
