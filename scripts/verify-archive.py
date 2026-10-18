#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Smoke-test an extracted release archive using only the Python standard library."""
import argparse
import copy
import csv
import importlib.util
import io
import json
import pathlib
import re
import subprocess
import sys

from validation_evidence import DECODE_PROFILES
from release_assets import SOURCE_ASSETS, GENERATED_ASSETS, MANIFEST

EXPECTED = '450000210000000040118e95c0000201c633640230390009000d9f8868656c6c6f'


def run(command, cwd):
    result = subprocess.run(command, cwd=cwd, check=True, capture_output=True,
                            text=True, encoding='utf-8', timeout=60)
    if not result.stdout.strip():
        raise ValueError(f'empty output from {command}')
    return result.stdout


def verify_forwarding_consumer(root):
    spec = importlib.util.spec_from_file_location('forwarding', root / 'examples/consumers/forwarding.py')
    consumer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(consumer)

    def consume(document, output_format='json', exit_code=0):
        data = (json.dumps(document) + '\n').encode()
        return consumer.consume(io.BytesIO(data), output_format, exit_code)

    fixture = json.loads((root / 'examples/consumers/fixtures/forwarding.json').read_text())
    exit_code = 0 if fixture['result']['verdict'] == 'pass' else 1
    consume(fixture, 'ndjson', exit_code)
    terminal = copy.deepcopy(fixture)
    fixture['mode'] = 'aggregate'
    fixture.pop('event')
    fixture.pop('sequence')
    consume(fixture, exit_code=exit_code)
    error = json.loads((root / 'examples/documents/output-verify-forwarding-error.json').read_text())
    if consume(error, exit_code=2)['execution'] != 'error':
        raise ValueError('forwarding consumer lost the error envelope')

    def rejects(document, output_format='json', status=exit_code):
        try:
            consume(document, output_format, status)
        except consumer.ContractError:
            return
        raise ValueError('forwarding consumer accepted malformed or unsupported evidence')

    for version in (0, *range(2, 19), 999):
        invalid = copy.deepcopy(fixture)
        invalid['schema'] = f'packetcraftr.output/v{version}'
        rejects(invalid)
    invalid = copy.deepcopy(fixture)
    invalid['result']['verdict'] = 'unknown'
    rejects(invalid)
    invalid = copy.deepcopy(fixture)
    invalid['result']['summary']['checks_evaluated'] += 1
    rejects(invalid)
    rejects(fixture, status=1 - exit_code)
    invalid = copy.deepcopy(terminal)
    invalid['sequence'] = 1
    rejects(invalid, 'ndjson')
    invalid = copy.deepcopy(terminal)
    invalid['event'] = 'event'
    rejects(invalid, 'ndjson')
    trailing = (json.dumps(terminal) + '\n') * 2
    try:
        consumer.consume(io.BytesIO(trailing.encode()), 'ndjson', exit_code)
    except consumer.ContractError:
        pass
    else:
        raise ValueError('forwarding consumer accepted a record after the terminal')


def verify(root, version, commit, target, variant):
    root = root.resolve()
    binary = root / ('packetcraftr.exe' if 'windows' in target else 'packetcraftr')
    for asset in (*SOURCE_ASSETS, *GENERATED_ASSETS, binary.name):
        path = root / asset
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f'packaged {asset} is missing or empty')
    if json.loads((root / 'scripts/release-assets.json').read_text()) != MANIFEST:
        raise ValueError('packaged asset manifest differs from the release inventory')
    for directory in ('schemas', 'examples/documents', 'examples/consumers/fixtures'):
        expected = {asset for asset in SOURCE_ASSETS if asset.startswith(directory + '/')}
        actual = {path.relative_to(root).as_posix() for path in (root / directory).rglob('*')
                  if path.is_file()}
        if actual != expected:
            raise ValueError(f'packaged {directory} differs from the current asset inventory')
    # Keep manifest writing and verification under one identity implementation.
    subprocess.run([
        sys.executable, str(pathlib.Path(__file__).resolve().with_name('build-manifest.py')),
        '--binary', str(binary), '--verify', str(root / 'BUILD-METADATA.json'),
        '--commit', commit, '--target', target, '--variant', variant,
    ], cwd=root, check=True, timeout=60)

    verify_forwarding_consumer(root)

    def cli(*args):
        return run([str(binary), *args], root)

    if cli('--version').splitlines()[0] != f'packetcraftr {version}':
        raise ValueError('unexpected packaged version')
    cli('reference', 'protocols')
    built = cli('--output', 'hex', 'packet', 'build', '--packet',
                'ipv4(src=192.0.2.1,dst=198.51.100.2)/udp(sport=12345,dport=9)/raw(text=hello)')
    if built.strip() != EXPECTED:
        raise ValueError('unexpected build bytes')
    if cli('--output', 'hex', 'packet', 'dissect', '--link-type', '228', '--hex', EXPECTED).strip() != EXPECTED:
        raise ValueError('dissect did not preserve exact bytes')
    output = cli('--output', 'ndjson', 'files', 'read',
                 'examples/captures/tls-handshake.pcapng', '--max-frames', '100')
    if not output.endswith('\n'):
        raise ValueError('unterminated NDJSON output')
    records = [json.loads(line) for line in output.splitlines()]
    if not records or not all(isinstance(record, dict) for record in records):
        raise ValueError('expected NDJSON objects')
    if records[-1].get('event') != 'complete':
        raise ValueError('stream has no terminal completion')
    expected_frames = DECODE_PROFILES['curated']['tls-handshake']
    if len(records) != expected_frames + 1:
        raise ValueError(f'packaged capture must produce {expected_frames} frames and one completion')
    for index, record in enumerate(records):
        if (record.get('schema') != 'packetcraftr.output/v1'
                or type(record.get('sequence')) is not int
                or record['sequence'] != index
                or record.get('event') != ('complete' if index == len(records) - 1 else 'frame')):
            raise ValueError('stream has invalid schema, sequence or completion')
    cli('analyze', 'tls', 'examples/captures/tls-handshake.pcapng')
    json.loads(cli('--output', 'json', 'packet', 'build', '--packet-file',
                   'examples/documents/packet-ipv4-udp.json'))

    # Run the commands published in docs/analysis-resources.md from the archive,
    # and keep their clock and encapsulation evidence equal to the shipped examples.
    for capture, example, options in (
        ('clock-regression.pcap', 'output-stats-clock.json',
         ('--table', 'io', '--interval-ms', '1000')),
        ('scoped-vxlan.pcap', 'output-stats-scopes.json',
         ('--table', 'conversations')),
    ):
        actual = json.loads(cli('--output', 'json', 'analyze', 'stats',
                                f'examples/captures/{capture}', *options))
        expected = json.loads((root / 'examples/documents' / example).read_text(encoding='utf-8'))
        if actual != expected:
            raise ValueError(f'packaged stats output differs from {example}')

    overview = json.loads(cli('--output', 'json', 'analyze', 'stats',
                              'examples/captures/http-stream.pcap', '--table', 'overview'))
    if overview.get('schema') != 'packetcraftr.output/v1' or overview['result']['table'] != 'overview':
        raise ValueError('packaged overview must use output/v1')
    for rows, count in (('protocols', 'protocol_count'), ('endpoints', 'endpoint_count'),
                        ('conversations', 'conversation_count')):
        if len(overview['result'][rows]) > min(5, overview['result'][count]):
            raise ValueError(f'invalid overview leaderboard: {rows}')
    exported = cli('--output', 'csv', 'analyze', 'stats',
                   'examples/captures/http-stream.pcap', '--table', 'endpoints', '--sort', 'bytes')
    records = list(csv.reader(io.StringIO(exported)))
    if not records or records[0] != ['address', 'tx_frames', 'tx_bytes', 'rx_frames', 'rx_bytes']:
        raise ValueError('packaged CSV has invalid endpoint headers')
    if any(len(row) != 5 for row in records):
        raise ValueError('packaged CSV must contain only endpoint records')

    # Discover grouped commands through registry-backed
    # help, then verify their packaged pages without a separate inventory file.
    def commands(help_text):
        _, heading, body = help_text.partition('Commands:\n')
        if not heading:
            raise ValueError('packaged help has no command list')
        section = body.split('\n\n', 1)[0]
        return [name for name in re.findall(r'^  ([a-z][a-z0-9-]*) {2,}', section, re.MULTILINE)
                if name != 'help']

    groups = commands(cli('--help'))
    if set(groups) != {'packet', 'files', 'analyze', 'network', 'reference'}:
        raise ValueError('packaged help must list the five workflow groups')
    paths = []
    for group in groups:
        for command in commands(cli(group, '--help')):
            canonical = f'{group} {command}'
            help_text = cli(group, command, '--help')
            if f'Command: packetcraftr {canonical}.' not in help_text:
                raise ValueError(f'packaged help for {canonical} has no command path')
            if 'Legacy alias:' in help_text:
                raise ValueError(f'packaged help for {canonical} advertises a removed path')
            paths.append(canonical)
    if len(paths) != 38:
        raise ValueError('packaged help must describe all 38 commands')
    for path in [*groups, *paths]:
        name = path.replace(' ', '-')
        page = root / 'man' / f'packetcraftr-{name}.1'
        if not page.is_file() or page.stat().st_size == 0:
            raise ValueError(f'packaged man page for {path} is missing or empty')
        cli(*path.split(), '--help')
    for path in paths:
        flat = 'dns-read' if path == 'analyze dns' else path.split()[1]
        removed = subprocess.run([str(binary), flat, '--help'], cwd=root,
                                 capture_output=True, timeout=60)
        if removed.returncode != 2:
            raise ValueError(f'removed flat command {flat} did not fail with usage exit 2')
        if (root / 'man' / f'packetcraftr-{flat}.1').exists():
            raise ValueError(f'archive contains removed flat manual: {flat}')
    for file in (root / 'completions').iterdir():
        completion = file.read_text(encoding='utf-8')
        if not all(group in completion for group in groups):
            raise ValueError(f'completion {file.name} is missing workflow groups')


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
