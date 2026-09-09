#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Archive public API snapshots and a release diff without checking out over user work."""
import argparse
import difflib
import json
import os
import pathlib
import subprocess
import tarfile
import tempfile

from validation_evidence import ROOT, digest

TOOLCHAIN = 'nightly-2026-08-28'
TOOL_VERSION = '0.52.0'
CRATES = ['packetcraftr-core', 'packetcraftr-netio', 'packetcraftr', 'packetcraftr-cli']


def snapshots(root, output, label, env):
    lock = root / 'Cargo.lock'
    before = digest(lock)
    subprocess.run(['cargo', 'fetch', '--locked', '--manifest-path', str(root / 'Cargo.toml')],
                   cwd=root, check=True, timeout=300)
    for crate in CRATES:
        command = ['cargo', f'+{TOOLCHAIN}', 'public-api', '--color', 'never', '--omit', 'blanket-impls',
                   '--all-features', '--manifest-path', str(root / 'Cargo.toml'), '-p', crate]
        with (output / f'{crate}.{label}.log').open('w') as log:
            result = subprocess.run(command, cwd=root, env=dict(env, CARGO_NET_OFFLINE='true'),
                                    stdout=subprocess.PIPE, stderr=log, text=True, timeout=900)
        if result.returncode:
            raise RuntimeError(f'{crate} {label}: public API generation failed; see log')
        if not result.stdout.startswith('pub mod '):
            raise RuntimeError(f'{crate} {label}: missing public API output')
        (output / f'{crate}.{label}.txt').write_text(result.stdout)
    if digest(lock) != before:
        raise RuntimeError(f'API inspection unexpectedly changed {lock}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', help='git revision; defaults to the preceding release tag')
    parser.add_argument('--output', type=pathlib.Path, default=ROOT / 'target/public-api')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = dict(status='failed', inspection_toolchain=TOOLCHAIN, tool_version=TOOL_VERSION,
                  features='all-features', crates=[],
                  interpretation='Signature diffs require review; absence of removed lines is not a semantic compatibility proof.')
    try:
        version = subprocess.check_output(['cargo', 'public-api', '--version'], text=True).strip()
        if version != f'cargo-public-api {TOOL_VERSION}':
            raise RuntimeError(f'expected cargo-public-api {TOOL_VERSION}, found {version}')
        report['commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        report['dirty'] = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT))
        baseline = args.baseline or subprocess.check_output(['git', 'describe', '--tags', '--abbrev=0', 'HEAD^'], cwd=ROOT, text=True).strip()
        report['baseline'] = subprocess.check_output(['git', 'rev-parse', f'{baseline}^{{commit}}'], cwd=ROOT, text=True).strip()
        env = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / 'target/api-inspection-build'))
        snapshots(ROOT, output, 'current', env)
        with tempfile.TemporaryDirectory(prefix='packetcraftr-api-') as temporary:
            root = pathlib.Path(temporary)
            archive = root / 'baseline.tar'
            subprocess.run(['git', 'archive', '--format=tar', '--output', str(archive), report['baseline']], cwd=ROOT, check=True)
            with tarfile.open(archive) as source:
                source.extractall(root, filter='data')
            archive.unlink()
            snapshots(root, output, 'baseline', env)
        changes = []
        for crate in CRATES:
            old = (output / f'{crate}.baseline.txt').read_text().splitlines(keepends=True)
            new = (output / f'{crate}.current.txt').read_text().splitlines(keepends=True)
            changes.extend(difflib.unified_diff(old, new, fromfile=f'{crate}@{baseline}', tofile=f'{crate}@current'))
            report['crates'].append(dict(name=crate, baseline_lines=len(old), current_lines=len(new),
                                        removed_lines=len(set(old) - set(new)), added_lines=len(set(new) - set(old)),
                                        baseline_sha256=digest(output / f'{crate}.baseline.txt'),
                                        current_sha256=digest(output / f'{crate}.current.txt')))
        (output / 'API-DIFF.txt').write_text(''.join(changes) or 'No public signature changes.\n')
        report['status'] = 'passed'
    except Exception as error:
        report['error'] = str(error)
    finally:
        (output / 'public-api.json').write_text(json.dumps(report, indent=2) + '\n')
    print(output / 'public-api.json')
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
