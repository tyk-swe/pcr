#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""M4 scoped evidence across Linux profiles, using fresh private namespaces."""
import argparse
import importlib.util
import json
import os
import pathlib
import platform
import shutil
import socket
import subprocess
import sys

from native_platform_evidence import PROFILES, SCOPED_MARKER, scoped_paths, status_of, validate
from validation_evidence import ROOT, digest


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, pathlib.Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


isolated = load('isolated', 'test-native-isolated.py')
host = load('host', 'test-native-platform.py')


def child(args):
    namespace = os.stat('/proc/self/ns/net').st_ino
    if namespace == args.parent_namespace or {name for _, name in socket.if_nameindex()} != {'lo'}:
        raise RuntimeError('refusing M4 fixtures outside a fresh private network namespace')
    isolated.ip('link', 'set', 'lo', 'up')
    result = dict(namespace=namespace, parent_namespace=args.parent_namespace)
    try:
        isolated.scoped_ipv6(args.binary, result, args.profile)
        print(SCOPED_MARKER + json.dumps(result['scoped_paths']), flush=True)
    except Exception as error:
        result.update(status='failed', error=str(error))
    args.report.write_text(json.dumps(result, indent=2) + '\n')
    return 0 if result.get('status') == 'passed' else 1


def parent(args):
    report = host.unavailable_report('Only M4 scoped target evidence is selected.')
    if report['dirty']:
        raise RuntimeError('M4 profile evidence requires a clean implementation revision')
    namespace = os.stat('/proc/self/ns/net').st_ino
    mapping = ['--map-root-user']
    if os.geteuid() == 0 and 'SUDO_UID' in os.environ:
        uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
        mapping = [f'--map-users=0:{uid}:1', f'--map-groups=0:{gid}:1', '--setuid=0', '--setgid=0']
    for profile in report['profiles']:
        command = ['cargo', 'build', '--locked', '-p', 'packetcraftr-cli',
                   *host.FEATURES[profile['name']], '--message-format=json']
        built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=900)
        profile['cli_build'] = dict(command=command, exit_code=built.returncode, stdout=built.stdout,
                                    stderr=built.stderr, execution='compilation')
        if built.returncode:
            report['error'] = 'CLI profile build failed'
            break
        binary, = [row['executable'] for row in map(json.loads, built.stdout.splitlines())
                   if row.get('reason') == 'compiler-artifact' and row.get('executable')
                   and row.get('target', {}).get('name') == 'packetcraftr']
        directory = args.report.parent / profile['name']
        directory.mkdir(parents=True, exist_ok=True)
        if os.geteuid() == 0 and 'SUDO_UID' in os.environ:
            os.chown(directory, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))
        preserved = directory / 'packetcraftr'
        shutil.copy2(binary, preserved)
        profile.update(binary_sha256=digest(preserved), test_binary_sha256=digest(__file__),
                       interpreter_sha256=digest(sys.executable))
        child_report = directory / 'scoped.json'
        child_report.unlink(missing_ok=True)
        command = ['unshare', '--user', *mapping, '--net', sys.executable, str(pathlib.Path(__file__).resolve()),
                   '--binary', str(preserved), '--profile', profile['name'], '--report', str(child_report),
                   '--parent-namespace', str(namespace)]
        scenario = next(item for item in profile['scenarios'] if item['name'] == 'scoped_ipv6_targets')
        for field in ('reason', 'reason_code'):
            scenario.pop(field, None)
        scenario.update(command=command, execution='privileged_native', privilege_granted=True, status='failed')
        try:
            output = subprocess.run(command, capture_output=True, text=True, timeout=120)
            scenario.update(exit_code=output.returncode, stdout=output.stdout, stderr=output.stderr)
            evidence = json.loads(child_report.read_text()) if child_report.exists() else {}
            scenario['fixture'] = evidence
            if evidence.get('namespace') and evidence.get('parent_namespace') == namespace:
                report['isolation'] = dict(kind='fresh_network_namespace', namespace=evidence['namespace'],
                                          parent_namespace=evidence['parent_namespace'])
                scenario['isolation'] = report['isolation'].copy()
            else:
                scenario.update(status='unavailable', reason_code='isolation_unavailable',
                                reason='Fresh namespace admission was not established.', privilege_granted=False)
            if output.returncode or evidence.get('status') != 'passed':
                scenario['error'] = evidence.get('error', 'private namespace scenario did not pass')
            else:
                paths = scoped_paths(output.stdout)
                if paths != evidence['scoped_paths']:
                    raise ValueError('preserved fixture and process output disagree')
                scenario.update(status='exercised', scoped_paths=paths)
        except subprocess.TimeoutExpired as error:
            scenario.update(exit_code=-1, stdout=(error.stdout or b'').decode(),
                            stderr=(error.stderr or b'').decode(), error=str(error))
        except Exception as error:
            scenario.setdefault('exit_code', -1)
            scenario.setdefault('stdout', '')
            scenario.setdefault('stderr', '')
            scenario['error'] = str(error)
    for profile in report['profiles']:
        profile['status'] = status_of(profile['scenarios'])
    report['status'] = status_of([item for profile in report['profiles'] for item in profile['scenarios']])
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    validate(report)
    return 0 if not report.get('error') and all(next(item for item in profile['scenarios']
        if item['name'] == 'scoped_ipv6_targets')['status'] == 'exercised' for profile in report['profiles']) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=pathlib.Path, default=ROOT / 'target/validation/m4-linux/native-platform.json')
    parser.add_argument('--binary', type=pathlib.Path, help=argparse.SUPPRESS)
    parser.add_argument('--profile', choices=PROFILES, help=argparse.SUPPRESS)
    parser.add_argument('--parent-namespace', type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if platform.system() != 'Linux':
        parser.error('this route requires Linux user/network namespaces')
    args.report = args.report.resolve()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    if args.parent_namespace is not None:
        if args.binary is None or args.profile is None:
            parser.error('namespace child requires the selected binary and profile')
        return child(args)
    return parent(args)


if __name__ == '__main__':
    raise SystemExit(main())
