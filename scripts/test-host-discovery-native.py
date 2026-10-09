#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""M5 native discovery: fresh Linux namespaces or admitted host-local sockets/packets."""
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

from discovery_isolated_fixture import provision
from discovery_native_evidence import SCHEMA, inventory, status, validate
from discovery_native_fixture import host_cases, link_cases, measurements, socket_cases, unavailable
from native_platform_evidence import PROFILES
from validation_evidence import ROOT, digest

spec = importlib.util.spec_from_file_location('host_native', pathlib.Path(__file__).with_name('test-native-platform.py'))
host_native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host_native)


def current_platform():
    return 'macOS' if platform.system() == 'Darwin' else platform.system()


def initial_report(profiles):
    corpus = ROOT / 'docs/scanner-corpus.v1.json'
    return dict(schema=SCHEMA, platform=current_platform(),
                commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True, timeout=30).strip(),
                dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, timeout=30)),
                corpus_sha256=digest(corpus), corpus_dataset_version=measurements.load_corpus(corpus)[0]['dataset_version'],
                fixture_sha256=digest(pathlib.Path(__file__).with_name('discovery_native_fixture.py')),
                peer_fixture_sha256=digest(pathlib.Path(__file__).with_name('discovery_isolated_fixture.py')),
                launcher_sha256=digest(__file__),
                profiles=[dict(name=name, status='incomplete', scenarios=[
                    unavailable(case, family, 'runtime_evidence_missing', 'Native discovery has not executed.')
                    for case, family in inventory()]) for name in profiles], status='incomplete')


def child(args):
    namespace = os.stat('/proc/self/ns/net').st_ino
    if (namespace == args.parent_namespace or args.parent_namespace <= 0 or
            {name for _, name in socket.if_nameindex()} != {'lo'}):
        raise RuntimeError('refusing discovery fixtures outside a fresh private namespace')
    evidence = dict(isolation=dict(kind='fresh_network_namespace', namespace=namespace,
                                   parent_namespace=args.parent_namespace), scenarios=[])
    try:
        with provision() as received:
            evidence['scenarios'] = link_cases(args.binary, measurements.load_corpus(ROOT / 'docs/scanner-corpus.v1.json')[0], received)
            evidence['scenarios'] += socket_cases(args.binary)
            evidence['peer_requests'] = received
    except Exception as error:
        evidence['error'] = str(error)
    args.report.write_text(json.dumps(evidence, indent=2) + '\n')
    return 1 if evidence.get('error') or any(case['status'] == 'failed' for case in evidence['scenarios']) else 0


def privileged():
    if platform.system() != 'Windows':
        return os.geteuid() == 0
    import ctypes
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def captured(command, timeout):
    """Retain timeout diagnostics; a terminated child never counts as success."""
    try:
        process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        return dict(command=command, exit_code=process.returncode, stdout=process.stdout, stderr=process.stderr)
    except subprocess.TimeoutExpired as error:
        def text(value):
            return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else value or ''
        return dict(command=command, exit_code=None, stdout=text(error.stdout), stderr=text(error.stderr),
                    error='process exceeded its finite timeout')


def execute(args, report):
    if args.emit_unavailable:
        return
    if report['dirty'] or report['commit'] != args.reviewed_commit:
        raise ValueError('native discovery requires the exact clean, self-reviewed commit')
    if not privileged():
        for profile in report['profiles']:
            profile['scenarios'] = [unavailable(case, family, 'privilege_not_granted',
                'Explicit root/administrator admission was not granted for this reviewed native route.')
                for case, family in inventory()]
        return
    corpus = measurements.load_corpus(ROOT / 'docs/scanner-corpus.v1.json')[0]
    for profile in report['profiles']:
        command = ['cargo', 'build', '--locked', '-p', 'packetcraftr-cli',
                   *host_native.FEATURES[profile['name']], '--message-format=json']
        built = captured(command, timeout=900)
        profile['build'] = dict(built, execution='compilation')
        if built['exit_code'] != 0:
            profile['error'] = 'native CLI build failed; compilation is not runtime evidence'
            raise RuntimeError(profile['error'])
        binary, = [row['executable'] for row in map(json.loads, built['stdout'].splitlines())
                   if row.get('reason') == 'compiler-artifact' and row.get('executable')
                   and row.get('target', {}).get('name') == 'packetcraftr']
        directory = args.report.parent / profile['name']
        directory.mkdir(parents=True, exist_ok=True)
        if current_platform() == 'Linux' and 'SUDO_UID' in os.environ:
            os.chown(directory, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))
        preserved = directory / pathlib.Path(binary).name
        shutil.copy2(binary, preserved)
        profile.update(binary_sha256=digest(preserved), execution='privileged_native', privilege_granted=True)
        if current_platform() == 'Linux':
            namespace = os.stat('/proc/self/ns/net').st_ino
            mapping = ['--map-root-user']
            if 'SUDO_UID' in os.environ:
                mapping = [f"--map-users=0:{int(os.environ['SUDO_UID'])}:1",
                           f"--map-groups=0:{int(os.environ['SUDO_GID'])}:1", '--setuid=0', '--setgid=0']
            child_report = directory / 'fixtures.json'
            child_report.unlink(missing_ok=True)
            command = ['unshare', '--user', *mapping, '--net', sys.executable, str(pathlib.Path(__file__).resolve()),
                       '--binary', str(preserved), '--report', str(child_report), '--parent-namespace', str(namespace)]
            output = captured(command, timeout=180)
            profile['launcher'] = output
            if not child_report.exists():
                profile['scenarios'] = [unavailable(case, family, 'isolation_unavailable',
                    'Fresh network namespace admission failed; launcher output is preserved.') for case, family in inventory()]
                continue
            evidence = measurements.strict_json(child_report.read_text())
            if evidence.get('error'):
                raise RuntimeError(evidence['error'])
            profile.update(isolation=evidence['isolation'], scenarios=evidence['scenarios'])
            if output['exit_code'] != 0 and not any(case['status'] == 'failed' for case in profile['scenarios']):
                raise RuntimeError('failed namespace process cannot close a native discovery scenario')
        else:
            profile.update(isolation=dict(kind='host_local_only', external_destinations=False, interface_mutation=False),
                           scenarios=host_cases(preserved, corpus) + socket_cases(preserved))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reviewed-commit')
    parser.add_argument('--profiles', nargs='+', choices=PROFILES, default=list(PROFILES))
    parser.add_argument('--emit-unavailable', action='store_true')
    parser.add_argument('--require-complete', action='store_true')
    parser.add_argument('--report', type=pathlib.Path, required=True)
    parser.add_argument('--binary', type=pathlib.Path, help=argparse.SUPPRESS)
    parser.add_argument('--parent-namespace', type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if current_platform() not in ('Linux', 'macOS', 'Windows'):
        parser.error('supported native platforms are Linux, macOS, and Windows')
    if args.profiles != [name for name in PROFILES if name in args.profiles]:
        parser.error('profiles must be unique and in portable/default/layer2/pcap-free/full-native order')
    args.report = args.report.resolve()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    if args.parent_namespace is not None:
        if current_platform() != 'Linux' or args.binary is None:
            parser.error('private namespace child requires Linux and its selected binary')
        return child(args)
    report = initial_report(args.profiles)
    try:
        execute(args, report)
        if not args.emit_unavailable:
            settled = initial_report(args.profiles)
            bindings = ('commit', 'corpus_sha256', 'fixture_sha256', 'peer_fixture_sha256', 'launcher_sha256')
            if settled['dirty'] or any(settled[key] != report[key] for key in bindings):
                raise ValueError('native discovery sources or revision changed during execution')
    except Exception as error:
        report['error'] = str(error)
    finally:
        for profile in report['profiles']:
            profile['status'] = status(profile['scenarios'])
        report['status'] = status([case for profile in report['profiles'] for case in profile['scenarios']])
        try:
            validate(report, expected_commit=args.reviewed_commit, require_complete=args.require_complete)
        except (ValueError, KeyError, TypeError) as error:
            report['validation_error'] = str(error)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(args.report)
    return 1 if report.get('error') or report.get('validation_error') or report['status'] == 'failed' else 0


if __name__ == '__main__':
    raise SystemExit(main())
