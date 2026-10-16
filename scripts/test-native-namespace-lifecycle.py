#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Run N1's exact ignored test in a fresh isolated Linux user/network namespace.

This standalone report is not the frozen native schema_version: 2 release
inventory. A blocked namespace launcher is never successful runtime evidence.
"""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEST = 'platform::common::netlink::tests::namespace_churn::real_namespace_churn_recovers_resources'
FAMILY = 'packetcraftr.namespace-lifecycle/v1'


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def test_binary(args):
    if args.test_binary:
        return args.test_binary.resolve()
    matches = []
    for line in args.build_report.read_text().splitlines():
        record = json.loads(line)
        if (record.get('reason') == 'compiler-artifact'
                and record.get('target', {}).get('name') == 'packetcraftr_netio'
                and record.get('profile', {}).get('test') is True
                and record.get('executable')):
            matches.append(pathlib.Path(record['executable']).resolve())
    if len(matches) != 1:
        raise ValueError('build report must identify exactly one netio library test executable')
    return matches[0]


def validate_metrics(metrics, namespace, parent):
    ids = metrics.get('namespace_ids')
    if (not isinstance(ids, list) or len(ids) <= 16
            or any(type(value) is not int or value <= 0 for value in ids)
            or len(ids) != len(set(ids)) or namespace in ids or parent in ids):
        raise ValueError('test did not establish more than 16 distinct real namespace identities')
    if metrics.get('initial_namespace') != namespace or metrics.get('parent_namespace') != parent:
        raise ValueError('test namespace identity disagrees with isolated launcher')
    for name in ('resident_capacity', 'resident_peak', 'native_capacity', 'root_peak',
                 'root_recovered', 'fd_peak', 'fd_bound_peak', 'concurrent_request_rounds'):
        if type(metrics.get(name)) is not int or metrics[name] < 0:
            raise ValueError(f'missing nonnegative metric {name}')
    if (metrics['resident_capacity'] <= 0
            or metrics['native_capacity'] <= 0
            or len(ids) <= metrics['native_capacity']
            or metrics['resident_capacity'] > metrics['native_capacity']
            or metrics['resident_peak'] > metrics['resident_capacity']
            or metrics['root_peak'] > metrics['native_capacity']
            or metrics['root_recovered'] != 0
            or metrics['fd_peak'] > metrics['fd_bound_peak']
            or metrics['concurrent_request_rounds'] < 1
            or metrics.get('loopback_connected') is not True
            or metrics.get('control_completed') is not True):
        raise ValueError('native ownership or post-churn work did not satisfy its bounds')


def run(args, binary, report):
    if platform.system() != 'Linux':
        report['status'] = 'unsupported'
        raise RuntimeError('this runtime test requires Linux user/network namespaces')
    listed = subprocess.run([str(binary), '--list', '--exact', TEST], capture_output=True,
                            text=True, check=True, timeout=15)
    if f'{TEST}: test' not in listed.stdout:
        raise RuntimeError('executable does not contain the exact native namespace test')
    namespace = os.stat('/proc/self/ns/net').st_ino
    if args.parent_fd is None:
        mapping = ['--map-root-user']
        if os.geteuid() == 0 and 'SUDO_UID' in os.environ:
            uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
            mapping = [f'--map-users=0:{uid}:1', f'--map-groups=0:{gid}:1', '--setuid=0', '--setgid=0']
        parent_fd = os.open('/proc/self/ns/net', os.O_RDONLY)
        try:
            command = ['unshare', '--user', *mapping, '--net', sys.executable, str(pathlib.Path(__file__).resolve()),
                       '--test-binary', str(binary), '--report', str(args.report),
                       '--parent-fd', str(parent_fd), '--run-id', report['run_id']]
            result = subprocess.run(command, capture_output=True, text=True, timeout=110,
                                    pass_fds=(parent_fd,))
        finally:
            os.close(parent_fd)
        launcher = dict(command=command, exit_code=result.returncode, stdout=result.stdout,
                        stderr=result.stderr)
        if args.report.exists():
            child = json.loads(args.report.read_text())
            if child.get('run_id') == report['run_id'] and child.get('parent_namespace') == namespace:
                report.update(child)
            elif child.get('run_id') == report['run_id']:
                launcher['child_failure'] = child
        report['namespace_launcher'] = launcher
        if result.returncode:
            if 'Operation not permitted' in result.stderr and 'namespace' not in report:
                report['status'] = 'blocked'
            raise RuntimeError('isolated namespace launcher or lifecycle test failed')
        if report.get('status') != 'passed':
            raise RuntimeError('launcher returned without matching successful child evidence')
        return
    parent_fd = args.parent_fd
    if parent_fd < 3 or not os.readlink(f'/proc/self/fd/{parent_fd}').startswith('net:['):
        raise RuntimeError('missing inherited parent network-namespace descriptor')
    parent = os.fstat(parent_fd).st_ino
    report.update(namespace=namespace, parent_namespace=parent)
    interfaces = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show'], text=True, timeout=10))
    if namespace == parent or {link['ifname'] for link in interfaces} != {'lo'}:
        raise RuntimeError('refusing a non-fresh or non-loopback-only namespace')
    environment = os.environ.copy()
    environment['PACKETCRAFTR_N1_PARENT_FD'] = str(parent_fd)
    command = [str(binary), '--exact', TEST, '--ignored', '--nocapture', '--test-threads=1']
    result = subprocess.run(command, capture_output=True, text=True, timeout=90,
                            env=environment, pass_fds=(parent_fd,))
    report['test'] = dict(command=command, exit_code=result.returncode, stdout=result.stdout,
                          stderr=result.stderr)
    if result.returncode:
        raise RuntimeError('native namespace test failed')
    matches = re.findall(r'N1_NAMESPACE_LIFECYCLE (\{[^\n]*\})', result.stdout)
    if len(matches) != 1 or not re.search(r'1 passed; 0 failed; 0 ignored;', result.stdout):
        raise RuntimeError('exact ignored test did not execute exactly once')
    metrics = json.loads(matches[0])
    validate_metrics(metrics, namespace, parent)
    report.update(metrics=metrics, status='passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--test-binary', type=pathlib.Path)
    source.add_argument('--build-report', type=pathlib.Path,
                        help='Cargo --message-format=json output from netio --lib --no-run')
    parser.add_argument('--report', type=pathlib.Path, default=ROOT / 'target/native-namespace-lifecycle.json')
    parser.add_argument('--parent-fd', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--run-id', help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.report = args.report.resolve()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report = dict(schema=FAMILY, status='failed', run_id=args.run_id or str(uuid.uuid4()),
                  os=platform.platform(), test_name=TEST,
                  os_initialization_failure='not_exercised', namespace_identity_reuse='not_exercised')
    try:
        binary = test_binary(args)
        report.update(test_executable=str(binary), test_executable_sha256=digest(binary),
                      commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True, timeout=30).strip(),
                      dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, timeout=30)),
                      launcher_sha256=digest(pathlib.Path(__file__).resolve()))
        run(args, binary, report)
    except Exception as error:
        report['error'] = str(error)
    finally:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        if args.parent_fd is None and os.geteuid() == 0 and 'SUDO_UID' in os.environ:
            os.chown(args.report, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))
    print(args.report)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
