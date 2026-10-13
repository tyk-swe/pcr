#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Revision-bound M12 checks in fresh Linux namespaces or host-local sockets.

No external destinations, host interface changes, DNS, or driver installation.
"""
import argparse
import contextlib
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import time

from native_platform_evidence import PROFILES, status_of
from tcp_diagnostic_corpus import validate as validate_corpus
import tcp_diagnostic_native_evidence as evidence
from validation_evidence import ROOT, digest


def git(*args):
    return subprocess.check_output(['git', '-c', 'safe.directory=' + str(ROOT), *args], cwd=ROOT, text=True, timeout=30).strip()

FEATURES = {'portable': ['--no-default-features'], 'default': [],
            'layer2': ['--no-default-features', '--features', 'native-layer2'],
            'pcap-free': ['--no-default-features', '--features', 'native-layer3'],
            'full-native': ['--all-features']}
SOURCES = ('scripts/test-tcp-diagnostics-native.py', 'scripts/tcp_diagnostic_native_evidence.py',
           'scripts/tcp_diagnostic_isolated_fixture.py', 'scripts/tcp_diagnostic_wire.py',
           'scripts/tcp_diagnostic_capture.py', 'scripts/tcp_diagnostic_corpus.py', 'scripts/tcp_diagnostic_kernel_fixture.py', 'scripts/discovery_isolated_fixture.py',
           'scripts/validation_evidence.py', 'scripts/native_platform_evidence.py', 'scripts/benchmark-scanner.py',
           'docs/scanner-corpus.v1.json', 'schemas/packetcraftr.scanner-corpus.v1.schema.json',
           'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml')


def source_identity():
    paths = set(SOURCES)
    paths.update(str(path.relative_to(ROOT)) for path in (ROOT / 'crates').rglob('*')
                 if path.is_file() and (path.suffix == '.rs' or path.name == 'Cargo.toml'))
    return {path: digest(ROOT / path) for path in sorted(paths)}


def write(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')


def capture_version():
    try:
        from tcp_diagnostic_capture import library
        return library().pcap_lib_version().decode('utf-8', errors='replace')
    except (OSError, AttributeError):
        return None


def privileged():
    return bool(ctypes.windll.shell32.IsUserAnAdmin()) if platform.system() == 'Windows' else os.geteuid() == 0


def measurements():
    spec = importlib.util.spec_from_file_location('m12_measurements', ROOT / 'scripts/benchmark-scanner.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cargo_record(args, log):
    measurement = measurements()
    measurement.PROCESS_TIMEOUT = 900
    try:
        record = measurement.measured(args)
    except Exception as error:
        def retained(value):
            return (value.decode('utf-8', errors='replace') if isinstance(value, bytes) else str(value or ''))[:1048576]
        record = dict(command=args, exit_code=None, stdout=retained(getattr(error, 'output', '')),
                      stderr=retained(getattr(error, 'stderr', '')), error=str(error),
                      timed_out=isinstance(error, subprocess.TimeoutExpired))
        write(log, record)
        raise RuntimeError('native Cargo command failed; retained ' + str(log)) from error
    write(log, record)
    if record['exit_code']:
        raise RuntimeError('native Cargo command failed; retained ' + str(log))
    return record


def build(profile, report_path, offline=False):
    args = ['cargo', 'build', '--locked', '-p', 'packetcraftr-cli', '--message-format=json', *FEATURES[profile]]
    if offline:
        args.append('--offline')
    log = report_path.parent / ('tcp-diagnostics-build-' + profile + '.json')
    record = cargo_record(args, log)
    artifacts = [json.loads(line) for line in record['stdout'].splitlines() if line.startswith('{')]
    paths = [item['executable'] for item in artifacts if item.get('reason') == 'compiler-artifact' and item.get('executable') and item.get('target', {}).get('name') == 'packetcraftr']
    if len(set(paths)) != 1:
        raise ValueError('build lacks unique CLI artifact')
    binary = report_path.parent / ('packetcraftr-tcp-' + profile + ('.exe' if platform.system() == 'Windows' else ''))
    shutil.copy2(paths[0], binary)
    return binary.resolve(), dict(path=str(log), digest_sha256=digest(log), command=args, exit_code=0)


@contextlib.contextmanager
def sockets(profile):
    owned = []
    provisioned = {}
    try:
        for family, native, target in (('ipv4', socket.AF_INET, '127.0.0.1'), ('ipv6', socket.AF_INET6, '::1')):
            created = []
            try:
                for port, listen in ((43123, True), (43125, False)):
                    channel = socket.socket(native, socket.SOCK_STREAM)
                    owned.append(channel)
                    created.append(channel)
                    if native == socket.AF_INET6:
                        channel.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    channel.bind((target, port))
                    if listen:
                        channel.listen(128)
                provisioned[family] = dict(target=target, listening_port=43123,
                    reserved_non_listening_port=43125, syn_control_required=True)
            except OSError as error:
                for channel in created:
                    channel.close()
                profile.setdefault('kernel_fixture_errors', {})[family] = str(error)
        profile['kernel_fixture'] = provisioned
        yield provisioned
    finally:
        for channel in owned:
            channel.close()
        profile['kernel_cleanup'] = 'sockets_closed'


def execute(binary, case, corpus, measurement, link_mode='layer3'):
    target = (evidence.SCRIPTED_TARGETS if case['provision'] == 'scripted' else evidence.kernel_targets('Linux' if platform.system() == 'Linux' else platform.system()))[case['family'] == 'ipv6']
    ports = list(range(1000, 1008)) if case['provision'] == 'scripted' else [43123, 43125]
    command = evidence.command(binary, case, target, ports, link_mode)
    started = time.time_ns()
    try:
        run = measurement.measured(command)
    except (subprocess.TimeoutExpired, ValueError, OSError) as error:
        raw_out, raw_err = getattr(error, 'stdout', ''), getattr(error, 'stderr', '')
        def text(value):
            return (value.decode('utf-8', errors='replace') if isinstance(value, bytes) else value or '')[:1048576]
        return dict(command=command, stdout=text(raw_out), stderr=text(raw_err), exit_code=None,
                    limits=evidence.LIMITS, link_mode=link_mode, started_unix_ns=started,
                    finished_unix_ns=time.time_ns(), timed_out=isinstance(error, subprocess.TimeoutExpired),
                    error=dict(code='fixture.process', message=str(error)))
    run.update(command=command, limits=evidence.LIMITS, link_mode=link_mode, platform={'Darwin':'macOS'}.get(platform.system(), platform.system()),
               started_unix_ns=started, finished_unix_ns=time.time_ns())
    try:
        docs = evidence.documents(run, case['output'], successful=False)
        if run['exit_code'] or any(doc.get('status') != 'success' for doc in docs):
            run['error'] = docs[-1].get('error') or dict(code='fixture.process', message='native command failed')
        else:
            run['observation'] = evidence.validate_output(run, case, corpus)
    except Exception as error:
        run['error'] = dict(code='fixture.contradiction', message=str(error))
    return run


def classify(case, run, profile):
    case['run'] = run
    if 'error' not in run:
        case.update(status='exercised')
        case.pop('reason', None)
        case.pop('message', None)
    elif run['error'].get('code') in ('capability.unsupported', 'capability.route'):
        case.update(status='unavailable', reason='unsupported_capability', message=run['error'].get('message', 'typed native refusal'),
                    expected_refusal=profile in ('portable', 'default', 'pcap-free') or profile == 'layer2' and case['provision'] == 'kernel' and platform.system() != 'Linux')
    else:
        case.update(status='failed', message=run['error'].get('message', 'native fixture failed'))
        case.pop('reason', None)


def run_profile(profile, args, report, corpus, measurement):
    binary, build_record = build(profile['profile'], args.report, offline=getattr(args, 'inside', False))
    profile.update(binary=str(binary), binary_digest_sha256=digest(binary), build=build_record,
                   execution='privileged_native', privilege_granted=True,
                   capture_backend_version=capture_version(), kernel=platform.release(), architecture=platform.machine())
    if platform.system() == 'Linux':
        profile['isolation'] = dict(kind='fresh_network_namespace', netns_inode=os.stat('/proc/self/ns/net').st_ino,
                                    parent_netns_inode=args.parent_netns, initial_interfaces=['lo'])
    else:
        profile['isolation'] = dict(kind='host_local_only', external_destinations=False, interface_mutation=False)
    link_mode = 'layer2' if profile['profile'] == 'layer2' else 'layer3'
    if platform.system() == 'Linux':
        from tcp_diagnostic_isolated_fixture import provision
        profile['independent_peer'] = dict(requests=[], setup=[])
        with provision(profile['independent_peer']):
            for case in profile['cases']:
                if case['provision'] == 'scripted':
                    classify(case, execute(binary, case, corpus, measurement, link_mode), profile['profile'])
                    write(args.report, report)
        from tcp_diagnostic_kernel_fixture import provision as kernel_provision
    else:
        for case in profile['cases']:
            if case['provision'] == 'scripted':
                case.update(reason='isolation_unavailable', message='host-local route has no isolated independent link peer')
    with (kernel_provision(profile) if platform.system() == 'Linux' else sockets(profile)) as provisioned:
        from tcp_diagnostic_capture import provision as capture_provision
        targets = evidence.kernel_targets('Linux' if platform.system() == 'Linux' else 'host')
        device = 'pcrm12ks' if platform.system() == 'Linux' else None
        capture_available = bool(profile['capture_backend_version'])
        with (capture_provision(targets, device) if capture_available else contextlib.nullcontext(None)) as capture:
            profile['kernel_capture'] = capture
            for case in profile['cases']:
                if case['provision'] != 'kernel':
                    continue
                if case['family'] not in provisioned:
                    case.update(reason='isolation_unavailable', message='could not reserve independently known native sockets')
                    continue
                run = execute(binary, case, corpus, measurement, link_mode)
                classify(case, run, profile['profile'])
                if not capture_available and not case.get('expected_refusal'):
                    case.update(status='unavailable', reason='backend_not_installed',
                                message='existing independent capture backend unavailable; retained attempted CLI execution')
                write(args.report, report)
    if digest(binary) != profile['binary_digest_sha256']:
        raise ValueError('native executable changed during execution')
    for case in profile['cases']:
        if case['status'] == 'exercised':
            run = case['run']
            try:
                evidence.validate_output(run, case, corpus, evidence.preparation_frames(profile, case, run))
            except ValueError as error:
                run['error'] = dict(code='fixture.contradiction', message=str(error))
                classify(case, run, profile['profile'])
    profile['status'] = status_of(profile['cases'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reviewed-commit', required=True)
    parser.add_argument('--profiles', default=','.join(PROFILES))
    parser.add_argument('--report', type=Path, default=ROOT / 'target/validation/tcp-diagnostics-native.json')
    parser.add_argument('--emit-unavailable', choices=evidence.UNAVAILABLE_REASONS)
    parser.add_argument('--require-complete', action='store_true')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--parent-netns', type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.report = args.report.resolve()
    profiles = args.profiles.split(',')
    if profiles != [profile for profile in PROFILES if profile in profiles] or not profiles:
        parser.error('profiles must be unique and in supported inventory order')
    if not evidence.hexadecimal(args.reviewed_commit, 40):
        parser.error('reviewed commit must be a full lowercase immutable SHA')
    revision, dirty = git('rev-parse', 'HEAD'), bool(git('status', '--porcelain'))
    corpus_path = ROOT / 'docs/scanner-corpus.v1.json'
    corpus = evidence.strict_json(corpus_path.read_text())
    validate_corpus(corpus)
    native_platform = {'Darwin': 'macOS', 'Windows': 'Windows', 'Linux': 'Linux'}.get(platform.system())
    if native_platform is None:
        parser.error('unsupported native platform')
    reason = args.emit_unavailable or 'runtime_evidence_missing'
    report = evidence.initial(native_platform, revision, dirty, digest(corpus_path), source_identity(), profiles,
                              reason, 'native reviewed execution has not completed')
    report.update(reviewed_commit=args.reviewed_commit, kernel=platform.release(), architecture=platform.machine(),
                  captured_unix_ns=time.time_ns(), status='incomplete')
    write(args.report, report)
    try:
        if revision != args.reviewed_commit or dirty:
            raise ValueError('native execution requires the exact clean reviewed commit')
        if args.emit_unavailable:
            evidence.validate(report, corpus, args.reviewed_commit, args.require_complete, source_identity(), digest(corpus_path))
            return 0
        if not privileged():
            for profile in report['profiles']:
                for case in profile['cases']:
                    case.update(reason='privilege_not_granted', message='native execution requires existing root/administrator privileges')
            raise ValueError('native privilege not granted')
        if native_platform == 'Linux' and not args.inside:
            missing = [tool for tool in ('unshare', 'ip', 'nsenter', 'ethtool') if not shutil.which(tool)]
            if missing:
                for profile in report['profiles']:
                    for case in profile['cases']:
                        case.update(reason='isolation_unavailable', message='missing isolation prerequisites: ' + ','.join(missing))
                raise ValueError('isolation unavailable: missing ' + ','.join(missing))
            # Only native traffic needs isolation. Populate Cargo's cache while
            # the launcher can still reach the configured registry, then make
            # every build in the child namespace explicitly offline.
            cargo_record(['cargo', 'fetch', '--locked'], args.report.parent / 'tcp-diagnostics-fetch.json')
            parent = os.stat('/proc/self/ns/net').st_ino
            command = ['unshare', '--net', '--', sys.executable, str(Path(__file__).resolve()),
                       '--inside', '--parent-netns', str(parent), '--reviewed-commit', args.reviewed_commit,
                       '--profiles', args.profiles, '--report', str(args.report)]
            if args.require_complete:
                command.append('--require-complete')
            try:
                result = subprocess.run(command, cwd=ROOT, timeout=3000)
            finally:
                if args.report.is_file():
                    report = evidence.strict_json(args.report.read_text())
            report = evidence.strict_json(args.report.read_text())
            evidence.validate(report, corpus, args.reviewed_commit, args.require_complete, source_identity(), digest(corpus_path))
            return result.returncode
        if native_platform == 'Linux':
            current = os.stat('/proc/self/ns/net').st_ino
            if not args.parent_netns or current == args.parent_netns or sorted(item['ifname'] for item in json.loads(subprocess.check_output(['ip', '-j', 'link'], text=True, timeout=15))) != ['lo']:
                raise ValueError('refusing execution outside a fresh parent-distinct namespace')
        measurement = measurements()
        for profile in report['profiles']:
            try:
                run_profile(profile, args, report, corpus, measurement)
            except Exception as error:
                profile['error'] = str(error)
                for case in profile['cases']:
                    if case['status'] == 'unavailable' and case['reason'] == 'runtime_evidence_missing':
                        case.update(status='failed', message='profile execution failed: ' + str(error))
                profile['status'] = status_of(profile['cases'])
            write(args.report, report)
        if git('rev-parse', 'HEAD') != revision or bool(git('status', '--porcelain')) or source_identity() != report['sources']:
            raise ValueError('source identity changed during native execution')
        report['status'] = evidence.report_status(report['profiles'])
        # Recompute completeness from retained evidence, never from successful builds.
        report['acceptance_complete'] = evidence.coverage_complete(report)
        evidence.validate(report, corpus, args.reviewed_commit, args.require_complete, source_identity(), digest(corpus_path))
    except Exception as error:
        report['launcher_error'] = str(error)
        report['acceptance_complete'] = False
        report['status'] = evidence.report_status(report['profiles'])
        write(args.report, report)
        print(str(error), file=sys.stderr)
        return 1
    finally:
        write(args.report, report)
    return 1 if report['status'] == 'failed' else 0


if __name__ == '__main__':
    sys.exit(main())
