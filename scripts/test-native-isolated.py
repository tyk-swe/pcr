#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Run native Linux validation only inside a fresh user/network namespace."""
import argparse
import json
import os
import pathlib
import platform
import socket
import struct
import subprocess
import sys
import threading
import uuid

from validation_evidence import ROOT, digest, provenance

SCENARIOS = ['readiness_and_repeated_cleanup', 'idle_deadline_and_cancellation',
             'bounded_queue_reports_real_capture_loss', 'native_filter_error_preserves_diagnostic_and_releases_admission',
             'interface_disappearance_reports_driver_failure_and_cleans_up']


def checksum(data):
    if len(data) % 2: data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16: total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def exchange(binary, report):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        server.bind(('127.0.0.1', 0))
        receiver.bind(('127.0.0.1', 0))
        server.settimeout(5)
        source_port, destination_port = receiver.getsockname()[1], server.getsockname()[1]
        messages = []
        def reply():
            try:
                data, address = server.recvfrom(1024)
                messages.append(data.hex())
                # Kernel UDP loopback capture may expose checksum-offload
                # placeholders. Emit an exact, checksummed local reply instead
                # of weakening the production decoder/integrity checks.
                if address[0] != '127.0.0.1':
                    raise RuntimeError('refusing a non-loopback response destination')
                payload = b'isolated-reply'
                source = destination = socket.inet_aton('127.0.0.1')
                udp = struct.pack('!HHHH', destination_port, address[1], 8 + len(payload), 0) + payload
                check = checksum(source + destination + struct.pack('!BBH', 0, 17, len(udp)) + udp) or 0xffff
                udp = udp[:6] + struct.pack('!H', check) + udp[8:]
                ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 2, 0, 64, 17, 0, source, destination)
                ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as raw:
                    raw.sendto(ip + udp, ('127.0.0.1', 0))
                report['reply_bytes'] = (ip + udp).hex()
            except OSError as error:
                report['responder_error'] = str(error)
        worker = threading.Thread(target=reply, daemon=True)
        worker.start()
        command = [str(binary), '--output', 'ndjson', 'exchange', '--interface', 'lo', '--link-mode', 'layer3',
                   '--timeout-ms', '1000', '--max-packets', '1', '--max-bytes', '1024',
                   '--max-queue-frames', '64', '--max-captured-bytes', '65536', '--snap-length', '2048', '--max-responses', '1', '--max-unsolicited', '64',
                   '--packet', f'ipv4(dst=127.0.0.1,identification=1)/udp(sport={source_port},dport={destination_port})/raw(text=isolated-probe)']
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        worker.join(timeout=5)
    report.update(command=command, exit_code=output.returncode, stdout=output.stdout.decode(),
                  stderr=output.stderr.decode(), received_messages=messages)
    assert output.returncode == 0, 'exchange command failed'
    records = [json.loads(line) for line in output.stdout.splitlines()]
    assert records and records[-1]['event'] == 'complete', 'exchange output incomplete'
    assert [record['sequence'] for record in records] == list(range(len(records))), 'noncontiguous output'
    assert messages == [b'isolated-probe'.hex()], 'local responder did not receive exact probe'
    assert b'isolated-reply'.hex() in output.stdout.decode(), 'reply absent from capture'
    assert next(index for index, record in enumerate(records) if record['event'] == 'sent') < len(records) - 1
    report['status'] = 'passed'


def build_tests():
    built = subprocess.run(['cargo', 'test', '--locked', '-p', 'packetcraftr-netio', '--all-features',
                            '--test', 'native_isolated', '--no-run', '--message-format=json'],
                           cwd=ROOT, stdout=subprocess.PIPE, text=True, check=True, timeout=900)
    executables = [row['executable'] for row in map(json.loads, built.stdout.splitlines())
                   if row.get('reason') == 'compiler-artifact' and row.get('executable')
                   and row.get('target', {}).get('name') == 'native_isolated']
    if len(executables) != 1:
        raise RuntimeError('could not identify native test executable')
    return pathlib.Path(executables[0])


def run(args, report):
    report.update(provenance(args.binary), os=platform.platform())
    if platform.system() != 'Linux':
        report['status'] = 'unsupported'
        raise RuntimeError('this suite requires Linux user/network namespaces')
    namespace = os.stat('/proc/self/ns/net').st_ino
    if args.parent_namespace is None:
        args.native_test_binary = args.native_test_binary or build_tests()
        report['native_test_sha256'] = digest(args.native_test_binary)
        mapping = ['--map-root-user']
        if os.geteuid() == 0 and 'SUDO_UID' in os.environ:
            # Map namespace root back to the checkout owner, so private home
            # directories remain accessible without changing permissions.
            uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
            mapping = [f'--map-users=0:{uid}:1', f'--map-groups=0:{gid}:1', '--setuid=0', '--setgid=0']
        command = ['unshare', '--user', *mapping, '--net', sys.executable,
                   str(pathlib.Path(__file__).resolve()), '--binary', str(args.binary),
                   '--native-test-binary', str(args.native_test_binary),
                   '--report', str(args.report), '--parent-namespace', str(namespace), '--run-id', report['run_id']]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
        if args.report.exists():
            child = json.loads(args.report.read_text())
            if child.get('parent_namespace') == namespace and child.get('run_id') == report['run_id']:
                report.update(child)
        report['namespace_launcher'] = dict(command=command, exit_code=result.returncode, stderr=result.stderr)
        if result.returncode:
            raise RuntimeError('isolated namespace launcher or native scenarios failed; see namespace_launcher and scenarios')
        return
    interfaces = {link['ifname'] for link in json.loads(subprocess.check_output(['ip', '-j', 'link', 'show'], text=True, timeout=10))}
    if namespace == args.parent_namespace or interfaces != {'lo'}:
        raise RuntimeError('refusing native test outside a fresh, loopback-only network namespace')
    report.update(namespace=namespace, parent_namespace=args.parent_namespace,
                  native_test_sha256=digest(args.native_test_binary))
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True, timeout=10)
    try:
        exchange(args.binary, report['scenarios'][0])
    except Exception as error:
        report['scenarios'][0].update(status='failed', error=str(error))
    env = dict(os.environ, PACKETCRAFTR_PARENT_NETNS=str(args.parent_namespace))
    listing = subprocess.check_output([str(args.native_test_binary), '--ignored', '--list'], text=True, timeout=10)
    present = {line.removesuffix(': test') for line in listing.splitlines() if line.endswith(': test')}
    if present != set(SCENARIOS):
        raise RuntimeError(f'native test inventory differs: {sorted(present)}')
    for scenario in report['scenarios'][1:]:
        command = [str(args.native_test_binary), '--ignored', '--exact', scenario['name'], '--nocapture', '--test-threads=1']
        try:
            result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
            scenario.update(command=command, exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr,
                            status='passed' if result.returncode == 0 else 'failed')
        except Exception as error:
            scenario.update(status='failed', error=str(error))
    if any(item['status'] != 'passed' for item in report['scenarios']):
        raise RuntimeError('one or more required native scenarios did not pass')
    report['status'] = 'passed'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    parser.add_argument('--native-test-binary', type=pathlib.Path, help='prebuilt native_isolated test executable; otherwise build it')
    parser.add_argument('--report', type=pathlib.Path, default=ROOT / 'target/native-isolated.json')
    parser.add_argument('--parent-namespace', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--run-id', default=None, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.binary, args.report = args.binary.resolve(), args.report.resolve()
    created = not args.report.parent.exists()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    owner = (int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])) if args.parent_namespace is None and os.geteuid() == 0 and 'SUDO_UID' in os.environ else None
    if created and owner:
        os.chown(args.report.parent, *owner)

    if args.native_test_binary: args.native_test_binary = args.native_test_binary.resolve()
    report = dict(status='failed', run_id=args.run_id or str(uuid.uuid4()), scenarios=[dict(name=name, status='not_exercised')
                  for name in ['loopback_exchange', *SCENARIOS]],
                  other_platforms=[dict(platform=name, status='not_exercised', reason='no privileged lab lane configured')
                                   for name in ['Windows', 'macOS']])
    try:
        run(args, report)
    except Exception as error:
        report['error'] = str(error)
        if report['status'] != 'unsupported': report['status'] = 'failed'
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        if owner: os.chown(args.report, *owner)
    print(args.report)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
