#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Run native Linux validation only inside a fresh user/network namespace."""
import argparse
import os
import pathlib
import platform
import socket
import struct
import subprocess
import sys
import threading
import uuid

from script_support import prepare_report, read_json, strict_json, write_json_atomic
from validation_evidence import NATIVE_SCENARIOS, ROOT, checksum, provenance, validate_native


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
            except (OSError, RuntimeError) as error:
                report['responder_error'] = str(error)
        worker = threading.Thread(target=reply, daemon=True)
        worker.start()
        command = [str(binary), '--output', 'ndjson', 'network', 'exchange', '--interface', 'lo', '--link-mode', 'layer3',
                   '--timeout-ms', '1000', '--max-packets', '1', '--max-bytes', '1024',
                   '--max-queue-frames', '64', '--max-captured-bytes', '65536', '--snap-length', '2048', '--max-responses', '1', '--max-unsolicited', '64',
                   '--packet', f'ipv4(dst=127.0.0.1,identification=1)/udp(sport={source_port},dport={destination_port})/raw(text=isolated-probe)']
        try:
            output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        finally:
            worker.join(timeout=6)
        if worker.is_alive():
            raise RuntimeError('local responder did not terminate')
    report.update(command=command, exit_code=output.returncode, stdout=output.stdout.decode(),
                  stderr=output.stderr.decode(), received_messages=messages)
    validate_exchange(report)
    report['status'] = 'passed'


def validate_exchange(report):
    """Validate native evidence with checks that remain active under python -O."""
    if type(report.get('exit_code')) is not int or report['exit_code'] != 0:
        raise ValueError('exchange command failed')
    if report.get('responder_error'):
        raise ValueError('local responder failed')
    output = report.get('stdout')
    if not isinstance(output, str) or not output.endswith('\n') or len(output.encode('utf-8')) > 4 * 1024 * 1024:
        raise ValueError('exchange output is missing, truncated or oversized')
    records = [strict_json(line) for line in output.split('\n')[:-1]]
    if not records or not all(isinstance(record, dict) for record in records):
        raise ValueError('exchange output must contain object records')
    if any(record.get('schema') != 'packetcraftr.output/v1'
           or record.get('mode') != 'stream' or record.get('command') != 'exchange'
           or record.get('status') != 'success' for record in records):
        raise ValueError('exchange output has an unsupported identity or failed status')
    if any(type(record.get('sequence')) is not int or record['sequence'] != index
           for index, record in enumerate(records)):
        raise ValueError('noncontiguous exchange output')
    if records[-1].get('event') != 'complete' or any(
            record.get('event') not in ('sent', 'response', 'unsolicited', 'unanswered', 'diagnostic', 'undecoded')
            for record in records[:-1]):
        raise ValueError('exchange stream has missing, duplicate or unknown terminal events')
    if report.get('received_messages') != [b'isolated-probe'.hex()]:
        raise ValueError('local responder did not receive the exact probe')
    sent = [index for index, record in enumerate(records) if record['event'] == 'sent']
    responses = [index for index, record in enumerate(records) if record['event'] == 'response']
    if len(sent) != 1 or len(responses) != 1 or sent[0] >= responses[0]:
        raise ValueError('exchange lacks exactly one sent request followed by an attributed response')
    for index in sent + responses:
        request = records[index].get('result', {}).get('request_index')
        if type(request) is not int or request != 0:
            raise ValueError('exchange attribution does not identify the authorized request')
    reply = report.get('reply_bytes')
    decoded = records[responses[0]]['result'].get('response', {})
    response = decoded.get('frame', {})
    if not isinstance(reply, str) or not reply.endswith(b'isolated-reply'.hex()):
        raise ValueError('exact local reply absent from attributed capture')
    frame_bytes = response.get('bytes_hex')
    if not isinstance(frame_bytes, str):
        raise ValueError('exact local reply absent from attributed capture')
    layout = decoded.get('layout')
    if isinstance(layout, dict):
        layers = [layer for layer in layout.get('layers', []) if isinstance(layer, dict)]
        ipv4_start = next((layer.get('range', {}).get('start') for layer in layers
                           if layer.get('protocol') == 'ipv4'), None)
        frame_end = max((layer.get('range', {}).get('end', 0) for layer in layers), default=None)
        if type(ipv4_start) is not int or type(frame_end) is not int:
            raise ValueError('exact local reply capture has an invalid ipv4 layout range')
        if not (0 <= ipv4_start <= frame_end <= len(frame_bytes) // 2):
            raise ValueError('exact local reply capture has an invalid ipv4 layout range')
        frame_bytes = frame_bytes[2 * ipv4_start:2 * frame_end]
    if frame_bytes != reply:
        raise ValueError('exact local reply absent from attributed capture')
    if records[-1].get('result', {}).get('unanswered') != []:
        raise ValueError('exchange completed with an unanswered request')


def run(args, report):
    report.update(provenance(args.binary), os=platform.platform())
    if platform.system() != 'Linux':
        report['status'] = 'unsupported'
        raise RuntimeError('this suite requires Linux user/network namespaces')
    namespace = os.stat('/proc/self/ns/net').st_ino
    if args.parent_namespace is None:
        mapping = ['--map-root-user']
        if os.geteuid() == 0 and 'SUDO_UID' in os.environ:
            # Map namespace root back to the checkout owner, so private home
            # directories remain accessible without changing permissions.
            uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
            mapping = [f'--map-users=0:{uid}:1', f'--map-groups=0:{gid}:1', '--setuid=0', '--setgid=0']
        command = ['unshare', '--user', *mapping, '--net', sys.executable,
                   str(pathlib.Path(__file__).resolve()), '--binary', str(args.binary),
                   '--report', str(args.report), '--parent-namespace', str(namespace), '--run-id', report['run_id']]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
        launcher = dict(command=command, exit_code=result.returncode, stderr=result.stderr)
        if args.report.exists():
            child = read_json(args.report)
            if child.get('parent_namespace') == namespace and child.get('run_id') == report['run_id']:
                report.update(child)
                child_error = child.get('error')
                if isinstance(child_error, str) and child_error:
                    launcher['child_error'] = child_error
        report['namespace_launcher'] = launcher
        if result.returncode:
            raise RuntimeError('isolated namespace launcher or native scenarios failed; see namespace_launcher and scenarios')
        return
    interfaces = {link['ifname'] for link in strict_json(subprocess.check_output(['ip', '-j', 'link', 'show'], text=True, timeout=10))}
    if namespace == args.parent_namespace or interfaces != {'lo'}:
        raise RuntimeError('refusing native test outside a fresh, loopback-only network namespace')
    report.update(namespace=namespace, parent_namespace=args.parent_namespace)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True, timeout=10)
    for scenario in report['scenarios']:
        try:
            exchange(args.binary, scenario)
        except Exception as error:
            scenario.update(status='failed', error=str(error))
    if any(item['status'] != 'passed' for item in report['scenarios']):
        raise RuntimeError('one or more required native scenarios did not pass')
    report['status'] = 'passed'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    parser.add_argument('--report', type=pathlib.Path, default=ROOT / 'target/native-isolated.json')
    parser.add_argument('--parent-namespace', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--run-id', default=None, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.binary, args.report = args.binary.resolve(), args.report.resolve()
    try:
        prepare_report(args.report, args.binary)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    created = not args.report.parent.exists()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    owner = (int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])) if args.parent_namespace is None and os.geteuid() == 0 and 'SUDO_UID' in os.environ else None
    if created and owner:
        os.chown(args.report.parent, *owner)

    report = dict(status='failed', run_id=args.run_id or str(uuid.uuid4()), scenarios=[dict(name=name, status='not_exercised')
                  for name in NATIVE_SCENARIOS],
                  other_platforms=[dict(platform=name, status='not_exercised', reason='no privileged lab lane configured')
                                   for name in ['Windows', 'macOS']])
    try:
        run(args, report)
        # Only the parent can record the launcher exit after the child finishes.
        if args.parent_namespace is None:
            validate_native(report)
    except Exception as error:
        report['error'] = str(error)
        if report['status'] != 'unsupported': report['status'] = 'failed'
    finally:
        write_json_atomic(args.report, report)
        if owner: os.chown(args.report, *owner)
    print(args.report)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
