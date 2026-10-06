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
import time
import uuid

from validation_evidence import NATIVE_SCENARIOS, ROOT, checksum, digest, provenance, validate_native

# Two veth links share one link-local pair, so only a declared zone decides
# which peer a probe reaches. The raw peer fe80::3 exists only as a user-space
# responder behind the first link.
SCOPED_LINKS = (('pcrs0', 'pcrs1'), ('pcrt0', 'pcrt1'))
SCOPED_RAW_PEER = 'fe80::3'
SCOPED_OPEN, SCOPED_CLOSED = 8443, 8444


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


def ip(*args):
    subprocess.run(['ip', *args], check=True, timeout=10)


def cli(binary, report, *args):
    command = [str(binary), *args]
    output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
    report.setdefault('runs', []).append(dict(command=command, exit_code=output.returncode,
                                              stdout=output.stdout, stderr=output.stderr))
    records = [json.loads(line) for line in output.stdout.splitlines()]
    assert output.returncode == 0 and records and records[-1]['event'] == 'complete', f'{command} did not complete'
    return records


def scope(record, interface):
    return record.get('scope') == dict(zone=interface, interface=dict(name=interface, index=socket.if_nametoindex(interface)))


def respond(stop, interface, received):
    """Answer raw SYNs to the scoped peer with exact, checksummed TCP replies."""
    peer = socket.inet_pton(socket.AF_INET6, SCOPED_RAW_PEER)
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x86dd)) as raw:
        raw.bind((interface, 0x86dd))
        raw.settimeout(0.1)
        while not stop.is_set():
            try:
                frame, (_, _, kind, _, _) = raw.recvfrom(2048)
            except socket.timeout:
                continue
            # Ethernet (14) + IPv6 (40) + TCP (20): a SYN without ACK to the peer.
            if kind == socket.PACKET_OUTGOING or len(frame) < 74 or frame[20] != 6 or frame[38:54] != peer \
                    or (frame[67] & 0x12) != 0x02:
                continue
            source, destination = frame[38:54], frame[22:38]
            source_port, destination_port, sequence = struct.unpack('!HHI', frame[54:62])
            received.append(dict(interface=interface, destination_port=destination_port, frame=frame.hex()))
            # A veth peer can answer before the scanner's send call returns, and
            # correlation rightly refuses a frame captured inside that interval.
            time.sleep(0.05)
            flags, window = (0x12, 65535) if destination_port == SCOPED_OPEN else (0x14, 0)
            tcp = struct.pack('!HHIIBBHHH', destination_port, source_port, 0x1000, (sequence + 1) & 0xffffffff,
                              0x50, flags, window, 0, 0)
            check = checksum(source + destination + struct.pack('!I3xB', len(tcp), 6) + tcp)
            tcp = tcp[:16] + struct.pack('!H', check) + tcp[18:]
            header = struct.pack('!IHBB', 0x6 << 28, len(tcp), 6, 64) + source + destination
            raw.send(frame[6:12] + frame[0:6] + frame[12:14] + header + tcp)


def scoped_capability_failure(binary, report, *options, target='fe80::1%1'):
    command = [str(binary), '--output', 'json', 'scan', target, *options]
    output = subprocess.run(command, capture_output=True, text=True, timeout=20)
    report.setdefault('runs', []).append(dict(command=command, exit_code=output.returncode,
                                              stdout=output.stdout, stderr=output.stderr))
    assert output.returncode != 0, 'unsupported scoped operation succeeded'
    assert json.loads(output.stdout)['error']['code'] == 'capability.unsupported', \
        'unsupported scoped operation did not publish a capability failure'


def scoped_ipv6(binary, report, profile='full-native'):
    corpus_path = ROOT / 'docs/scanner-corpus.v1.json'
    corpus = json.loads(corpus_path.read_bytes())
    expected = next(case['expected'] for case in corpus['target_planning_scenarios']
                    if case['id'] == 'scoped-isolated-links')
    report.update(corpus_sha256=digest(corpus_path), corpus_dataset_version=corpus['dataset_version'])
    if profile == 'portable':
        for options in (('--list',), ('--connect', '--ports', '1'), ('--ports', '1')):
            scoped_capability_failure(binary, report, *options)
        report.update(exit_code=0, status='passed', scoped_paths=dict(
            selection='unsupported_capability', connect='unsupported_capability', raw='unsupported_capability'))
        return
    near, far = SCOPED_LINKS[0]
    other = SCOPED_LINKS[1][0]
    try:
        for link, peer in SCOPED_LINKS:
            ip('link', 'add', link, 'type', 'veth', 'peer', 'name', peer)
            for name, address in ((link, 'fe80::1/64'), (peer, 'fe80::2/64')):
                ip('link', 'set', name, 'addrgenmode', 'none')
                ip('-6', 'addr', 'add', address, 'dev', name, 'nodad')
                ip('link', 'set', name, 'up')
        mac = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', far], text=True, timeout=10))[0]['address']
        ip('-6', 'neigh', 'add', SCOPED_RAW_PEER, 'lladdr', mac, 'dev', near, 'nud', 'permanent')

        records = cli(binary, report, '--output', 'ndjson', 'scan', '--list', f'fe80::2%{near}',
                      f'fe80::2%{socket.if_nametoindex(near)}', f'fe80::2%{other}')
        listed = [record['result'] for record in records if record['event'] == 'target']
        assert len(listed) == expected['selected_targets'] and scope(listed[0], near) and scope(listed[1], other), 'zones did not resolve'
        assert [origin['index'] for origin in listed[0]['origins']] == [0, 1], 'name/index aliases did not merge'

        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as listener:
            listener.bind(('fe80::2', SCOPED_OPEN, 0, socket.if_nametoindex(far)))
            listener.listen(4)
            records = cli(binary, report, '--output', 'ndjson', 'scan', '--connect', f'fe80::2%{near}',
                          f'fe80::2%{other}', '--ports', str(SCOPED_OPEN), '--timeout-ms', '1000')
        probes = {record['result']['scope']['zone']: record['result']
                  for record in records if record['event'] == 'connect_probe'}
        assert set(probes) == {near, other} and all(scope(probe, zone) for zone, probe in probes.items()), \
            'connect probes lost their scope'
        assert probes[near]['classification'] == 'open', 'scoped connect missed the listening link'
        assert probes[near]['local'].startswith(f'[fe80::1%{socket.if_nametoindex(near)}]:'), \
            'connect socket was not bound to the declared zone'
        assert probes[other]['classification'] == 'closed', 'scoped connect reached the wrong link'

        if profile in ('default', 'pcap-free'):
            scoped_capability_failure(binary, report, '--ports', '1', target=f'{SCOPED_RAW_PEER}%{near}')
            report.update(exit_code=0, status='passed', scoped_paths=dict(
                selection='exercised', connect='exercised', raw='unsupported_capability'))
            return

        stop, received = threading.Event(), []
        responder = threading.Thread(target=respond, args=(stop, far, received), daemon=True)
        responder.start()
        try:
            mode = ('--link-mode', 'layer2') if profile == 'layer2' else ()
            records = cli(binary, report, '--output', 'ndjson', 'scan', f'{SCOPED_RAW_PEER}%{near}',
                          '--ports', f'{SCOPED_OPEN},{SCOPED_CLOSED}', '--timeout-ms', '1000', *mode)
        finally:
            stop.set()
            responder.join(timeout=5)
        report['responder_received'] = received
        probes = {record['result']['probe']['destination_port']: record['result']['probe']
                  for record in records if record['event'] == 'probe'}
        assert set(probes) == {SCOPED_OPEN, SCOPED_CLOSED} and all(scope(probe, near) for probe in probes.values()), \
            'raw probes lost their scope'
        assert {item['destination_port'] for item in received} == set(probes), 'raw probes did not leave the declared link'
        assert probes[SCOPED_OPEN]['classification'] == expected['raw_open'] and probes[SCOPED_CLOSED]['classification'] == expected['raw_closed'], \
            'raw replies on the declared link were not correlated'
    finally:
        for link, _ in SCOPED_LINKS:
            subprocess.run(['ip', 'link', 'del', link], stderr=subprocess.DEVNULL, timeout=10)
    report.update(exit_code=0, status='passed', scoped_paths=dict(
        selection='exercised', connect='exercised', raw='exercised'))


# Launcher-driven CLI scenarios; every other scenario is a native_isolated test.
# The scoped scenario adds interfaces, so it runs after the loopback-only tests.
CLI_SCENARIOS = {'loopback_exchange': exchange, 'scoped_ipv6_targets': scoped_ipv6}
SCENARIOS = tuple(name for name in NATIVE_SCENARIOS if name not in CLI_SCENARIOS)


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
        launcher = dict(command=command, exit_code=result.returncode, stderr=result.stderr)
        if args.report.exists():
            child = json.loads(args.report.read_text())
            if child.get('parent_namespace') == namespace and child.get('run_id') == report['run_id']:
                report.update(child)
                child_error = child.get('error')
                if isinstance(child_error, str) and child_error:
                    launcher['child_error'] = child_error
        report['namespace_launcher'] = launcher
        if result.returncode:
            raise RuntimeError('isolated namespace launcher or native scenarios failed; see namespace_launcher and scenarios')
        return
    interfaces = {link['ifname'] for link in json.loads(subprocess.check_output(['ip', '-j', 'link', 'show'], text=True, timeout=10))}
    if namespace == args.parent_namespace or interfaces != {'lo'}:
        raise RuntimeError('refusing native test outside a fresh, loopback-only network namespace')
    report.update(namespace=namespace, parent_namespace=args.parent_namespace,
                  native_test_sha256=digest(args.native_test_binary))
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True, timeout=10)
    env = dict(os.environ, PACKETCRAFTR_PARENT_NETNS=str(args.parent_namespace))
    listing = subprocess.check_output([str(args.native_test_binary), '--ignored', '--list'], text=True, timeout=10)
    present = {line.removesuffix(': test') for line in listing.splitlines() if line.endswith(': test')}
    if present != set(SCENARIOS):
        raise RuntimeError(f'native test inventory differs: {sorted(present)}')
    for scenario in report['scenarios']:
        try:
            if scenario['name'] in CLI_SCENARIOS:
                CLI_SCENARIOS[scenario['name']](args.binary, scenario)
                continue
            command = [str(args.native_test_binary), '--ignored', '--exact', scenario['name'], '--nocapture', '--test-threads=1']
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
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        if owner: os.chown(args.report, *owner)
    print(args.report)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
