#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Generate bounded adverse captures and measure complete CLI workflows on Linux.

RSS/time and allocator evidence are separate. --heaptrack records allocation
profiles when that optional tool is installed; no noisy thresholds are imposed.
"""
import argparse
import functools
import hashlib
import json
import pathlib
import socket
import struct
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent


def checksum(data):
    data += b'\0' * (len(data) % 2)
    value = sum(struct.unpack(f'!{len(data)//2}H', data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def ipv4(payload, source, protocol=6, identity=0, fragment=0):
    destination = socket.inet_aton('198.51.100.2')
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), identity,
                         fragment, 64, protocol, 0, source, destination)
    return header[:10] + struct.pack('!H', checksum(header)) + header[12:] + payload


def tcp(index, sequence=1000, flags=2, payload=b''):
    source = socket.inet_aton(f'192.0.2.{1 + (index // 60000) % 254}')
    destination = socket.inet_aton('198.51.100.2')
    segment = struct.pack('!HHIIBBHHH', 1024 + index % 60000, 4444, sequence,
                          0, 0x50, flags, 8192, 0, 0) + payload
    pseudo = source + destination + struct.pack('!BBH', 0, 6, len(segment))
    segment = segment[:16] + struct.pack('!H', checksum(pseudo + segment)) + segment[18:]
    return ipv4(segment, source)


@functools.cache
def client_hello_record():
    # The checked-in fixture uses little-endian PCAPNG and raw IPv4 frames.
    data = (ROOT / 'examples/captures/tls-handshake.pcapng').read_bytes()
    cursor = 0
    while cursor < len(data):
        kind, length = struct.unpack_from('<II', data, cursor)
        if kind == 6:
            captured = struct.unpack_from('<I', data, cursor + 20)[0]
            packet = data[cursor + 28:cursor + 28 + captured]
            ip_header = (packet[0] & 15) * 4
            tcp_header = (packet[ip_header + 12] >> 4) * 4
            payload = packet[ip_header + tcp_header:]
            if payload[:1] == b'\x16' and payload[5:6] == b'\x01':
                return payload
        cursor += length
    raise AssertionError('published fixture lacks ClientHello')


def packets(kind, size):
    if kind in ('tcp-growth', 'tcp-growth-reverse'):
        yield tcp(0)
        indices = range(size) if kind == 'tcp-growth' else range(size - 1, -1, -1)
        for index in indices:
            # Leave the first expected byte absent: one ever-growing interval.
            yield tcp(0, 1002 + index * 100, 16, b'x' * 100)
        return
    for index in range(size):
        if kind == 'flows':
            yield tcp(index)
        elif kind in ('segments', 'overlaps'):
            yield tcp(index)
            offsets = range(31, -1, -1) if kind == 'segments' else [0, 0, 1, 0]
            for offset in offsets:
                yield tcp(index, 1001 + offset, 16, bytes([offset]))
        elif kind == 'tls-gaps':
            hello = client_hello_record()
            yield tcp(index)
            yield tcp(index, 1001, 16, hello[:64])
            yield tcp(index, 1097, 16, hello[96:128])
        elif kind == 'fragments':
            source = socket.inet_aton(f'192.0.2.{1 + (index // 60000) % 254}')
            payload = struct.pack('!HHHH', 1024 + index % 60000, 9999, 16, 0) + b'fragment'
            yield ipv4(payload[8:], source, 17, index % 65536, 1)
            yield ipv4(payload[:8], source, 17, index % 65536, 0x2000)
        elif kind == 'scopes':
            ethernet = bytes.fromhex('0200000000020200000000010800')
            vxlan = b'\x08\0\0\0' + (index + 1).to_bytes(3, 'big') + b'\0'
            udp_payload = vxlan + ethernet + tcp(0)
            udp = struct.pack('!HHHH', 40000, 4789, 8 + len(udp_payload), 0) + udp_payload
            yield ipv4(udp, socket.inet_aton('203.0.113.1'), 17)
        else:
            raise ValueError(kind)


def write_capture(path, kind, size):
    count = 0
    with path.open('wb') as output:
        output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 228))
        for count, packet in enumerate(packets(kind, size), 1):
            output.write(struct.pack('<IIII', 100 + count // 1000000, count % 1000000,
                                     len(packet), len(packet)))
            output.write(packet)
    return count


def measure(binary, args, capture, out, label, pipe, heaptrack):
    command = [str(binary), *args]
    if pipe:
        command = ['bash', '-o', 'pipefail', '-c', 'cat -- "$1" | "${@:2}"',
                   'capture-pipe', str(capture), *command]
    metrics = out / f'{label}.time'
    started = time.monotonic()
    with (out / f'{label}.stderr').open('wb') as errors:
        result = subprocess.run(['/usr/bin/time', '-f', '%M %e %U %S %x', '-o', str(metrics),
                                 *command], stdout=subprocess.DEVNULL, stderr=errors)
    values = metrics.read_text().splitlines()[-1].split()
    report = dict(label=label, command=command, exit_code=result.returncode,
                  peak_rss_kib=int(values[0]), elapsed_seconds=float(values[1]),
                  user_seconds=float(values[2]), system_seconds=float(values[3]),
                  harness_seconds=time.monotonic() - started)
    if heaptrack and not pipe:
        profile = out / f'{label}.heaptrack'
        # This separate run is intentionally excluded from throughput/RSS numbers.
        with (out / f'{label}.heaptrack.log').open('wb') as log:
            subprocess.run(['heaptrack', '-o', str(profile), *command],
                           stdout=subprocess.DEVNULL, stderr=log, check=False)
        report['allocator_profile_prefix'] = str(profile)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, default=ROOT / 'target/release/packetcraftr')
    parser.add_argument('--output', type=pathlib.Path, default=ROOT / 'target/analysis-measurements')
    parser.add_argument('--sizes', type=int, nargs='+', default=[128, 1024, 8192])
    parser.add_argument('--heaptrack', action='store_true')
    options = parser.parse_args()
    if any(size < 1 or size > 100000 for size in options.sizes):
        parser.error('each cardinality must be within 1..100000')
    out = options.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    binary = options.binary.resolve()
    report = dict(binary=str(binary), binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  version=subprocess.check_output([binary, '--version'], text=True).strip(),
                  rustc=subprocess.check_output(['rustc', '--version', '--verbose'], text=True),
                  memory_note='Peak process RSS, not a heap limit. No post-exit heap exists; in-process cleanup is tested separately.',
                  measurements=[])
    # Store exact effective defaults and command lines alongside each run.
    for command in ['read', 'follow', 'tls', 'stats']:
        (out / f'{command}-limits.txt').write_bytes(subprocess.check_output([binary, command, '--help']))
    for size in options.sizes:
        for kind in ['flows', 'segments', 'overlaps', 'fragments', 'scopes', 'tls-gaps', 'tcp-growth', 'tcp-growth-reverse']:
            path = out / f'{kind}-{size}.pcap'
            count = write_capture(path, kind, size)
            limits = ['--max-frames', str(count), '--max-flows', str(size)]
            workloads = [('stats-protocols', ['--output', 'json', 'stats', str(path), '--table', 'protocols', *limits]),
                         ('tls-ndjson', ['--output', 'ndjson', 'tls', str(path), *limits])]
            if kind == 'flows':
                workloads.extend([
                    ('read-ndjson', ['--output', 'ndjson', 'read', str(path), '--max-frames', str(count)]),
                    ('follow-ndjson', ['--output', 'ndjson', 'follow', str(path), '--stream', 'tcp:0', *limits]),
                    ('filtered-stats', ['--output', 'json', 'stats', str(path), '--table', 'protocols', '--filter', 'tcp.stream == 0', *limits]),
                    ('flow-limit', ['--output', 'json', 'stats', str(path), '--max-flows', str(max(1, size // 2))]),
                ])
            if kind == 'scopes':
                workloads.append(('scope-limit', ['--output', 'json', 'stats', str(path), '--max-scope-bytes', '1024']))
            for name, args in workloads:
                label = f'{kind}-{size}-{name}'
                measured = measure(binary, args, path, out, label, False, options.heaptrack)
                measured.update(workload=kind, cardinality=size, physical_frames=count,
                                input_bytes=path.stat().st_size)
                report['measurements'].append(measured)
            if kind == 'flows':
                args = ['--output', 'ndjson', 'read', '-', '--max-frames', str(count)]
                report['measurements'].append(measure(binary, args, path, out, f'{kind}-{size}-pipe-read', True, False))
            (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    # Include a valid assembled handshake and aggregate/stream comparison.
    capture = ROOT / 'examples/captures/tls-handshake.pcapng'
    for output in ['json', 'ndjson']:
        report['measurements'].append(measure(binary, ['--output', output, 'tls', str(capture)], capture, out,
                                             f'tls-handshake-{output}', False, options.heaptrack))
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(out / 'report.json')


if __name__ == '__main__':
    main()
