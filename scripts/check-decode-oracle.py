#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Compare curated physical-frame fields with pinned TShark, without live traffic."""
import argparse
import hashlib
import ipaddress
import json
import pathlib
import re
import runpy
import socket
import shutil
import struct
import subprocess
import tempfile
from validation_evidence import digest, provenance

ROOT = pathlib.Path(__file__).resolve().parent.parent
helpers = runpy.run_path(str(ROOT / 'scripts/measure-analysis.py'))
checksum, ipv4, packets = [helpers[key] for key in ['checksum', 'ipv4', 'packets']]
FIELDS = [
    ('ipv4', 'source', 'ip.src', 'address'),
    ('ipv4', 'destination', 'ip.dst', 'address'),
    ('ipv4', 'total_length', 'ip.len', 'integer'),
    ('ipv4', 'checksum', 'ip.checksum', 'integer'),
    ('ipv4', 'fragment_offset', 'ip.frag_offset', 'integer'),
    ('ipv6', 'source', 'ipv6.src', 'address'),
    ('ipv6', 'destination', 'ipv6.dst', 'address'),
    ('ipv6', 'payload_length', 'ipv6.plen', 'integer'),
    ('tcp', 'source_port', 'tcp.srcport', 'integer'),
    ('tcp', 'destination_port', 'tcp.dstport', 'integer'),
    ('tcp', 'sequence', 'tcp.seq_raw', 'integer'),
    ('tcp', 'checksum', 'tcp.checksum', 'integer'),
    ('tcp', 'options', 'tcp.options', 'bytes'),
    ('udp', 'source_port', 'udp.srcport', 'integer'),
    ('udp', 'destination_port', 'udp.dstport', 'integer'),
    ('udp', 'length', 'udp.length', 'integer'),
    ('udp', 'checksum', 'udp.checksum', 'integer'),
    ('dns', 'id', 'dns.id', 'integer'),
    ('dns', 'qname', 'dns.qry.name', 'names'),
    ('dns', 'question_count', 'dns.count.queries', 'integer'),
    ('dns', 'answer_count', 'dns.count.answers', 'integer'),
]


def curated():
    yield from packets('fragments', 2)
    yield from packets('scopes', 2)
    source, destination = socket.inet_aton('192.0.2.1'), socket.inet_aton('198.51.100.2')
    options = bytes.fromhex('020405b4010303070402080a0000000100000000')
    segment = struct.pack('!HHIIBBHHH', 40000, 4444, 1000, 0, 0xa0, 2, 8192, 0, 0) + options
    pseudo = source + destination + struct.pack('!BBH', 0, 6, len(segment))
    segment = segment[:16] + struct.pack('!H', checksum(pseudo + segment)) + segment[18:]
    yield ipv4(segment, source)
    dns = bytes.fromhex('123481800001000100000000076578616d706c6504746573740000010001c00c000100010000003c0004c0000209')
    udp = struct.pack('!HHHH', 53, 40000, 8 + len(dns), 0) + dns
    yield ipv4(udp, source, 17)
    src6, dst6 = [socket.inet_pton(socket.AF_INET6, value) for value in ['2001:db8::1', '2001:db8::2']]
    udp = struct.pack('!HHHH', 40000, 9999, 8, 0)
    pseudo = src6 + dst6 + struct.pack('!I3xB', len(udp), 17)
    udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp))
    extensions = bytes.fromhex('3c000000000000001100000000000000')
    yield struct.pack('!IHBB16s16s', 0x60000000, len(extensions + udp), 0, 64, src6, dst6) + extensions + udp


def pcap(frames):
    output = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
    for index, packet in enumerate(frames):
        output += struct.pack('<IIII', 100, index, len(packet), len(packet)) + packet
    return bytes(output)


def tshark(data, fields, binary="tshark"):
    # stdin also works when an OS confines TShark's filesystem access.
    command = [binary, '-n', '-r', '-', '-o', 'ip.defragment:FALSE',
               '-o', 'tcp.desegment_tcp_streams:FALSE', '-T', 'fields', '-E', 'occurrence=a']
    for field in fields:
        command.extend(['-e', field])
    return subprocess.check_output(command, input=data, stderr=subprocess.PIPE, timeout=30).decode().splitlines()


def normalize(value, kind, core=False):
    if kind == 'names': return value.rstrip('.')
    if kind == 'address':
        return str(ipaddress.ip_address(value))
    if kind == 'bytes':
        return bytes(value).hex() if core else value.replace(':', '').lower()
    value = int(value) if isinstance(value, int) else int(value, 16 if value.startswith('0x') else 10)
    return value


def compare(args, report):
    report.update(provenance(args.binary))
    version = subprocess.check_output([args.tshark, '--version'], text=True, timeout=10).splitlines()[0]
    report['tshark'] = version
    report['tshark_sha256'] = digest(shutil.which(args.tshark))
    if not re.search(r'\b' + re.escape(args.tshark_version) + r'\b', version):
        raise RuntimeError(f'expected TShark {args.tshark_version}; found {version}')
    captures = [('spec-vectors', pcap(curated())),
                ('tls-handshake', (ROOT / 'examples/captures/tls-handshake.pcapng').read_bytes())]
    if args.full:
        captures.extend((kind, pcap(packets(kind, 64))) for kind in
                        ['flows', 'segments', 'overlaps', 'fragments', 'scopes', 'tls-gaps'])
        captures.extend((f'{kind}-{size}', pcap(packets(kind, size)))
                        for kind in ['tcp-growth', 'tcp-growth-reverse'] for size in [128, 1024, 8192])
    for name, data in captures:
        capture_report = dict(name=name, sha256=hashlib.sha256(data).hexdigest(), status='failed')
        report['captures'].append(capture_report)
        with tempfile.NamedTemporaryFile(suffix='.pcap') as capture:
            capture.write(data)
            capture.flush()
            encoded = subprocess.check_output([str(args.binary), '--output', 'ndjson', 'read', capture.name, '--dissect'], timeout=60)
        records = [json.loads(line) for line in encoded.splitlines()]
        if not records or records[-1]['event'] != 'complete':
            raise RuntimeError(f'{name}: incomplete PacketcraftR output')
        records = [record['result'] for record in records if record['event'] == 'frame']
        reference = tshark(data, [field[2] for field in FIELDS], args.tshark)
        if len(records) != len(reference):
            raise RuntimeError(f'{name}: frame count {len(records)} != {len(reference)}')
        capture_report['frames'] = len(records)
        mismatches = 0
        for index, (record, row) in enumerate(zip(records, reference), 1):
            if len(row.split('\t')) != len(FIELDS):
                raise RuntimeError(f'{name}: incomplete oracle field row {index}')
            layers = record['decoded']['packet']['layers']
            fragmented = any(layer['protocol'] == 'ipv4' and
                             (layer['fields']['more_fragments']['value'] or layer['fields']['fragment_offset']['value'])
                             for layer in layers)
            for (protocol, field, oracle_field, kind), reference_value in zip(FIELDS, row.split('\t')):
                if fragmented and protocol in ('tcp', 'udp', 'dns'):
                    continue
                observed = [layer['fields'][field]['value'] for layer in layers
                            if layer['protocol'] == protocol and field in layer['fields']]
                if kind == 'names': observed = [name['value'] for names in observed for name in names]
                if kind == 'bytes': observed = [value for value in observed if value]
                observed = [normalize(value, kind, True) for value in observed]
                expected = [normalize(value, kind) for value in reference_value.split(',') if value]
                if observed != expected:
                    mismatches += 1
                    if len(report['mismatches']) < 100:
                        report['mismatches'].append(dict(capture=name, frame=index, field=oracle_field,
                                                         observed=observed, expected=expected))
        capture_report.update(status='failed' if mismatches else 'passed', mismatches=mismatches)
    data = captures[1][1]
    session = json.loads(subprocess.check_output([str(args.binary), '--output', 'json', 'tls',
                         str(ROOT / 'examples/captures/tls-handshake.pcapng')], timeout=30))['result']['sessions'][0]
    ja3 = [value for value in tshark(data, ['tls.handshake.ja3'], args.tshark) if value]
    report['tls_ja3'] = dict(expected=ja3, observed=[session['client']['ja3']])
    if ja3 != [session['client']['ja3']] or any(item['mismatches'] for item in report['captures']):
        raise RuntimeError('independent decode comparison failed; see mismatches and tls_ja3')
    report['status'] = 'passed'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, default=ROOT / 'target/release/packetcraftr')
    parser.add_argument('--tshark-version', default='4.6.4')
    parser.add_argument('--tshark', default='tshark', help='path to the pinned TShark executable')
    parser.add_argument('--report', type=pathlib.Path, default=ROOT / 'target/decode-oracle.json')
    parser.add_argument('--full', action='store_true', help='include growth, overlap and generated protocol captures')
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    report = dict(status='failed', profile='full' if args.full else 'pull-request',
                  expected_tshark=args.tshark_version, fields=[field[2] for field in FIELDS],
                  allowances=['Fragmented physical children remain opaque in PacketcraftR; compare network fields only on those frames.'],
                  captures=[], mismatches=[])
    try:
        compare(args, report)
    except Exception as error:
        report['error'] = str(error)
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(args.report)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
