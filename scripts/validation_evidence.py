# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared contracts and provenance for validation reports (not product output)."""
import hashlib
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent

EVIDENCE_VERSION = 1
TSHARK_VERSION = '4.6.4'

DECODE_FIELDS = (
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
)

# Expected physical-frame counts, independent of capture generation and decoding.
DECODE_PROFILES = {
    'pull-request': {'spec-vectors': 9, 'tls-handshake': 8},
    'full': {
        'spec-vectors': 9, 'tls-handshake': 8,
        'flows': 64, 'segments': 2112, 'overlaps': 320, 'fragments': 128,
        'scopes': 64, 'tls-gaps': 192,
        'tcp-growth-128': 129, 'tcp-growth-1024': 1025, 'tcp-growth-8192': 8193,
        'tcp-growth-reverse-128': 129, 'tcp-growth-reverse-1024': 1025,
        'tcp-growth-reverse-8192': 8193,
    },
}

# Preserve the runner's scenario order while sharing the required inventory.
NATIVE_SCENARIOS = (
    'loopback_exchange', 'readiness_and_repeated_cleanup', 'idle_deadline_and_cancellation',
    'bounded_queue_reports_real_capture_loss',
    'native_filter_error_preserves_diagnostic_and_releases_admission',
    'interface_disappearance_reports_driver_failure_and_cleans_up',
)


def tshark_matches(identity, expected=TSHARK_VERSION):
    if not isinstance(identity, str):
        return False
    match = re.match(r'^TShark \(Wireshark\) (\d+\.\d+\.\d+)(?:\s|\.$|$)', identity)
    return match is not None and match[1] == expected


def valid_digest(value, width=64):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{' + str(width) + r'}', value) is not None


def named_results(items, expected, label):
    if not isinstance(items, list) or len(items) != len(expected):
        raise ValueError(f'{label}: incomplete inventory')
    names = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get('name'), str) or item.get('status') != 'passed':
            raise ValueError(f'{label}: missing or failed result')
        names.append(item['name'])
    if len(set(names)) != len(names) or set(names) != set(expected):
        raise ValueError(f'{label}: duplicate or unexpected result names')
    return items


def validate_native(report):
    scenarios = named_results(report.get('scenarios'), NATIVE_SCENARIOS, 'native scenarios')
    if any(type(item.get('exit_code')) is not int or item['exit_code'] != 0 for item in scenarios):
        raise ValueError('native evidence lacks successful scenario exit codes')
    if not valid_digest(report.get('native_test_sha256')):
        raise ValueError('native evidence lacks test executable digest')
    namespace, parent = report.get('namespace'), report.get('parent_namespace')
    if type(namespace) is not int or type(parent) is not int or namespace <= 0 or parent <= 0 or namespace == parent:
        raise ValueError('native evidence lacks distinct positive namespace identifiers')
    launcher = report.get('namespace_launcher')
    if not isinstance(launcher, dict) or type(launcher.get('exit_code')) is not int or launcher['exit_code'] != 0:
        raise ValueError('native evidence lacks a successful namespace launcher')


def validate_decoder(report, expected_tshark=TSHARK_VERSION):
    profile = report.get('profile')
    if not isinstance(profile, str) or profile not in DECODE_PROFILES:
        raise ValueError('decoder evidence has an unknown corpus profile')
    if report.get('expected_tshark') != expected_tshark or not tshark_matches(report.get('tshark'), expected_tshark):
        raise ValueError('decoder evidence lacks the pinned TShark identity')
    if not valid_digest(report.get('tshark_sha256')):
        raise ValueError('decoder evidence lacks TShark binary digest')
    fields = report.get('fields')
    expected_fields = {field[2] for field in DECODE_FIELDS}
    if (not isinstance(fields, list) or not all(isinstance(field, str) for field in fields)
            or len(fields) != len(expected_fields) or set(fields) != expected_fields):
        raise ValueError('decoder evidence lacks the complete comparison field set')
    if report.get('mismatches') != []:
        raise ValueError('decoder evidence lacks an explicit empty mismatch list')
    expected = DECODE_PROFILES[profile]
    for capture in named_results(report.get('captures'), expected, 'decoder captures'):
        if not valid_digest(capture.get('sha256')):
            raise ValueError(f"decoder capture {capture['name']}: missing input digest")
        if type(capture.get('frames')) is not int or capture['frames'] != expected[capture['name']]:
            raise ValueError(f"decoder capture {capture['name']}: unexpected physical frame count")
        if type(capture.get('mismatches')) is not int or capture['mismatches'] != 0:
            raise ValueError(f"decoder capture {capture['name']}: missing or nonzero mismatch count")
    ja3 = report.get('tls_ja3')
    if not isinstance(ja3, dict) or ja3.get('capture') != 'tls-handshake':
        raise ValueError('decoder evidence lacks the named TLS JA3 comparison')
    fingerprints = ja3.get('expected')
    if (not isinstance(fingerprints, list) or len(fingerprints) != 1
            or not valid_digest(fingerprints[0], 32) or ja3.get('observed') != fingerprints):
        raise ValueError('decoder evidence lacks a successful TLS JA3 comparison')


def digest(path):
    with pathlib.Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def provenance(binary):
    return dict(schema_version=EVIDENCE_VERSION,
                commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
                binary_sha256=digest(binary),
                binary_version=subprocess.check_output([str(binary), '--version'], text=True, timeout=10).strip())
