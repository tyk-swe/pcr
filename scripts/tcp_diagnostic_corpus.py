# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""TCP diagnostic inventory validation; expectations are original corpus data, not output."""
from script_support import same_json

MODES = dict(ack=16, window=16, fin=1, null=0, xmas=41, maimon=17, custom=1)
CONDITIONS = ('reset-zero', 'reset-positive', 'silent', 'prohibited', 'unexpected',
              'reset-and-prohibited', 'port-unreachable', 'time-exceeded')
VARIANTS = ['ordinary', 'wrong_identity_and_checksum', 'reordered', 'duplicate', 'late']


def validate(corpus):
    cases = corpus.get('tcp_diagnostic_scenarios', [])
    if [case['id'] for case in cases] != list(CONDITIONS):
        raise ValueError('TCP diagnostic inventory missing, duplicated or reordered')
    for index, case in enumerate(cases):
        if set(case) != {'id', 'port', 'families', 'provision', 'request', 'variants', 'expected'}:
            raise ValueError('unknown diagnostic case fields')
        if type(case['port']) is not int or case['port'] != 1000 + index:
            raise ValueError('diagnostic port identity changed')
        if (case['families'] != ['ipv4', 'ipv6'] or case['variants'] != VARIANTS or
                case['provision'] != 'independent_tcp_reply_scripts' or not same_json(case['request'], dict(
                    attempts=1, timeout_ms=40, max_duration_ms=10000, max_probes=8,
                    max_evidence_bytes=65536, windows=[1, 4]))):
            raise ValueError('diagnostic fixture scope or bounds changed')
        if [row['mode'] for row in case['expected']] != list(MODES):
            raise ValueError('diagnostic mode inventory incomplete')
        for row in case['expected']:
            if set(row) != {'mode', 'flags', 'status', 'classification', 'reply', 'tcp_window',
                            'state', 'rule', 'partitions'}:
                raise ValueError('unknown diagnostic expectation fields')
            if type(row['flags']) is not int or row['flags'] != MODES[row['mode']]:
                raise ValueError('diagnostic flags disagree with declared mode')
            if row['status'] not in ('response', 'timeout') or row['classification'] not in (
                    'closed', 'filtered', 'unreachable', 'unknown', 'timeout'):
                raise ValueError('invalid diagnostic attempt expectation')
            if row['reply'] not in (None, 'tcp_reset', 'tcp_syn_ack', 'tcp_other', 'icmp_port_unreachable',
                                   'icmp_administratively_prohibited', 'icmp_destination_unreachable', 'icmp_time_exceeded'):
                raise ValueError('invalid diagnostic reply expectation')
            window = row['tcp_window']
            if window is not None and (type(window) is not int or not 0 <= window <= 65535):
                raise ValueError('invalid diagnostic window')
            if (row['status'] == 'timeout') != (row['reply'] is None):
                raise ValueError('silent attempt cannot carry a reply')
            if row['state'] not in ('open', 'closed', 'filtered', 'open_or_filtered', 'unfiltered', 'unknown'):
                raise ValueError('invalid diagnostic inference state')
            if not isinstance(row['rule'], str) or not row['rule'].startswith('tcp_' + row['mode'] + '.'):
                raise ValueError('invalid diagnostic rule identity')
            if not same_json(row['partitions'], dict(supporting=[1], conflicting=[], unanswered=[], failed=[])):
                raise ValueError('diagnostic partitions must reference the single local attempt')


def expectation(corpus, condition, mode):
    case = next(case for case in corpus['tcp_diagnostic_scenarios'] if case['id'] == condition)
    return next(row for row in case['expected'] if row['mode'] == mode)
