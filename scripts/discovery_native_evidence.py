# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Strict inventory and runtime-output verification for M5 native evidence."""
import re

from discovery_native_fixture import MODES, REASONS, measurements, validate_router_evidence
from discovery_isolated_fixture import addresses
from native_platform_evidence import PROFILES, UNAVAILABLE_REASONS

SCHEMA = 'packetcraftr.discovery-native-evidence/v1'
HEX = re.compile(r'[0-9a-f]{64}')


def inventory():
    return [(name, family) for family in ('ipv4', 'ipv6') for name in REASONS] + [
        (name, family) for family in ('ipv4', 'ipv6') for name in ('connect-responsive', 'connect-closed')]


def status(cases):
    if any(case['status'] == 'failed' for case in cases):
        return 'failed'
    return 'incomplete' if any(case['status'] == 'unavailable' for case in cases) else 'exercised'


def expected_capability_refusal(profile, case):
    """These profiles have no capture; only a real typed refusal closes that path."""
    if (case['status'] != 'unavailable' or profile['name'] not in ('portable', 'default', 'pcap-free')
            or case['name'].startswith('connect-') or case.get('reason_code') != 'unsupported_capability'
            or not case.get('runs')):
        return False
    run = case['runs'][0]
    if type(run.get('exit_code')) is not int or run['exit_code'] == 0:
        return False
    output = measurements.strict_json(run['stdout'])
    return (output.get('schema') in ('packetcraftr.output/v10', 'packetcraftr.output/v11') and output.get('status') == 'error'
            and output.get('error', {}).get('kind') == 'capability'
            and output['error'].get('code') in ('capability.unsupported', 'capability.route'))


def validate(report, expected_commit=None, require_complete=False):
    if report.get('schema') != SCHEMA or report.get('platform') not in ('Linux', 'macOS', 'Windows'):
        raise ValueError('unknown discovery evidence contract or platform')
    if not re.fullmatch('[0-9a-f]{40}', report.get('commit', '')) or type(report.get('dirty')) is not bool:
        raise ValueError('native evidence lacks revision provenance')
    if expected_commit is not None and (report['commit'] != expected_commit or report['dirty']):
        raise ValueError('native discovery evidence is not bound to the clean reviewed revision')
    if not HEX.fullmatch(report.get('corpus_sha256', '')) or not report.get('corpus_dataset_version'):
        raise ValueError('native evidence lacks independently authored corpus provenance')
    if not all(HEX.fullmatch(report.get(field, '')) for field in (
            'fixture_sha256', 'peer_fixture_sha256', 'launcher_sha256')):
        raise ValueError('native evidence lacks fixture-source provenance')
    if require_complete and (report.get('error') or report.get('validation_error')):
        raise ValueError('failed native launcher record cannot close acceptance')
    profiles = report['profiles']
    names = [profile['name'] for profile in profiles]
    if names != [name for name in PROFILES if name in names] or not names:
        raise ValueError('native profiles must be unique and in the supported order')
    for profile in profiles:
        cases = profile['scenarios']
        if [(case['name'], case['family']) for case in cases] != inventory():
            raise ValueError('native discovery inventory is missing, duplicated, or reordered')
        if profile['status'] != status(cases):
            raise ValueError('native profile status contradicts its runtime inventory')
        for case in cases:
            state = case['status']
            if state == 'unavailable':
                if case.get('reason_code') not in UNAVAILABLE_REASONS or not case.get('reason'):
                    raise ValueError('unavailable native discovery needs a precise nonempty reason')
                continue
            if state == 'failed':
                if not case.get('error'):
                    raise ValueError('failed native discovery needs its retained failure')
                continue
            if state != 'exercised':
                raise ValueError('unknown native discovery status')
            if profile.get('execution') != 'privileged_native' or profile.get('privilege_granted') is not True:
                raise ValueError('compilation or fixture mocks are not native execution')
            if not HEX.fullmatch(profile.get('binary_sha256', '')):
                raise ValueError('native execution lacks an executable digest')
            isolation = profile['isolation']
            if report['platform'] == 'Linux':
                if (isolation.get('kind') != 'fresh_network_namespace' or
                        type(isolation.get('namespace')) is not int or isolation['namespace'] <= 0 or
                        type(isolation.get('parent_namespace')) is not int or isolation['parent_namespace'] <= 0 or
                        isolation['namespace'] == isolation['parent_namespace']):
                    raise ValueError('Linux native discovery was not admitted in a fresh namespace')
            elif isolation != dict(kind='host_local_only', external_destinations=False, interface_mutation=False):
                raise ValueError('host native discovery changed its admission boundary')
            runs = case['runs']
            if [run['mode'] for run in runs] != list(MODES):
                raise ValueError('native discovery lacks the complete follow-up choices')
            for run in runs:
                if run.get('exit_code') != 0 or run.get('error') or not run.get('command'):
                    raise ValueError('failed or unexecuted command cannot be exercised evidence')
                if len(run['stdout'].encode()) > measurements.OUTPUT_LIMIT or len(run['stderr'].encode()) > measurements.OUTPUT_LIMIT:
                    raise ValueError('native runtime output exceeds finite evidence bound')
                output = measurements.strict_json(run['stdout'])
                if output.get('schema') not in ('packetcraftr.output/v10', 'packetcraftr.output/v11') or output.get('status') != 'success':
                    raise ValueError('native command did not publish the successful machine contract')
                if report['platform'] == 'Linux' and case['name'] in ('discovery-blocked', 'discovery-routed'):
                    validate_router_evidence(output, case['family'] == 'ipv4', case['name'] == 'discovery-blocked')
                result = output['result']
                targets = ['127.0.0.1' if case['family'] == 'ipv4' else '::1']
                if report['platform'] == 'Linux' and not case['name'].startswith('connect-'):
                    local = addresses(case['family'] == 'ipv4')
                    index = list(REASONS).index(case['name'])
                    targets = local[1:3] if index == 5 else [local[-1] if index == 4 else local[index + 1]]
                if [host['address'] for host in result['hosts']] != targets:
                    raise ValueError('runtime output escaped the admitted literal target inventory')
                command = run['command']
                if command[1:4] != ['--output', 'json', 'scan'] or command[4:4 + len(targets)] != targets:
                    raise ValueError('recorded command escaped the admitted fixture')
                hosts, observation = result['hosts'], run['observation']
                expected_state = ('responded' if case['name'] in (
                    'discovery-responsive', 'discovery-closed-but-responsive', 'discovery-shared-link-address',
                    'connect-responsive', 'connect-closed') else 'no_response')
                expected_scan = ('not_requested' if run['mode'] == 'only' else 'scanned' if
                    case['name'] != 'discovery-silent' and (expected_state == 'responded' or
                    run['mode'] == 'before_all') else 'skipped')
                reasons = ({'tcp_connected'} if case['name'] == 'connect-responsive' else
                           {'tcp_refused'} if case['name'] == 'connect-closed' else REASONS[case['name']])
                if report['platform'] == 'Linux' and case['name'] in (
                        'discovery-responsive', 'discovery-closed-but-responsive'):
                    reasons = reasons | {'neighbor_reply'}
                elif report['platform'] != 'Linux' and case['name'] == 'discovery-closed-but-responsive':
                    reasons = {'icmp_echo_reply', 'tcp_reset'}
                count = 2 if case['name'] == 'discovery-shared-link-address' else 1
                if observation != dict(discovery=expected_state, scan=expected_scan, reasons=sorted(reasons),
                        hosts=count, endpoints=count if expected_scan == 'scanned' else 0):
                    raise ValueError('native observations contradict the independently authored fixture')
                if run['command'][1:4] != ['--output', 'json', 'scan']:
                    raise ValueError('native command is not the declared discovery workflow')
                if len(hosts) != observation['hosts'] or len(result['endpoints']) != observation['endpoints']:
                    raise ValueError('preserved machine output contradicts native observation counts')
                for host in hosts:
                    if host['discovery'] != observation['discovery'] or host['scan'] != observation['scan']:
                        raise ValueError('preserved host state contradicts native observation')
                    if sorted(reason['kind'] for reason in host['reasons']) != observation['reasons']:
                        raise ValueError('preserved host reasons contradict native observation')
                    evidence = 'socket' if case['name'].startswith('connect-') else 'wire'
                    if any(reason['evidence'] != evidence or reason['basis'] != (
                            'possible_proxy' if case['name'] == 'discovery-shared-link-address' else 'direct')
                            for reason in host['reasons']):
                        raise ValueError('native runtime evidence kind was relabeled')
    if report['status'] != status([case for profile in profiles for case in profile['scenarios']]):
        raise ValueError('native discovery status contradicts its profiles')
    if require_complete:
        if report['dirty'] or names != list(PROFILES):
            raise ValueError('acceptance requires every profile at a clean revision')
        for profile in profiles:
            for case in profile['scenarios']:
                if case['status'] == 'exercised':
                    continue
                # No capture capability was compiled: preserve and verify the
                # actual typed admission failure, rather than relabel a skip.
                if expected_capability_refusal(profile, case):
                    continue
                raise ValueError('required supported native discovery path remains unavailable or failed')
