# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Strict M12 evidence admission; inferred port states never establish socket truth."""
import copy
import json
from pathlib import Path
from tcp_diagnostic_wire import network, tcp
from native_platform_evidence import PROFILES, PLATFORMS, UNAVAILABLE_REASONS, hexadecimal, status_of
from tcp_diagnostic_corpus import MODES, expectation, validate as validate_corpus
from tcp_diagnostic_wire import outgoing, response, neighbor_request

SCHEMA = 'packetcraftr.tcp-diagnostic-native-evidence/v1'
SOURCES = ('192.0.2.1', '2001:db8::1')
SCRIPTED_TARGETS = ('192.0.2.2', '2001:db8::2')
KERNEL_TARGETS = ('127.0.0.1', '::1')
LIMITS = dict(max_probes=32, timeout_ms=500, max_duration_ms=10000,
              process_timeout_seconds=15, max_output_bytes=1048576,
              max_queue_frames=256, max_captured_bytes=1048576, snap_length=2048)


def strict_json(text):
    def unique(pairs):
        result = dict(pairs)
        if len(pairs) != len(result):
            raise ValueError('duplicate evidence field')
        return result
    def nonfinite(value):
        raise ValueError('nonfinite evidence number: ' + value)
    return json.loads(text, object_pairs_hook=unique, parse_constant=nonfinite)


def inventory():
    cases = []
    for provision in ('scripted', 'kernel'):
        for family in ('ipv4', 'ipv6'):
            for mode, flags in (MODES.items() if provision == 'scripted' else (('syn', 2), *MODES.items())):
                for window in (1, 4):
                    for output in ('json', 'ndjson'):
                        cases.append(dict(id=f'{provision}/{family}/{mode}/{window}/{output}',
                                          provision=provision, family=family, mode=mode, flags=flags,
                                          window=window, output=output))
    return cases


def initial(platform, revision, dirty, corpus_digest, sources, profiles, reason, message):
    return dict(schema=SCHEMA, platform=platform, source_revision=revision, source_dirty=dirty,
                reviewed_commit=revision, corpus_digest_sha256=corpus_digest, sources=sources,
                acceptance_complete=False, profiles=[dict(profile=profile, status='incomplete',
                    cases=[dict(**case, status='unavailable', reason=reason, message=message)
                           for case in inventory()]) for profile in profiles])


def frame_bytes(frame, captured=False):
    data = frame.get('bytes_hex')
    if not isinstance(data, str) or len(data) % 2 or len(data) > 4096:
        raise ValueError('invalid/unbounded frame evidence')
    raw = bytes.fromhex(data)
    if captured:
        if frame.get('captured_length') != len(raw) or frame.get('original_length') != len(raw):
            raise ValueError('truncated captured evidence')
        stamp = frame.get('timestamp')
        if not isinstance(stamp, dict) or type(stamp.get('unix_seconds')) is not int or not (
                type(stamp.get('nanoseconds')) is int and 0 <= stamp['nanoseconds'] < 1000000000):
            raise ValueError('captured evidence lacks exact timestamp')
    elif frame.get('length') != len(raw):
        raise ValueError('wire length contradicts bytes')
    return raw


def kernel_targets(platform):
    return ('198.51.100.2', '2001:db8:1::2') if platform == 'Linux' else KERNEL_TARGETS


def report_status(profiles):
    return 'failed' if any(profile['status'] == 'failed' or profile.get('error') for profile in profiles) else (
        'incomplete' if any(profile['status'] != 'exercised' for profile in profiles) else 'exercised')


def coverage_complete(report):
    return (not report['source_dirty'] and report.get('reviewed_commit') == report['source_revision'] and
            [profile['profile'] for profile in report['profiles']] == list(PROFILES) and
            not report.get('launcher_error') and all(not profile.get('error') and
                all(case['status'] == 'exercised' or (case['status'] == 'unavailable' and case.get('expected_refusal') is True)
                    for case in profile['cases']) for profile in report['profiles']))


def command(binary, case, target, ports, link_mode='layer3'):
    args = [str(binary), '--output', case['output'], 'scan', target,
            '--ports', ','.join(map(str, ports)), '--tcp-scan', case['mode'],
            '--method', 'raw', '--link-mode', link_mode, '--attempts', '1',
            '--max-in-flight', str(case['window']), '--timeout-ms', '500',
            '--max-duration-ms', '10000', '--max-probes', '32', '--max-queue-frames', '256',
            '--max-captured-bytes', '1048576', '--snap-length', '2048']
    if case['mode'] == 'custom':
        args += ['--tcp-flags', '0x001']
    return args


def documents(run, mode, successful=True):
    if not isinstance(run.get('stdout'), str) or not isinstance(run.get('stderr'), str) or any(
            len(run[key].encode()) > LIMITS['max_output_bytes'] for key in ('stdout', 'stderr')):
        raise ValueError('missing/unbounded process evidence')
    docs = ([strict_json(run['stdout'])] if mode == 'json' else
            [strict_json(line) for line in run['stdout'].splitlines() if line.strip()])
    if not docs or any(doc.get('schema') != 'packetcraftr.output/v15' or doc.get('command') != 'scan' for doc in docs):
        raise ValueError('missing/current-version scan evidence')
    if mode == 'ndjson':
        if [doc.get('sequence') for doc in docs] != list(range(len(docs))):
            raise ValueError('noncontiguous stream sequence')
        terminals = [doc for doc in docs if doc.get('event') in ('complete', 'error')]
        if len(terminals) != 1 or terminals[0] is not docs[-1]:
            raise ValueError('missing/duplicate/nonterminal stream completion')
    if successful and (run.get('exit_code') != 0 or any(doc.get('status') != 'success' for doc in docs)):
        raise ValueError('native process did not complete successfully')
    return docs


def observed_expectation(corpus, mode, reply, window):
    if mode == 'syn':
        if reply not in ('tcp_syn_ack', 'tcp_reset'):
            raise ValueError('SYN control did not establish socket prerequisites')
        return dict(status='response', classification='open' if reply == 'tcp_syn_ack' else 'closed',
                    reply=reply, tcp_window=window, state='open' if reply == 'tcp_syn_ack' else 'closed',
                    rule='tcp_syn.syn_ack' if reply == 'tcp_syn_ack' else 'tcp_syn.reset')
    condition = ({None: 'silent', 'icmp_administratively_prohibited': 'prohibited',
                  'icmp_destination_unreachable': 'port-unreachable', 'icmp_time_exceeded': 'time-exceeded',
                  'tcp_other': 'unexpected'}).get(reply)
    if reply == 'tcp_reset':
        condition = 'reset-positive' if window else 'reset-zero'
    if condition is None:
        raise ValueError('native reply outside declared diagnostic contract')
    row = copy.deepcopy(expectation(corpus, condition, mode))
    row['tcp_window'] = window
    return row


def preparation_frames(profile, case, run):
    if run.get('link_mode') != 'layer2':
        return []
    frames = (profile.get('independent_peer', {}).get('neighbor_requests', []) if case['provision'] == 'scripted'
              else profile.get('kernel_capture', {}).get('frames', []))
    target = (SCRIPTED_TARGETS if case['provision'] == 'scripted' else kernel_targets(run['platform']))[case['family'] == 'ipv6']
    source = (SOURCES if case['provision'] == 'scripted' else ('198.51.100.1', '2001:db8:1::1'))[case['family'] == 'ipv6']
    return [bytes.fromhex(frame['bytes_hex']) for frame in frames
            if run['started_unix_ns'] <= frame.get('unix_ns', 0) <= run['finished_unix_ns']
            and neighbor_request(bytes.fromhex(frame['bytes_hex']), frame['link_type'], target, source)]


def validate_output(run, case, corpus, preparation=None):
    ports = list(range(1000, 1008)) if case['provision'] == 'scripted' else [43123, 43125]
    target = (SCRIPTED_TARGETS if case['provision'] == 'scripted' else kernel_targets(run.get('platform')))[case['family'] == 'ipv6']
    if run.get('command') != command(run.get('command', [''])[0], case, target, ports, run.get('link_mode')) or run.get('limits') != LIMITS:
        raise ValueError('native command changed literal endpoints or finite limits')
    if run.get('error') or run.get('timed_out'):
        raise ValueError('failed process cannot establish native coverage')
    docs = documents(run, case['output'])
    if type(run.get('started_unix_ns')) is not int or type(run.get('finished_unix_ns')) is not int or not 0 < run['finished_unix_ns'] - run['started_unix_ns'] <= 16000000000:
        raise ValueError('missing/unbounded process timing')
    if case['output'] == 'json':
        result = docs[0]['result']
        endpoints = result['endpoints']
        probes = [probe for endpoint in endpoints for probe in endpoint['probes']]
        extras = result.get('unattributed', [])
        hosts = result.get('hosts', [])
    else:
        result = docs[-1]['result']
        endpoints = [doc['result']['endpoint'] for doc in docs if doc.get('event') == 'endpoint']
        probes = [doc['result']['probe'] for doc in docs if doc.get('event') == 'probe']
        extras = [doc['result']['unattributed'] for doc in docs if doc.get('event') == 'unattributed']
        hosts = [doc['result'] for doc in docs if doc.get('event') == 'host']
        if any(doc.get('event') == 'undecoded' for doc in docs):
            raise ValueError('undecoded native stream evidence')
    if result.get('target') != target or result.get('resolved_addresses') != [target]:
        raise ValueError('native scan changed literal target resolution')
    if result.get('plan', {}).get('tcp_scan') != dict(mode=case['mode'], flags=case['flags']):
        raise ValueError('effective TCP scan mode mismatch')
    if len(hosts) != 1:
        raise ValueError('native output omitted its host disposition')
    if any(host.get('scan') != 'scanned' or host.get('discovery') != 'not_requested' for host in hosts):
        raise ValueError('unrequested discovery/incomplete native host')
    if sorted(endpoint['port'] for endpoint in endpoints) != ports or len(probes) != len(ports):
        raise ValueError('native endpoint/attempt inventory mismatch')
    stats = docs[-1].get('stats', {})
    probe_bytes = (40 if case['family'] == 'ipv4' else 60) + (14 if run.get('link_mode') == 'layer2' else 0)
    if run.get('link_mode') == 'layer2' and preparation is None:
        # Live capture drains fully on fixture cleanup. Check the ceiling here;
        # final validation binds every preparation packet to independent bytes.
        packets = stats.get('packets_attempted')
        if type(packets) is not int or not len(ports) <= packets <= LIMITS['max_probes'] or stats.get('packets_completed') != packets or type(stats.get('bytes')) is not int or stats['bytes'] < len(ports) * probe_bytes:
            raise ValueError('native packet accounting mismatch')
    else:
        preparation = preparation or []
        packets = len(ports) + len(preparation)
        if packets > LIMITS['max_probes'] or stats.get('bytes') != len(ports) * probe_bytes + sum(map(len, preparation)) or stats.get('packets_attempted') != packets or stats.get('packets_completed') != packets:
            raise ValueError('native packet accounting mismatch')
    if result.get('retained_evidence_bytes', -1) not in range(0, 1048577):
        raise ValueError('native evidence budget exceeded')
    capture = stats.get('capture', {})
    if any(capture.get(key, 0) for key in ('dropped_frames', 'dropped_bytes', 'overflow_events')):
        raise ValueError('capture loss prevents native completeness')
    if result.get('undecoded'):
        raise ValueError('undecoded fixture evidence prevents native completeness')
    retained = [probe['frame'] for probe in probes if probe.get('frame')] + [item['frame'] for item in extras]
    for frame in retained:
        frame_bytes(frame, True)
        stamp = frame['timestamp']
        if not run['started_unix_ns'] <= stamp['unix_seconds'] * 1000000000 + stamp['nanoseconds'] <= run['finished_unix_ns']:
            raise ValueError('native frame timestamp is outside its invocation')
    if sum(len(frame_bytes(frame, True)) for frame in retained) != result.get('retained_evidence_bytes'):
        raise ValueError('native retained byte charge lost/added exact frames')
    sequences, observations, divergences = set(), [], []
    for endpoint in endpoints:
        port = endpoint['port']
        if endpoint.get('address') != target or endpoint.get('scope') is not None or endpoint.get('transport') != 'tcp':
            raise ValueError('native endpoint scope/transport mismatch')
        owned = endpoint['probes']
        selected = owned if case['output'] == 'json' else [probe for probe in probes if probe['sequence'] in owned]
        if len(selected) != 1:
            raise ValueError('native endpoint omitted/shared an attempt')
        probe = selected[0]
        identity = probe['sequence']
        if identity in sequences or probe.get('attempt') != 1 or probe.get('tcp_scan') != dict(mode=case['mode'], flags=case['flags']):
            raise ValueError('native attempt identity/mode mismatch')
        sequences.add(identity)
        captured = probe.get('frame')
        reply, window = None, None
        if probe.get('status') == 'response':
            if not captured:
                raise ValueError('native positive response has no exact frame')
            reply, window = response(frame_bytes(captured, True), captured['link_type'], target, port,
                                     identity, case['flags'])
            # The diagnostic matcher retains unexpected SYN/ACK as TcpOther.
            if reply == 'tcp_syn_ack' and case['mode'] != 'syn':
                reply = 'tcp_other'
        elif probe.get('status') != 'timeout' or captured:
            raise ValueError('operational failure is not a port state')
        row = (expectation(corpus, corpus['tcp_diagnostic_scenarios'][port - 1000]['id'], case['mode'])
               if case['provision'] == 'scripted' else observed_expectation(corpus, case['mode'], reply, window))
        if (reply, window) != (row['reply'], row['tcp_window']):
            raise ValueError('native response disagrees with independent wire fixture')
        for key in ('status', 'classification', 'tcp_window'):
            if probe.get(key) != row[key]:
                raise ValueError('native diagnostic attempt disagrees with contract: ' + key)
        inference = endpoint.get('inference') or {}
        if endpoint.get('classification') != row['classification'] or any(inference.get(key) != row[key] for key in ('state', 'rule')):
            raise ValueError('native classification/inference rule mismatch')
        if inference.get('supporting') != [identity] or any(inference.get(key) != [] for key in ('conflicting', 'unanswered', 'failed')):
            raise ValueError('native evidence partition lost/shared attempt evidence')
        truth = None if case['provision'] == 'scripted' else ('open' if port == 43123 else 'closed')
        if case['mode'] == 'syn' and truth != row['state']:
            raise ValueError('SYN control contradicts independently reserved sockets')
        if truth and case['mode'] != 'syn' and row['state'] in ('open', 'closed') and row['state'] != truth:
            divergences.append(dict(port=port, socket_truth=truth, inferred_state=row['state'], rule=row['rule']))
        observations.append(dict(port=port, sequence=identity, reply=reply, tcp_window=window,
                                 state=row['state'], rule=row['rule'], socket_truth=truth))
    return dict(observations=observations, divergences=divergences)


def validate(report, corpus, expected_commit=None, require_complete=False, expected_sources=None, expected_corpus_digest=None):
    validate_corpus(corpus)
    if report.get('schema') != SCHEMA or report.get('platform') not in PLATFORMS:
        raise ValueError('unknown M12 evidence schema/platform')
    revision = report.get('source_revision')
    if not hexadecimal(revision, 40) or type(report.get('source_dirty')) is not bool:
        raise ValueError('missing exact source identity')
    if expected_commit and (revision != expected_commit or report.get('reviewed_commit') != expected_commit):
        raise ValueError('native report changed reviewed commit')
    if not hexadecimal(report.get('corpus_digest_sha256'), 64) or not report.get('sources') or any(
            not isinstance(path, str) or not hexadecimal(sha, 64) for path, sha in report['sources'].items()):
        raise ValueError('missing corpus/runner/fixture source digests')
    if expected_sources is not None and report['sources'] != expected_sources:
        raise ValueError('native source digests changed')
    if expected_corpus_digest is not None and report['corpus_digest_sha256'] != expected_corpus_digest:
        raise ValueError('native corpus digest changed')
    required_sources = {'scripts/test-tcp-diagnostics-native.py', 'scripts/tcp_diagnostic_native_evidence.py',
                        'scripts/tcp_diagnostic_isolated_fixture.py', 'scripts/tcp_diagnostic_wire.py',
                        'scripts/tcp_diagnostic_capture.py', 'scripts/tcp_diagnostic_corpus.py', 'scripts/tcp_diagnostic_kernel_fixture.py', 'scripts/discovery_isolated_fixture.py',
                        'scripts/validation_evidence.py', 'scripts/benchmark-scanner.py', 'scripts/native_platform_evidence.py',
                        'schemas/packetcraftr.scanner-corpus.v1.schema.json', 'Cargo.toml', 'Cargo.lock',
                        'rust-toolchain.toml', 'docs/scanner-corpus.v1.json'}
    if not required_sources <= set(report['sources']):
        raise ValueError('omitted acceptance implementation identity')
    profiles = report.get('profiles', [])
    names = [profile.get('profile') for profile in profiles]
    if not names or names != [profile for profile in PROFILES if profile in names]:
        raise ValueError('unknown/duplicate/unordered feature profiles')
    complete = not report['source_dirty'] and report.get('reviewed_commit') == revision and names == list(PROFILES) and not report.get('launcher_error')
    for profile in profiles:
        complete &= not bool(profile.get('error'))
        cases = profile.get('cases', [])
        if [case.get('id') for case in cases] != [case['id'] for case in inventory()]:
            raise ValueError('missing/duplicate/unordered M12 native cases')
        for case, expected in zip(cases, inventory()):
            if any(case.get(key) != value for key, value in expected.items()):
                raise ValueError('native case changed immutable fixture inventory')
            run = case.get('run')
            if run and case['status'] != 'failed':
                if profile.get('execution') != 'privileged_native' or profile.get('privilege_granted') is not True or not hexadecimal(profile.get('binary_digest_sha256'), 64):
                    raise ValueError('native invocation lacks privileged executable provenance')
                target = (SCRIPTED_TARGETS if case['provision'] == 'scripted' else kernel_targets(report['platform']))[case['family'] == 'ipv6']
                ports = list(range(1000, 1008)) if case['provision'] == 'scripted' else [43123, 43125]
                binary = profile.get('binary')
                if not isinstance(binary, str) or not Path(binary).is_absolute() or run.get('command') != command(binary, case, target, ports, run.get('link_mode')) or run.get('limits') != LIMITS:
                    raise ValueError('native invocation changed executable/endpoints/budgets')
                if run.get('platform') != report['platform'] or run.get('link_mode') != ('layer2' if profile['profile'] == 'layer2' else 'layer3'):
                    raise ValueError('native invocation changed platform/link mode')
            status = case.get('status')
            if status == 'failed':
                if not case.get('message'):
                    raise ValueError('native failure lost its reason')
                complete = False
            elif status == 'unavailable':
                if case.get('reason') not in UNAVAILABLE_REASONS or not case.get('message'):
                    raise ValueError('native unavailability lost its precise reason')
                run = case.get('run')
                expected_refusal = False
                if run:
                    docs = documents(run, case['output'], successful=False)
                    error = docs[-1].get('error', {})
                    expected_refusal = (names and (profile['profile'] in ('portable', 'default', 'pcap-free') or
                                         profile['profile'] == 'layer2' and case['provision'] == 'kernel' and report['platform'] != 'Linux') and
                                        case['reason'] == 'unsupported_capability' and
                                        type(run.get('exit_code')) is int and run['exit_code'] != 0 and
                                        docs[-1].get('status') == 'error' and
                                        error.get('code') in ('capability.unsupported', 'capability.route'))
                    if not expected_refusal and case.get('expected_refusal'):
                        raise ValueError('unsupported coverage lacks actual typed refusal')
                if case.get('expected_refusal', False) != bool(expected_refusal):
                    raise ValueError('typed refusal coverage relabeled')
                complete &= expected_refusal
            elif status == 'exercised':
                if report['source_dirty'] or profile.get('execution') != 'privileged_native' or profile.get('privilege_granted') is not True:
                    raise ValueError('native exercise lacks clean privileged execution')
                if not hexadecimal(profile.get('binary_digest_sha256'), 64) or not profile.get('capture_backend_version'):
                    raise ValueError('missing executable/backend provenance')
                isolation = profile.get('isolation', {})
                if report['platform'] == 'Linux':
                    parent, child = isolation.get('parent_netns_inode'), isolation.get('netns_inode')
                    if isolation.get('kind') != 'fresh_network_namespace' or type(parent) is not int or type(child) is not int or parent <= 0 or child <= 0 or parent == child or isolation.get('initial_interfaces') != ['lo']:
                        raise ValueError('Linux native evidence lacks parent-distinct isolation')
                elif isolation != dict(kind='host_local_only', external_destinations=False, interface_mutation=False):
                    raise ValueError('host native execution changed its local-only boundary')
                if case['provision'] == 'scripted' and report['platform'] != 'Linux':
                    raise ValueError('host loopback cannot exercise scripted link peer')
                run = case.get('run') or {}
                if not isinstance(run.get('command'), list) or not run['command'] or not Path(run['command'][0]).is_absolute():
                    raise ValueError('missing absolute executable command')
                if run.get('platform') != report['platform'] or run.get('link_mode') != ('layer2' if profile['profile'] == 'layer2' else 'layer3'):
                    raise ValueError('native run changed platform/link mode')
                if run.get('observation') != validate_output(run, case, corpus, preparation_frames(profile, case, run)):
                    raise ValueError('retained observation/heuristic divergences were altered')
                if case['provision'] == 'kernel':
                    validate_kernel_capture(profile, case, run)
                    if profile.get('kernel_cleanup') != 'sockets_closed':
                        raise ValueError('kernel socket cleanup missing')
                    if report['platform'] == 'Linux':
                        peer = profile.get('kernel_peer', {})
                        ready = peer.get('ready', {})
                        if ready.get('parent_netns_inode') != isolation['netns_inode'] or type(ready.get('netns_inode')) is not int or ready['netns_inode'] == isolation['netns_inode'] or not peer.get('setup') or peer.get('cleanup', {}).get('exit_code') != 0 or peer.get('cleanup_failed'):
                            raise ValueError('Linux kernel peer lacks independent namespace/cleanup')
                    if profile.get('kernel_fixture', {}).get(case['family']) != dict(target=kernel_targets(report['platform'])[case['family'] == 'ipv6'], listening_port=43123, reserved_non_listening_port=43125, syn_control_required=True):
                        raise ValueError('missing independently provisioned socket truth')
                else:
                    validate_peer(profile, case, run)
            else:
                raise ValueError('unknown native case status')
        if profile.get('status') != status_of(cases):
            raise ValueError('profile status omits failure/unavailable coverage')
    if report.get('status') != report_status(profiles):
        raise ValueError('report status omits failure/unavailable coverage')
    if report.get('acceptance_complete') is not complete:
        raise ValueError('acceptance completion contradicts retained coverage')
    if require_complete and not complete:
        raise ValueError('M12 acceptance lacks clean complete supported runtime coverage')
    return complete


def retained_frames(run, case):
    """Keep attribution separate from other retained traffic in either output format."""
    docs = documents(run, case['output'])
    if case['output'] == 'json':
        result = docs[0]['result']
        probes = [probe for endpoint in result['endpoints'] for probe in endpoint['probes']]
        extras = [item['frame'] for item in result.get('unattributed', [])]
    else:
        probes = [doc['result']['probe'] for doc in docs if doc.get('event') == 'probe']
        extras = [doc['result']['unattributed']['frame'] for doc in docs if doc.get('event') == 'unattributed']
    return {probe['sequence']: probe['frame'] for probe in probes if probe.get('frame')}, extras


def validate_peer(profile, case, run):
    peer = profile.get('independent_peer', {})
    requests = peer.get('requests', [])
    neighbors = peer.get('neighbor_requests', [])
    if not isinstance(requests, list) or not isinstance(neighbors, list) or len(requests) + len(neighbors) > 4096 or not peer.get('setup') or peer.get('cleanup', {}).get('exit_code') != 0:
        raise ValueError('independent peer lacks bounded provisioning/cleanup evidence')
    if sum(len(request.get('bytes_hex', '')) // 2 + sum(len(answer.get('bytes_hex', '')) // 2 for answer in request.get('replies', [])) for request in [*requests, *neighbors]) > 1048576:
        raise ValueError('independent peer exceeded its byte ceiling')
    identities = {item['sequence']: item['port'] for item in run['observation']['observations']}
    matched = {}
    target = SCRIPTED_TARGETS[case['family'] == 'ipv6']
    attributed, extras = retained_frames(run, case)
    captures = [*attributed.values(), *extras]
    captured_packets = [network(frame_bytes(frame, True), frame['link_type'])['wire'] for frame in captures]
    recorded_replies = set()
    for request in requests:
        if not run['started_unix_ns'] <= request.get('unix_ns', 0) <= run['finished_unix_ns']:
            continue
        raw = bytes.fromhex(request['bytes_hex'])
        ip = network(raw, 1)
        segment = tcp(ip)
        identity = segment['sequence']
        if identity not in identities or ip['target'] != target or segment['port'] != identities[identity]:
            continue
        if identity in matched:
            raise ValueError('peer received duplicate diagnostic probe identity')
        sent = outgoing(raw, 1, case['mode'], case['flags'], identity, target, identities[identity])
        if type(request.get('unix_ns')) is not int or type(request.get('monotonic_ns')) is not int:
            raise ValueError('peer request lacks exact timestamps')
        port = identities[identity]
        expected_count = 0 if port == 1002 else 2 if port == 1005 else 1
        if len(request.get('replies', [])) != expected_count:
            raise ValueError('peer omitted independently provisioned replies')
        replies = set()
        for answer in request['replies']:
            if answer.get('link_type') != 1 or type(answer.get('unix_ns')) is not int or type(answer.get('monotonic_ns')) is not int:
                raise ValueError('peer response lacks exact wire scope/timestamps')
            answer_bytes = bytes.fromhex(answer['bytes_hex'])
            response(answer_bytes, 1, target, port, identity, case['flags'], sent)
            replies.add(network(answer_bytes, 1)['wire'])
        recorded_replies.update(replies)
        if identity in attributed:
            frame = attributed[identity]
            raw_response = frame_bytes(frame, True)
            response(raw_response, frame['link_type'], target, port, identity, case['flags'], sent)
            if network(raw_response, frame['link_type'])['wire'] not in replies:
                raise ValueError('attributed capture contradicts independent peer reply bytes')
        matched[identity] = request
    if set(matched) != set(identities):
        raise ValueError('independent peer did not observe every expected outgoing probe')
    if any(packet not in recorded_replies for packet in captured_packets):
        raise ValueError('retained capture is absent from independent peer replies')


def validate_kernel_capture(profile, case, run):
    capture = profile.get('kernel_capture', {})
    if capture.get('cleanup_complete') is not True or not capture.get('backend_version') or not capture.get('filter'):
        raise ValueError('kernel fixture lacks independent capture/cleanup')
    statistics = capture.get('statistics', {})
    if set(statistics) != {'received', 'dropped', 'interface_dropped'} or any(type(value) is not int or value < 0 for value in statistics.values()) or statistics['dropped'] or statistics['interface_dropped']:
        raise ValueError('independent kernel capture lacks loss-free native statistics')
    target = kernel_targets(run['platform'])[case['family'] == 'ipv6']
    identities = {item['sequence']: item['port'] for item in run['observation']['observations']}
    matched = {}
    frames = capture.get('frames', [])
    if len(frames) > 4096 or sum(len(frame.get('bytes_hex', '')) // 2 for frame in frames) > 1048576:
        raise ValueError('kernel capture retention exceeds finite ceilings')
    for frame in frames:
        if not run['started_unix_ns'] <= frame.get('unix_ns', 0) <= run['finished_unix_ns']:
            continue
        raw = bytes.fromhex(frame['bytes_hex'])
        if frame['link_type'] == 1 and raw[12:14] == b'\x08\x06':
            continue  # ARP preparation is accounted independently of TCP.
        ip = network(raw, frame['link_type'])
        if ip['target'] != target or ip['proto'] != 6:
            continue
        segment = tcp(ip)
        identity = segment['sequence']
        if identity not in identities or segment['port'] != identities[identity] or segment['flags'] & 4:
            continue  # The host kernel may reset an unsolicited SYN/ACK.
        outgoing(raw, frame['link_type'], case['mode'], case['flags'], identity, target, identities[identity])
        if identity in matched and matched[identity][0]['wire'] != ip['wire']:
            raise ValueError('kernel capture shares an identity across distinct wire probes')
        matched.setdefault(identity, (ip, segment, frame['unix_ns']))
    if set(matched) != set(identities):
        raise ValueError('independent kernel capture omitted an outgoing probe')
    attributed, _ = retained_frames(run, case)
    for identity, port in identities.items():
        sent_ip, sent_tcp, sent_ns = matched[identity]
        replies = set()
        for frame in frames:
            stamp = frame.get('unix_ns', 0)
            if not sent_ns <= stamp <= min(run['finished_unix_ns'], sent_ns + LIMITS['timeout_ms'] * 1000000):
                continue
            raw = bytes.fromhex(frame['bytes_hex'])
            if frame['link_type'] == 1 and raw[12:14] == b'\x08\x06':
                continue
            ip = network(raw, frame['link_type'])
            if ip['source'] != target or ip['target'] != sent_ip['source']:
                continue
            try:
                response(raw, frame['link_type'], target, port, identity, case['flags'], (sent_ip, sent_tcp))
            except ValueError:
                continue  # Other probes and kernel-generated traffic are not this exchange.
            replies.add(ip['wire'])
        if identity in attributed:
            frame = attributed[identity]
            raw = frame_bytes(frame, True)
            response(raw, frame['link_type'], target, port, identity, case['flags'], (sent_ip, sent_tcp))
            if network(raw, frame['link_type'])['wire'] not in replies:
                raise ValueError('kernel response lacks timely independent correlated capture')
        elif replies:
            raise ValueError('kernel timeout contradicts timely independent response')
