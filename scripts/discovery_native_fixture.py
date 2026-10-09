# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded discovery cases with independently stated socket and link expectations."""
import contextlib
import importlib.util
import json
import ipaddress
import pathlib
import socket
import threading

from discovery_isolated_fixture import SCANNER, addresses

spec = importlib.util.spec_from_file_location('scanner_measurements', pathlib.Path(__file__).with_name('benchmark-scanner.py'))
measurements = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measurements)

MODES = ('only', 'before', 'before_all')
REASONS = {
    'discovery-responsive': {'icmp_echo_reply', 'tcp_syn_ack', 'udp_payload'},
    'discovery-closed-but-responsive': {'icmp_echo_reply', 'tcp_reset', 'icmp_port_unreachable'},
    'discovery-silent': set(), 'discovery-blocked': set(), 'discovery-routed': set(),
    'discovery-shared-link-address': {'neighbor_reply'},
}


def unavailable(name, family, code, reason):
    return dict(name=name, family=family, status='unavailable', reason_code=code, reason=reason)


def run(binary, targets, mode, options, expected_state, expected_reasons, evidence='wire', possible_proxy=False, sendable=True, scan_port=22):
    command = [str(binary), '--output', 'json', 'scan', *targets]
    command += ['--discovery', 'only' if mode == 'only' else 'before', '--attempts', '1',
                '--timeout-ms', '500' if evidence == 'wire' else '5000',
                '--max-duration-ms', '10000' if evidence == 'wire' else '15000', '--max-probes', '32']
    command += options
    if mode != 'only':
        command += ['--ports', str(scan_port) if evidence == 'wire' else options[-1]]
    if mode == 'before_all':
        command += ['--unresponsive-hosts', 'scan']
    measured = measurements.measured(command)
    measured['mode'] = mode
    try:
        output = measurements.strict_json(measured['stdout'])
        if measured['exit_code'] or output.get('status') != 'success':
            measured['error'] = output.get('error', {})
            return measured
        result = output['result']
        expected_scan = 'not_requested' if mode == 'only' else (
            'scanned' if sendable and (expected_state == 'responded' or mode == 'before_all') else 'skipped')
        hosts = result['hosts']
        if [host['address'] for host in hosts] != targets:
            raise ValueError('native discovery changed the literal fixture target inventory')
        for host in hosts:
            if host['discovery'] != expected_state or host['scan'] != expected_scan:
                raise ValueError('native host state or requested follow-up contradicts the fixture')
            reasons = host['reasons']
            if {reason['kind'] for reason in reasons} != expected_reasons:
                raise ValueError('native discovery reasons contradict independently provisioned replies')
            if any(reason['evidence'] != evidence or reason['basis'] != (
                    'possible_proxy' if possible_proxy else 'direct') for reason in reasons):
                raise ValueError('native discovery relabeled evidence or link-address ambiguity')
        expected_endpoints = len(targets) if expected_scan == 'scanned' else 0
        if len(result['endpoints']) != expected_endpoints:
            raise ValueError('native workflow sent an unrequested scan or omitted the requested follow-up')
        measured['observation'] = dict(discovery=expected_state, scan=expected_scan,
                                       reasons=sorted(expected_reasons), hosts=len(hosts), endpoints=expected_endpoints)
    except Exception as error:
        measured['error'] = dict(code='fixture.contradiction', message=str(error))
    return measured



def validate_router_evidence(output, v4, blocked):
    """A missing reply is not interchangeable with an attributed router error."""
    router = ipaddress.ip_address(addresses(v4)[5])
    for host in output['result']['hosts']:
        probes = host['probes']
        if (len(probes) != 3 or len({probe['sequence'] for probe in probes}) != 3
                or {probe['protocol'] for probe in probes} != {'icmpv4' if v4 else 'icmpv6', 'tcp', 'udp'}):
            raise ValueError('router fixture requires evidence for every discovery transport')
        for probe in probes:
            if probe['status'] != 'response' or probe.get('responder') != str(router):
                raise ValueError('router error was lost or attributed to the target')
            frame = probe['frame']
            if frame['link_type'] != 1:
                raise ValueError('controlled link fixture did not retain Ethernet evidence')
            wire = bytes.fromhex(frame['bytes_hex'])[14:]
            if v4:
                valid = len(wire) >= 28 and wire[9] == 1 and wire[12:16] == router.packed
                icmp = wire[(wire[0] & 15) * 4:]
                expected = bytes((3, 13 if blocked else 1))
            else:
                valid = len(wire) >= 48 and wire[6] == 58 and wire[8:24] == router.packed
                icmp, expected = wire[40:], bytes((1, 1 if blocked else 3))
            if not valid or icmp[:2] != expected:
                raise ValueError('retained router frame contradicts the independently authored error')


def link_cases(binary, corpus, received):
    cases = []
    for v4 in (True, False):
        family = 'ipv4' if v4 else 'ipv6'
        local = addresses(v4)
        for index, authored in enumerate(corpus['discovery_scenarios']):
            name = authored['id']
            targets = [local[index + 1]] if index < 5 else local[1:3]
            # Routed is the off-link address, not the gateway.
            if index == 4:
                targets = [local[-1]]
            neighbor = index in (0, 1, 2, 4, 5)
            probes = 'neighbor' if index == 5 else ('neighbor,' if neighbor else '') + 'icmp,tcp,udp'
            options = ['--method', 'raw', '--interface', SCANNER, '--link-mode', 'layer2',
                       '--discovery-probes', probes]
            if index != 5:
                options += ['--discovery-ports', '9']
            expected = REASONS[name] | ({'neighbor_reply'} if index in (0, 1) else set())
            case = dict(name=name, family=family, status='failed', runs=[])
            cases.append(case)
            try:
                for mode in MODES:
                    start = len(received)
                    output = run(binary, targets, mode, options, authored['expected']['state'], expected,
                                 possible_proxy=index == 5, sendable=index != 2)
                    output['peer_requests'] = received[start:]
                    case['runs'].append(output)
                    if 'error' in output:
                        # Unsupported means capability admission refused, not a passed discovery.
                        if output['error'].get('code') in ('capability.unsupported', 'capability.route'):
                            case.update(status='unavailable', reason_code='unsupported_capability',
                                        reason=output['error'].get('message', 'selected profile lacks raw discovery'))
                        else:
                            case['error'] = 'native discovery process failed'
                        break
                    if index in (3, 4):
                        validate_router_evidence(measurements.strict_json(output['stdout']), v4, index == 3)
                    if index == 4:
                        for request in output['peer_requests']:
                            if request['kind'] in ('arp', 'ndp') and request['target'] == targets[0]:
                                raise ValueError('routed target was incorrectly solicited as an on-link neighbor')
                else:
                    case['status'] = 'exercised'
            except Exception as error:
                case['error'] = str(error)
    return cases


@contextlib.contextmanager
def socket_peer(family, address):
    """Keep closed ports bound and non-listening, avoiding a close/rebind race."""
    with contextlib.ExitStack() as stack:
        listening = stack.enter_context(measurements.fixture_socket(family, address))
        refused = stack.enter_context(measurements.fixture_socket(family, address))
        listening.listen(32)
        listening.settimeout(0.1)
        stop = threading.Event()
        failures = []

        def accept():
            try:
                while not stop.is_set():
                    try:
                        connection, _ = listening.accept()
                    except socket.timeout:
                        continue
                    connection.close()
            except Exception as error:
                failures.append(str(error))

        worker = threading.Thread(target=accept, daemon=True)
        worker.start()
        try:
            yield listening.getsockname()[1], refused.getsockname()[1]
        finally:
            stop.set()
            worker.join(timeout=2)
        if worker.is_alive() or failures:
            raise RuntimeError('local socket fixture failed or leaked: ' + str(failures))


def socket_cases(binary):
    cases = []
    for family, address, label in ((socket.AF_INET, '127.0.0.1', 'ipv4'), (socket.AF_INET6, '::1', 'ipv6')):
        try:
            with socket_peer(family, address) as ports:
                for name, port, reason in zip(('connect-responsive', 'connect-closed'), ports, ('tcp_connected', 'tcp_refused')):
                    case = dict(name=name, family=label, status='failed', runs=[])
                    cases.append(case)
                    try:
                        for mode in MODES:
                            case['runs'].append(run(binary, [address], mode,
                                ['--connect', '--discovery-probes', 'tcp', '--discovery-ports', str(port)],
                                'responded', {reason}, evidence='socket'))
                        if any('error' in output for output in case['runs']):
                            case['error'] = 'native socket discovery process failed'
                        else:
                            case['status'] = 'exercised'
                    except Exception as error:
                        case['error'] = str(error)
        except measurements.FixtureUnavailable as error:
            cases += [unavailable(name, label, 'unsupported_capability', str(error))
                      for name in ('connect-responsive', 'connect-closed')]
    return cases


@contextlib.contextmanager
def udp_peer(family, address, port):
    with socket.socket(family, socket.SOCK_DGRAM) as peer:
        peer.bind((address, port))
        peer.settimeout(0.1)
        stop, failures = threading.Event(), []

        def respond():
            try:
                received = 0
                while not stop.is_set():
                    try:
                        _, remote = peer.recvfrom(1024)
                    except socket.timeout:
                        continue
                    received += 1
                    if received > 32:
                        raise ValueError('loopback UDP peer exceeds finite request budget')
                    peer.sendto(b'm05', remote)
            except Exception as error:
                failures.append(str(error))

        worker = threading.Thread(target=respond, daemon=True)
        worker.start()
        try:
            yield
        finally:
            stop.set()
            worker.join(timeout=2)
        if worker.is_alive() or failures:
            raise RuntimeError('loopback UDP peer failed or leaked: ' + str(failures))


def host_cases(binary, corpus):
    """Host-local raw paths only; never invent routed or proxy fixtures on a host."""
    cases = []
    for family, address, label in ((socket.AF_INET, '127.0.0.1', 'ipv4'), (socket.AF_INET6, '::1', 'ipv6')):
        try:
            with socket_peer(family, address) as ports, udp_peer(family, address, ports[0]):
                for index, authored in enumerate(corpus['discovery_scenarios']):
                    name = authored['id']
                    if index >= 2:
                        cases.append(unavailable(name, label, 'isolation_unavailable',
                            'Host-local admission forbids interface mutation and remote fixtures; this condition requires disposable link isolation.'))
                        continue
                    case = dict(name=name, family=label, status='failed', runs=[])
                    cases.append(case)
                    probes = 'icmp,tcp,udp' if index == 0 else 'icmp,tcp'
                    expected = REASONS[name] if index == 0 else {'icmp_echo_reply', 'tcp_reset'}
                    try:
                        for mode in MODES:
                            # The scan follows the same reserved TCP port, not an unrelated host service.
                            output = run(binary, [address], mode,
                                ['--method', 'raw', '--link-mode', 'layer3', '--discovery-probes', probes,
                                 '--discovery-ports', str(ports[index])], 'responded', expected,
                                scan_port=ports[index])
                            case['runs'].append(output)
                            if 'error' in output:
                                code = output['error'].get('code')
                                if code in ('capability.unsupported', 'capability.route'):
                                    case.update(status='unavailable', reason_code='unsupported_capability',
                                                reason=output['error'].get('message', code))
                                elif code == 'capability.missing_dependency':
                                    case.update(status='unavailable', reason_code='backend_not_installed',
                                                reason=output['error'].get('message', code))
                                else:
                                    case['error'] = 'host-local raw discovery did not match the fixture'
                                break
                        else:
                            case['status'] = 'exercised'
                    except Exception as error:
                        case['error'] = str(error)
        except measurements.FixtureUnavailable as error:
            cases += [unavailable(authored['id'], label, 'unsupported_capability', str(error))
                      for authored in corpus['discovery_scenarios']]
    return cases
