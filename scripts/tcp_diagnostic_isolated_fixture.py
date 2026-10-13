# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Immediate independent M12 replies; unassigned peer IPs cannot use kernel truth."""
import contextlib
import json
import socket
import struct
import subprocess
import threading
import time
from discovery_isolated_fixture import packet, transport
from tcp_diagnostic_wire import network, tcp

SCANNER, PEER = 'pcrm12s', 'pcrm12p'
SOURCES = {'ipv4': '192.0.2.1', 'ipv6': '2001:db8::1'}
TARGETS = {'ipv4': '192.0.2.2', 'ipv6': '2001:db8::2'}


def reply(wire):
    ip = network(wire, 1)
    family = 'ipv4' if ip['version'] == 4 else 'ipv6'
    if ip['source'] != SOURCES[family] or ip['target'] != TARGETS[family] or ip['proto'] != 6:
        return []
    probe = tcp(ip)
    port, flags = probe['port'], probe['flags']
    if flags & 4:
        return []  # Never answer kernel-generated resets.
    if not 1000 <= port <= 1007:
        raise ValueError('fixture received an unapproved TCP port')
    envelope = wire[6:12] + wire[:6] + wire[12:14]
    source, target = ip['target'], ip['source']

    def segment(response_flags, window):
        sequence = probe['ack'] if response_flags == 4 else 100 if response_flags == 18 else 0
        ack = 0 if response_flags == 4 else (probe['sequence'] + bool(flags & 1) + bool(flags & 2)) & 0xffffffff
        body = struct.pack('!HHIIHHHH', port, probe['source_port'], sequence, ack,
                           0x5000 | response_flags, window, 0, 0)
        body = transport(source, target, 6, body, 16)
        return envelope + packet(source, target, 6, body)

    def error(expired=False, port_error=False):
        if ip['version'] == 4:
            kind, code, protocol = (11, 0, 1) if expired else (3, 3 if port_error else 13, 1)
            quoted = ip['wire'][:28]
        else:
            kind, code, protocol = (3, 0, 58) if expired else (1, 4 if port_error else 1, 58)
            quoted = ip['wire'][:48]
        body = struct.pack('!BBHI', kind, code, 0, 0) + quoted
        body = transport(source, target, protocol, body, 2)
        return envelope + packet(source, target, protocol, body)

    reset_flags = 4 if flags & 16 else 20
    if port in (1000, 1001):
        return [segment(reset_flags, 0 if port == 1000 else 4096)]
    if port == 1002:
        return []
    if port == 1003:
        return [error()]
    if port == 1004:
        return [segment(18, 29200)]
    if port == 1005:
        return [segment(reset_flags, 4096), error()]
    return [error(expired=port == 1007, port_error=port == 1006)]


def command(*args):
    result = subprocess.run(args, check=True, capture_output=True, text=True, timeout=15)
    return dict(command=list(args), stdout=result.stdout, stderr=result.stderr, exit_code=result.returncode)


@contextlib.contextmanager
def provision(evidence=None):
    if evidence is None:
        evidence = dict(requests=[], setup=[])
    stop, ready = threading.Event(), threading.Event()
    errors, worker = [], None
    created = False
    try:
        evidence['setup'].append(command('ip', 'link', 'set', 'lo', 'up'))
        evidence['setup'].append(command('ip', 'link', 'add', SCANNER, 'type', 'veth', 'peer', 'name', PEER))
        created = True
        for device in (SCANNER, PEER):
            evidence['setup'].append(command('ip', 'link', 'set', device, 'up'))
            evidence['setup'].append(command('ethtool', '-K', device, 'tx', 'off', 'rx', 'off',
                                             'tso', 'off', 'gso', 'off', 'gro', 'off'))
            evidence['setup'].append(command('ethtool', '-k', device))
        link = command('ip', '-j', 'link', 'show', 'dev', PEER)
        evidence['setup'].append(link)
        mac = json.loads(link['stdout'])[0]['address']
        for family in ('ipv4', 'ipv6'):
            version = [] if family == 'ipv4' else ['-6']
            evidence['setup'].append(command('ip', *version, 'address', 'add', SOURCES[family] +
                                             ('/24' if family == 'ipv4' else '/64'), 'dev', SCANNER,
                                             *([] if family == 'ipv4' else ['nodad'])))
            evidence['setup'].append(command('ip', *version, 'neigh', 'replace', TARGETS[family],
                                             'lladdr', mac, 'nud', 'permanent', 'dev', SCANNER))

        def serve():
            charged = 0
            try:
                with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as channel:
                    channel.bind((PEER, 0))
                    channel.settimeout(0.1)
                    ready.set()
                    while not stop.is_set():
                        try:
                            wire, address = channel.recvfrom(2048)
                        except socket.timeout:
                            continue
                        if address[2] == socket.PACKET_OUTGOING or len(wire) < 14 or wire[12:14] not in (b'\x08\x00', b'\x86\xdd'):
                            continue
                        ip = network(wire, 1)
                        if ip['proto'] != 6 or ip['target'] not in TARGETS.values():
                            continue
                        if tcp(ip)['flags'] & 4:
                            continue
                        answers = reply(wire)
                        charged += len(wire) + sum(map(len, answers))
                        if len(wire) > 2048 or any(len(answer) > 2048 for answer in answers) or charged > 1048576:
                            raise ValueError('independent scripted peer exceeded its byte/snap ceiling')
                        if len(evidence['requests']) >= 4096:
                            raise ValueError('independent peer request ceiling exceeded')
                        entry = dict(bytes_hex=wire.hex(), link_type=1, unix_ns=time.time_ns(),
                                     monotonic_ns=time.monotonic_ns(), replies=[])
                        evidence['requests'].append(entry)
                        for answer in answers:
                            channel.send(answer)
                            entry['replies'].append(dict(bytes_hex=answer.hex(), link_type=1,
                                                         unix_ns=time.time_ns(), monotonic_ns=time.monotonic_ns()))
            except Exception as error:
                errors.append(str(error))
                ready.set()
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        if not ready.wait(2) or errors:
            raise RuntimeError('independent M12 peer did not become ready: ' + '; '.join(errors))
        yield evidence
    except Exception as error:
        evidence['error'] = str(error)
        if hasattr(error, 'stdout'):
            evidence['failed_command'] = dict(command=error.cmd, stdout=str(error.stdout or '')[:1048576],
                                               stderr=str(error.stderr or '')[:1048576],
                                               exit_code=getattr(error, 'returncode', None))
        raise
    finally:
        stop.set()
        if worker:
            worker.join(timeout=2)
            if worker.is_alive():
                errors.append('independent peer failed bounded cleanup')
        if created:
            evidence['cleanup'] = command('ip', 'link', 'delete', SCANNER)
        if errors:
            raise RuntimeError('; '.join(errors))
