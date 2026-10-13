# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Independent M13 wire peer on the existing isolated documentation-address link."""
import struct
from discovery_isolated_fixture import packet, transport
from tcp_diagnostic_isolated_fixture import provision as link_provision, SOURCES, TARGETS
from tcp_diagnostic_wire import network


def crc32c(data):
    value = 0xffffffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
    return value ^ 0xffffffff


def sctp(body):
    return body[:8] + struct.pack('<I', crc32c(body[:8] + b'\0' * 4 + body[12:])) + body[12:]


def accepts(ip):
    family = 'ipv4' if ip['version'] == 4 else 'ipv6'
    return (ip['source'] == SOURCES[family] and ip['target'] == TARGETS[family]
            and ip['proto'] in (132, 47, 50, 112, 115, 254)
            and (ip['proto'] != 132 or len(ip['body']) >= 16 and ip['body'][12] in (1, 10)))


def request(ip):
    if not accepts(ip):
        raise ValueError('request outside the isolated M13 endpoint inventory')
    body = ip['body']
    if ip['proto'] != 132:
        if body:
            raise ValueError('IP-protocol inventory must send an empty payload')
        return ip['proto'], None
    if len(body) not in (20, 32) or sctp(body) != body:
        raise ValueError('invalid SCTP request length/checksum')
    _, port, tag = struct.unpack('!HHI', body[:8])
    if port not in range(2000, 2006):
        raise ValueError('unapproved SCTP fixture port')
    if body[12:16] == bytes.fromhex('01000014') and len(body) == 32 and tag == 0:
        tag = int.from_bytes(body[16:20], 'big')
        if (not tag or body[20:28] != bytes.fromhex('00010000000a000a')
                or body[28:32] != body[16:20]):
            raise ValueError('invalid SCTP INIT body')
    elif body[12:16] == bytes.fromhex('0a000008') and len(body) == 20 and tag:
        if body[16:20] != body[4:8]:
            raise ValueError('COOKIE-ECHO payload/tag mismatch')
    else:
        raise ValueError('invalid SCTP probe chunk')
    return port, tag


def reply(wire):
    ip = network(wire, 1)
    endpoint, tag = request(ip)
    source, target = ip['target'], ip['source']
    envelope = wire[6:12] + wire[:6] + wire[12:14]

    def error(kind):
        v4 = ip['version'] == 4
        protocol = 1 if v4 else 58
        types = {'prohibited': (3, 13) if v4 else (1, 1),
                 'expired': (11, 0) if v4 else (3, 0),
                 'unsupported': (3, 2) if v4 else (4, 1)}
        pointer = 6 if not v4 and kind == 'unsupported' else 0
        body = struct.pack('!BBHI', *types[kind], 0, pointer) + ip['wire']
        return envelope + packet(source, target, protocol, transport(source, target, protocol, body, 2))

    if ip['proto'] == 132:
        if endpoint == 2005:
            return []
        if endpoint in (2003, 2004):
            return [error('prohibited' if endpoint == 2003 else 'expired')]
        if endpoint == 2000:
            chunk = struct.pack('!BBHIIHHI', 2, 0, 20, 0x12345678, 65536, 10, 10, 1)
        else:
            chunk = struct.pack('!BBH', 6 if endpoint == 2001 else 11, 0, 4)
        sport = int.from_bytes(ip['body'][:2], 'big')
        body = sctp(struct.pack('!HHII', endpoint, sport, tag, 0) + chunk)
        return [envelope + packet(source, target, 132, body)]
    if endpoint == 47:
        return [envelope + packet(source, target, 47, b'')]
    if endpoint == 254:
        return []
    return [error({50: 'unsupported', 112: 'prohibited', 115: 'expired'}[endpoint])]


def provision(evidence):
    return link_provision(evidence, responder=reply, accepts=accepts)


def outgoing(raw, link, case, sequence, endpoint):
    ip = network(raw, link)
    observed, tag = request(ip)
    if observed != endpoint or ip['target'] != TARGETS[case['family']]:
        raise ValueError('outgoing fixture endpoint/family mismatch')
    if case['scenario'] == 'ip-protocol':
        identity = (int.from_bytes(ip['wire'][4:6], 'big') if ip['version'] == 4
                    else int.from_bytes(ip['wire'][:4], 'big') & 0xfffff)
        expected = (sequence % 65535 + 1) if ip['version'] == 4 else sequence % 1048576
        if identity != expected:
            raise ValueError('outgoing IP-protocol sequence mismatch')
    else:
        expected = ((sequence + 0x50435231) & 0xffffffff) or 1
        chunk = 1 if case['scenario'] == 'sctp-init' else 10
        if tag != expected or ip['body'][12] != chunk:
            raise ValueError('outgoing SCTP sequence/mode mismatch')
    return ip
