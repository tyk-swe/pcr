# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Independent, bounded TCP diagnostic wire checks (RFC 9293 §3.10.7 reset generation).

No PacketcraftR codecs or inferred states are used to encode or decode packets.
"""
import ipaddress
import struct
from validation_evidence import checksum


def network(raw, link=101, quoted=False):
    offset = {1: 14, 0: 4, 108: 4, 12: 0, 101: 0, 113: 16, 276: 20}.get(link)
    if offset is None:
        raise ValueError('unsupported evidence link type')
    data = raw[offset:]
    if not data:
        raise ValueError('missing IP packet')
    version = data[0] >> 4
    if version == 4:
        if len(data) < 20:
            raise ValueError('short IPv4 header')
        size = (data[0] & 15) * 4
        length = int.from_bytes(data[2:4], 'big')
        if size < 20 or len(data) < size or length < size or checksum(data[:size]):
            raise ValueError('invalid IPv4 length/checksum')
        if int.from_bytes(data[6:8], 'big') & 0x3fff:
            raise ValueError('fragmented fixture packet')
        source, target = data[12:16], data[16:20]
        proto = data[9]
    elif version == 6:
        if len(data) < 40:
            raise ValueError('short IPv6 header')
        size, length, proto = 40, 40 + int.from_bytes(data[4:6], 'big'), data[6]
        source, target = data[8:24], data[24:40]
    else:
        raise ValueError('unsupported IP packet')
    if not quoted and len(data) < length:
        raise ValueError('truncated IP packet')
    return dict(version=version, source=str(ipaddress.ip_address(source)),
                target=str(ipaddress.ip_address(target)), proto=proto,
                body=data[size:length], wire=data[:length])


def pseudo(ip, length):
    addresses = ipaddress.ip_address(ip['source']).packed + ipaddress.ip_address(ip['target']).packed
    return addresses + (struct.pack('!BBH', 0, ip['proto'], length) if ip['version'] == 4
                        else struct.pack('!I3xB', length, ip['proto']))


def tcp(ip):
    body = ip['body']
    if ip['proto'] != 6 or len(body) < 20 or checksum(pseudo(ip, len(body)) + body):
        raise ValueError('invalid TCP header/checksum')
    source, target, sequence, ack, offset_flags, window, _, _ = struct.unpack('!HHIIHHHH', body[:20])
    size = (offset_flags >> 12) * 4
    if not 20 <= size <= len(body):
        raise ValueError('invalid TCP data offset')
    return dict(source_port=source, port=target, sequence=sequence, ack=ack,
                flags=offset_flags & 0x1ff, window=window, size=size, length=len(body))


def neighbor_request(raw, link, target, source):
    """Recognize only this fixture's outbound Ethernet ARP/NDP preparation."""
    if link != 1 or len(raw) < 14:
        return False
    address = ipaddress.ip_address(target)
    if address.version == 4:
        return (len(raw) >= 42 and raw[12:22] == bytes.fromhex('08060001080006040001')
                and raw[22:28] == raw[6:12] and raw[28:32] == ipaddress.ip_address(source).packed
                and raw[38:42] == address.packed)
    if raw[12:14] != b'\x86\xdd':
        return False
    ip = network(raw, link)
    body = ip['body']
    return (ip['source'] == source and ip['proto'] == 58 and ip['wire'][7] == 255
            and len(body) >= 24 and body[:2] == b'\x87\x00' and body[8:24] == address.packed
            and checksum(pseudo(ip, len(body)) + body) == 0)


def outgoing(raw, link, mode, flags, sequence, target, port):
    ip = network(raw, link)
    segment = tcp(ip)
    ack = (sequence + 0x50435201) & 0xffffffff if flags & 16 else 0
    if (ip['target'] != target or segment['port'] != port or segment['flags'] != flags or
            segment['sequence'] != sequence & 0xffffffff or segment['ack'] != ack or
            segment['size'] != 20 or segment['length'] != 20):
        raise ValueError('outgoing diagnostic endpoint/flags/identity/options/payload mismatch')
    return ip, segment


def response(raw, link, target, port, sequence, flags, sent=None):
    ip = network(raw, link)
    window = None
    if ip['proto'] == 6:
        segment = tcp(ip)
        if ip['source'] != target or segment['source_port'] != port:
            raise ValueError('TCP reply endpoint mismatch')
        if sent and (ip['target'] != sent[0]['source'] or segment['port'] != sent[1]['source_port']):
            raise ValueError('TCP reply local endpoint mismatch')
        consumed = bool(flags & 1) + bool(flags & 2)
        if segment['flags'] & 4 and flags & 16:
            if segment['flags'] != 4 or segment['sequence'] != (sequence + 0x50435201) & 0xffffffff:
                raise ValueError('bare reset identity mismatch')
        elif not segment['flags'] & 16 or segment['ack'] != (sequence + consumed) & 0xffffffff:
            raise ValueError('TCP acknowledgment mismatch')
        window = segment['window']
        reply = ('tcp_reset' if segment['flags'] & 4 else
                 'tcp_syn_ack' if segment['flags'] & 18 == 18 else 'tcp_other')
    elif ip['proto'] in (1, 58):
        body = ip['body']
        if len(body) < 8 or checksum((pseudo(ip, len(body)) if ip['proto'] == 58 else b'') + body):
            raise ValueError('invalid ICMP checksum/length')
        kind, code = body[:2]
        quote = network(body[8:], quoted=True)
        if quote['target'] != target or quote['proto'] != 6 or len(quote['body']) < 8:
            raise ValueError('ICMP quote endpoint mismatch')
        _, quoted_port, identity = struct.unpack('!HHI', quote['body'][:8])
        if quoted_port != port or identity != sequence & 0xffffffff:
            raise ValueError('ICMP quote identity mismatch')
        if sent and (quote['source'] != sent[0]['source'] or quote['wire'] != sent[0]['wire'][:len(quote['wire'])]):
            raise ValueError('ICMP quote bytes mismatch')
        if (ip['proto'], kind) in ((1, 11), (58, 3)):
            reply = 'icmp_time_exceeded'
        elif (ip['proto'], kind) in ((1, 3), (58, 1)):
            reply = ('icmp_administratively_prohibited' if (ip['proto'], code) in ((1, 9), (1, 10), (1, 13), (58, 1))
                     else 'icmp_destination_unreachable')
        else:
            raise ValueError('unrelated ICMP response')
    else:
        raise ValueError('unrelated response protocol')
    return reply, window
