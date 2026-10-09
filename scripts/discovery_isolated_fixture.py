# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Independent immediate-reply Ethernet peer, admitted only in a fresh Linux netns."""
import contextlib
import ipaddress
import socket
import struct
import subprocess
import threading

SCANNER = 'pcrm5s'
PEER = 'pcrm5p'


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def ip(*arguments):
    subprocess.run(['ip', *arguments], check=True, capture_output=True, timeout=10)


def addresses(v4):
    return (['192.0.2.' + str(last) for last in (1, 2, 3, 4, 5, 254)] + ['198.51.100.2'] if v4 else
            ['2001:db8::' + last for last in ('1', '2', '3', '4', '5', 'ffff')] + ['2001:db8:1::2'])


def packet(source, destination, protocol, body):
    source, destination = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    if source.version == 4:
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 1, 0, 64, protocol, 0,
                             source.packed, destination.packed)
        return header[:10] + struct.pack('!H', checksum(header)) + header[12:] + body
    return struct.pack('!IHBB16s16s', 6 << 28, len(body), protocol, 255 if protocol == 58 else 64,
                       source.packed, destination.packed) + body


def transport(source, destination, protocol, body, offset):
    source, destination = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    if protocol == 1:
        pseudo = b''
    elif source.version == 4:
        pseudo = source.packed + destination.packed + struct.pack('!BBH', 0, protocol, len(body))
    else:
        pseudo = source.packed + destination.packed + struct.pack('!I3xB', len(body), protocol)
    value = checksum(pseudo + body)
    if protocol == 17 and value == 0:
        value = 0xffff
    return body[:offset] + struct.pack('!H', value) + body[offset + 2:]


def reply(frame, mac, received):
    """No PacketcraftR encoders or output-derived expectations are used."""
    if len(frame) < 14:
        return None
    ether_type = int.from_bytes(frame[12:14], 'big')
    ipv4, ipv6 = addresses(True), addresses(False)
    if ether_type == 0x0806:
        if len(frame) < 42 or frame[14:22] != bytes.fromhex('0001080006040001'):
            return None
        target = str(ipaddress.ip_address(frame[38:42]))
        if target not in ipv4[1:] or target in (ipv4[3], ipv4[-1]):
            return None
        received.append(dict(kind='arp', target=target, frame=frame.hex()))
        body = bytes.fromhex('0001080006040002') + mac + frame[38:42] + frame[22:32]
        return frame[6:12] + mac + frame[12:14] + body
    if ether_type == 0x0800:
        if len(frame) < 34 or frame[14] != 0x45:
            return None
        wire = frame[14:14 + int.from_bytes(frame[16:18], 'big')]
        if len(wire) < 20 or checksum(wire[:20]) != 0:
            raise ValueError('scanner IPv4 header lacks independent checksum integrity')
        protocol, source, target, body = wire[9], wire[12:16], wire[16:20], wire[20:]
    elif ether_type == 0x86dd:
        if len(frame) < 54 or frame[14] >> 4 != 6:
            return None
        wire = frame[14:54 + int.from_bytes(frame[18:20], 'big')]
        protocol, source, target, body = wire[6], wire[8:24], wire[24:40], wire[40:]
        if protocol == 58 and len(body) >= 24 and body[0] == 135:
            target = body[8:24]
            address = str(ipaddress.ip_address(target))
            if address not in ipv6[1:] or address in (ipv6[3], ipv6[-1]):
                return None
            received.append(dict(kind='ndp', target=address, frame=frame.hex()))
            advertisement = struct.pack('!BBHI', 136, 0, 0, 0x60000000) + target + bytes((2, 1)) + mac
            advertisement = transport(target, source, 58, advertisement, 2)
            return frame[6:12] + mac + frame[12:14] + packet(target, source, 58, advertisement)
    else:
        return None
    source, target = str(ipaddress.ip_address(source)), str(ipaddress.ip_address(target))
    family = ipv4 if ether_type == 0x0800 else ipv6
    if target not in family[1:] or target == family[3]:
        return None
    if protocol not in (1, 6, 17, 58):
        return None
    if (protocol in (1, 58) and (len(body) < 8 or body[0] not in (8, 128))) or \
            (protocol == 6 and (len(body) < 20 or body[13] & 0x12 != 2)) or \
            (protocol == 17 and len(body) < 8):
        return None
    received.append(dict(kind={1: 'icmp', 58: 'icmp', 6: 'tcp', 17: 'udp'}[protocol],
                         target=target, frame=frame.hex()))
    v4, closed = ether_type == 0x0800, target == family[2]
    if target in (family[4], family[-1]) or (closed and protocol == 17):
        blocked = target == family[4]
        sender = target if closed else family[5]
        code = (13 if v4 else 1) if blocked else ((3 if v4 else 4) if closed else (1 if v4 else 3))
        response = struct.pack('!BBHI', 3 if v4 else 1, code, 0, 0) + wire
        protocol = 1 if v4 else 58
    elif protocol in (1, 58):
        sender, response = target, bytes((0 if v4 else 129,)) + body[1:2] + b'\0\0' + body[4:]
    elif protocol == 6:
        sport, dport, sequence = struct.unpack('!HHI', body[:8])
        sender = target
        response = struct.pack('!HHIIBBHHH', dport, sport, 0x1000, (sequence + 1) & 0xffffffff,
                               0x50, 0x14 if closed else 0x12, 65535, 0, 0)
    else:
        sport, dport = struct.unpack('!HH', body[:4])
        sender, response = target, struct.pack('!HHHH', dport, sport, 8, 0)
    response = transport(sender, source, protocol, response, 16 if protocol == 6 else (6 if protocol == 17 else 2))
    return frame[6:12] + mac + frame[12:14] + packet(sender, source, protocol, response)


@contextlib.contextmanager
def provision():
    ip('link', 'set', 'lo', 'up')
    ip('link', 'add', SCANNER, 'type', 'veth', 'peer', 'name', PEER)
    received, failures = [], []
    stop, ready = threading.Event(), threading.Event()

    def respond():
        try:
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as raw:
                raw.bind((PEER, 0))
                raw.settimeout(0.1)
                mac = raw.getsockname()[4]
                ready.set()
                while not stop.is_set():
                    try:
                        frame, (_, _, kind, _, _) = raw.recvfrom(4096)
                    except socket.timeout:
                        continue
                    if len(received) >= 256:
                        raise ValueError('independent peer exceeds its finite request budget')
                    if kind != socket.PACKET_OUTGOING:
                        response = reply(frame, mac, received)
                        if response is not None:
                            raw.send(response)
        except Exception as error:
            failures.append(str(error))
            ready.set()

    worker = None
    try:
        for interface in (SCANNER, PEER):
            ip('link', 'set', interface, 'up')
        ip('address', 'add', '192.0.2.1/24', 'dev', SCANNER)
        ip('-6', 'address', 'add', '2001:db8::1/64', 'dev', SCANNER, 'nodad')
        ip('route', 'add', '198.51.100.0/24', 'via', '192.0.2.254', 'dev', SCANNER)
        ip('-6', 'route', 'add', '2001:db8:1::/64', 'via', '2001:db8::ffff', 'dev', SCANNER)
        worker = threading.Thread(target=respond, daemon=True)
        worker.start()
        if not ready.wait(2) or failures:
            raise RuntimeError('independent discovery peer failed readiness: ' + str(failures))
        yield received
    finally:
        stop.set()
        if worker is not None:
            worker.join(timeout=2)
        ip('link', 'delete', SCANNER)
    if failures or (worker is not None and worker.is_alive()):
        raise RuntimeError('independent discovery peer failed or leaked: ' + str(failures))
