# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded independent libpcap watcher for explicitly provisioned kernel fixtures."""
import contextlib
import ctypes as c
import ctypes.util
import os
from pathlib import Path
import platform
import threading
import time


class Timeval(c.Structure):
    _fields_ = [('seconds', c.c_long), ('microseconds', c.c_long)]


class Header(c.Structure):
    _fields_ = [('time', Timeval), ('captured_length', c.c_uint32), ('original_length', c.c_uint32)]


class Statistics(c.Structure):
    # Extra storage accommodates Windows extensions after the portable counters.
    _fields_ = [(name, c.c_uint) for name in (
        "received", "dropped", "interface_dropped", "captured", "sent", "network_dropped")]


class Program(c.Structure):
    _fields_ = [('length', c.c_uint), ('instructions', c.c_void_p)]


class Device(c.Structure):
    pass


Device._fields_ = [('next', c.POINTER(Device)), ('name', c.c_char_p), ('description', c.c_char_p),
                  ('addresses', c.c_void_p), ('flags', c.c_uint)]


def library():
    path = ctypes.util.find_library('pcap')
    if platform.system() == 'Windows':
        root = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32'
        path = next((str(item) for item in (root / 'Npcap/wpcap.dll', root / 'wpcap.dll') if item.is_file()), None)
    if not path:
        raise OSError('existing libpcap/Npcap backend not installed')
    if platform.system() == 'Windows':
        with os.add_dll_directory(str(Path(path).parent)):
            lib = c.CDLL(path)
    else:
        lib = c.CDLL(path)
    signatures = {
        'pcap_open_live': (c.c_void_p, [c.c_char_p, c.c_int, c.c_int, c.c_int, c.c_char_p]),
        'pcap_close': (None, [c.c_void_p]), 'pcap_datalink': (c.c_int, [c.c_void_p]),
        'pcap_setnonblock': (c.c_int, [c.c_void_p, c.c_int, c.c_char_p]),
        'pcap_compile': (c.c_int, [c.c_void_p, c.POINTER(Program), c.c_char_p, c.c_int, c.c_uint32]),
        'pcap_setfilter': (c.c_int, [c.c_void_p, c.POINTER(Program)]),
        'pcap_freecode': (None, [c.POINTER(Program)]),
        'pcap_next_ex': (c.c_int, [c.c_void_p, c.POINTER(c.POINTER(Header)), c.POINTER(c.POINTER(c.c_ubyte))]),
        'pcap_findalldevs': (c.c_int, [c.POINTER(c.POINTER(Device)), c.c_char_p]),
        'pcap_freealldevs': (None, [c.POINTER(Device)]), 'pcap_geterr': (c.c_char_p, [c.c_void_p]),
        'pcap_lib_version': (c.c_char_p, []),
        'pcap_stats': (c.c_int, [c.c_void_p, c.POINTER(Statistics)])}
    for name, (result, args) in signatures.items():
        getattr(lib, name).restype = result
        getattr(lib, name).argtypes = args
    return lib


def loopback(lib):
    if platform.system() == 'Darwin':
        return 'lo0'
    if platform.system() == 'Linux':
        return 'lo'
    devices, error = c.POINTER(Device)(), c.create_string_buffer(256)
    if lib.pcap_findalldevs(c.byref(devices), error):
        raise OSError(error.value.decode(errors='replace'))
    try:
        candidates, current = [], devices
        while current:
            item = current.contents
            text = (item.name or b'') + b' ' + (item.description or b'')
            if item.flags & 1 or b'loopback' in text.lower():
                candidates.append(item.name.decode())
            current = item.next
        if len(candidates) != 1:
            raise OSError('existing capture backend lacks one unambiguous loopback interface')
        return candidates[0]
    finally:
        lib.pcap_freealldevs(devices)


@contextlib.contextmanager
def provision(targets, device=None):
    lib = library()
    device = device or loopback(lib)
    error = c.create_string_buffer(256)
    handle = lib.pcap_open_live(device.encode(), 2048, 0, 10, error)
    if not handle:
        raise OSError(error.value.decode(errors='replace'))
    worker, errors = None, []
    stop = threading.Event()
    expression = 'tcp and (host ' + targets[0] + ' or host ' + targets[1] + ') and (port 43123 or port 43125)'
    report = dict(device=device, filter=expression, link_type=lib.pcap_datalink(handle), frames=[],
                  backend_version=lib.pcap_lib_version().decode(errors='replace'), cleanup_complete=False)
    try:
        program = Program()
        if lib.pcap_compile(handle, c.byref(program), expression.encode(), 1, 0xffffffff):
            raise OSError(lib.pcap_geterr(handle).decode(errors='replace'))
        try:
            if lib.pcap_setfilter(handle, c.byref(program)) or lib.pcap_setnonblock(handle, 1, error):
                raise OSError('independent capture filter/nonblocking setup failed')
        finally:
            lib.pcap_freecode(c.byref(program))

        def capture():
            charged = 0
            try:
                header, packet = c.POINTER(Header)(), c.POINTER(c.c_ubyte)()
                while True:
                    result = lib.pcap_next_ex(handle, c.byref(header), c.byref(packet))
                    if result == 1:
                        item = header.contents
                        charged += item.captured_length
                        if item.captured_length != item.original_length or item.captured_length > 2048 or charged > 1048576 or len(report['frames']) >= 4096:
                            raise ValueError('independent kernel capture retention ceiling/truncation')
                        report['frames'].append(dict(bytes_hex=c.string_at(packet, item.captured_length).hex(),
                            link_type=report['link_type'], unix_ns=item.time.seconds * 1000000000 + item.time.microseconds * 1000,
                            monotonic_ingress_ns=time.monotonic_ns()))
                    elif result < 0:
                        raise OSError('independent capture stopped: ' + lib.pcap_geterr(handle).decode(errors='replace'))
                    elif stop.is_set():
                        break
                    else:
                        stop.wait(0.01)
            except Exception as error:
                errors.append(str(error))
        worker = threading.Thread(target=capture, daemon=True)
        worker.start()
        yield report
    finally:
        stop.set()
        if worker:
            worker.join(timeout=2)
            if worker.is_alive():
                raise RuntimeError('independent capture failed bounded cleanup')
        stats = Statistics()
        if lib.pcap_stats(handle, c.byref(stats)):
            errors.append('independent capture statistics unavailable')
        else:
            report['statistics'] = dict(received=stats.received, dropped=stats.dropped,
                                        interface_dropped=stats.interface_dropped)
            if stats.dropped or stats.interface_dropped:
                errors.append('independent capture loss prevents completeness')
        lib.pcap_close(handle)
        report['cleanup_complete'] = True
        if errors:
            raise RuntimeError('; '.join(errors))
