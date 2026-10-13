# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Real Linux kernel peer in a second disposable network namespace."""
import contextlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import time
from tcp_diagnostic_isolated_fixture import command

SCANNER, PEER = 'pcrm12ks', 'pcrm12kp'
SOURCES = ('198.51.100.1', '2001:db8:1::1')
TARGETS = ('198.51.100.2', '2001:db8:1::2')


def serve(parent):
    current = os.stat('/proc/self/ns/net').st_ino
    if current == parent or sorted(item['ifname'] for item in json.loads(subprocess.check_output(['ip', '-j', 'link'], text=True, timeout=15))) != ['lo']:
        raise ValueError('kernel peer requires a fresh parent-distinct namespace')
    owned = []
    try:
        for family, target in ((socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')):
            for port, listen in ((43123, True), (43125, False)):
                channel = socket.socket(family, socket.SOCK_STREAM)
                owned.append(channel)
                if family == socket.AF_INET6:
                    channel.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                channel.bind((target, port))
                if listen:
                    channel.listen(128)
        print(json.dumps(dict(netns_inode=current, parent_netns_inode=parent,
                              listening_port=43123, reserved_non_listening_port=43125)), flush=True)
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            time.sleep(0.2)
        raise TimeoutError('kernel peer finite lifetime expired')
    finally:
        for channel in owned:
            channel.close()


@contextlib.contextmanager
def provision(profile):
    args = ['unshare', '--net', '--', sys.executable, str(Path(__file__).resolve()),
            '--peer', str(os.stat('/proc/self/ns/net').st_ino)]
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    created = False
    fixture = dict(command=args, setup=[])
    profile['kernel_peer'] = fixture
    try:
        if not select.select([process.stdout], [], [], 10)[0]:
            raise RuntimeError('kernel peer readiness deadline exceeded')
        ready = process.stdout.readline(4096)
        fixture['readiness_stdout'] = ready
        fixture['ready'] = json.loads(ready)
        parent, child = fixture['ready']['parent_netns_inode'], fixture['ready']['netns_inode']
        if parent != os.stat('/proc/self/ns/net').st_ino or child == parent or child != os.stat(f'/proc/{process.pid}/ns/net').st_ino:
            raise ValueError('kernel peer namespace identity mismatch')
        fixture['setup'].append(command('ip', 'link', 'add', SCANNER, 'type', 'veth', 'peer', 'name', PEER))
        created = True
        fixture['setup'].append(command('ip', 'link', 'set', PEER, 'netns', str(process.pid)))
        for prefix, device, targets in (([], SCANNER, SOURCES),
                                        (['nsenter', '-t', str(process.pid), '-n'], PEER, TARGETS)):
            fixture['setup'].append(command(*prefix, 'ip', 'link', 'set', 'lo', 'up'))
            fixture['setup'].append(command(*prefix, 'ip', 'link', 'set', device, 'up'))
            fixture['setup'].append(command(*prefix, 'ip', 'addr', 'add', targets[0] + '/24', 'dev', device))
            fixture['setup'].append(command(*prefix, 'ip', '-6', 'addr', 'add', targets[1] + '/64', 'dev', device, 'nodad'))
            fixture['setup'].append(command(*prefix, 'ethtool', '-K', device, 'tx', 'off', 'rx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off'))
            fixture['setup'].append(command(*prefix, 'ethtool', '-k', device))
        profile['kernel_fixture'] = {family: dict(target=target, listening_port=43123,
            reserved_non_listening_port=43125, syn_control_required=True) for family, target in zip(('ipv4', 'ipv6'), TARGETS)}
        yield profile['kernel_fixture']
        if process.poll() is not None:
            raise RuntimeError('kernel peer stopped before all cases completed')
    except Exception as error:
        fixture['error'] = str(error)
        if hasattr(error, 'stdout'):
            fixture['failed_command'] = dict(command=error.cmd, stdout=str(error.stdout or '')[:1048576],
                                             stderr=str(error.stderr or '')[:1048576],
                                             exit_code=getattr(error, 'returncode', None))
        raise
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
            fixture['cleanup_failed'] = True
        fixture['stdout'], fixture['stderr'], fixture['exit_code'] = stdout[:1048576], stderr[:1048576], process.returncode
        if created:
            fixture['cleanup'] = command('ip', 'link', 'delete', SCANNER)
        profile['kernel_cleanup'] = 'sockets_closed'
        if fixture.get('cleanup_failed'):
            raise RuntimeError('kernel peer failed bounded cleanup')


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != '--peer':
        raise SystemExit('internal isolated kernel peer only')
    serve(int(sys.argv[2]))
