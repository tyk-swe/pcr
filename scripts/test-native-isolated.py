#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Opt-in Linux native exchange test in a new network namespace containing only lo."""
import argparse
import json
import os
import pathlib
import platform
import socket
import subprocess
import sys
import threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', type=pathlib.Path, required=True)
parser.add_argument('--report', type=pathlib.Path, default=ROOT / 'target/native-isolated.json')
parser.add_argument('--parent-namespace', type=int, help=argparse.SUPPRESS)
args = parser.parse_args()
binary = args.binary.resolve()
report_path = args.report.resolve()
if platform.system() != 'Linux':
    raise SystemExit('this isolated suite requires Linux network namespaces')
namespace = os.stat('/proc/self/ns/net').st_ino
if args.parent_namespace is None:
    result = subprocess.run(['unshare', '--user', '--map-root-user', '--net', sys.executable,
                             str(pathlib.Path(__file__).resolve()), '--binary', str(binary),
                             '--report', str(report_path), '--parent-namespace', str(namespace)])
    raise SystemExit(result.returncode)
interfaces = {link['ifname'] for link in json.loads(subprocess.check_output(['ip', '-j', 'link', 'show'], text=True))}
if namespace == args.parent_namespace or interfaces != {'lo'}:
    raise SystemExit('refusing native test outside a new, loopback-only network namespace')
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
    server.bind(('127.0.0.1', 0))
    receiver.bind(('127.0.0.1', 0))
    server.settimeout(5)
    source_port, destination_port = receiver.getsockname()[1], server.getsockname()[1]
    messages = []
    def reply():
        data, address = server.recvfrom(1024)
        messages.append(data.hex())
        server.sendto(b'isolated-reply', address)
    worker = threading.Thread(target=reply, daemon=True)
    worker.start()
    command = [str(binary), '--output', 'ndjson', 'exchange', '--interface', 'lo', '--link-mode', 'layer3',
               '--timeout-ms', '1000', '--max-packets', '1', '--max-bytes', '1024',
               '--max-queue-frames', '64', '--max-captured-bytes', '65536', '--snap-length', '2048', '--max-responses', '1',
               '--packet', f'ipv4(dst=127.0.0.1)/udp(sport={source_port},dport={destination_port})/raw(text=isolated-probe)']
    output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    worker.join(timeout=5)
report = dict(os=platform.platform(), version=subprocess.check_output([binary, '--version'], text=True),
              parent_namespace=args.parent_namespace, namespace=namespace,
              command=command, exit_code=output.returncode, stdout=output.stdout.decode(),
              stderr=output.stderr.decode(), received_messages=messages)
report_path.parent.mkdir(parents=True, exist_ok=True)
report_path.write_text(json.dumps(report, indent=2) + '\n')
assert output.returncode == 0, report
records = [json.loads(line) for line in output.stdout.splitlines()]
assert records[-1]['event'] == 'complete', report
assert [record['sequence'] for record in records] == list(range(len(records))), report
assert messages == [b'isolated-probe'.hex()], report
assert b'isolated-reply'.hex() in output.stdout.decode(), report
assert next(index for index, record in enumerate(records) if record['event'] == 'sent') < len(records) - 1
print(report_path)
