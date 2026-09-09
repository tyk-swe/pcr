#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Check domain dependency direction from Cargo metadata, not source layout."""
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
ALLOWED = {
    'packetcraftr-core': set(),
    'packetcraftr-netio': {'packetcraftr-core'},
    'packetcraftr': {'packetcraftr-core', 'packetcraftr-netio'},
    'packetcraftr-cli': {'packetcraftr-core', 'packetcraftr-netio', 'packetcraftr'},
}
NATIVE = {'pcap', 'socket2', 'tokio', 'windows', 'libc', 'libloading', 'rtnetlink'}


def validate(metadata):
    errors = []
    members = set(metadata['workspace_members'])
    for package in metadata['packages']:
        if package['id'] not in members:
            continue
        name = package['name']
        if name not in ALLOWED:
            errors.append(f'unclassified workspace crate: {name}')
            continue
        for dependency in package['dependencies']:
            # Tests may depend on peers, but production and build dependencies
            # must preserve direction, including optional/target-specific ones.
            if dependency['kind'] == 'dev':
                continue
            child = dependency['name']
            if child in ALLOWED and child not in ALLOWED[name]:
                errors.append(f'{name} must not depend on {child}')
            if name == 'packetcraftr-core' and child in NATIVE:
                errors.append(f'portable core must not depend on native/runtime crate {child}')
    return errors


if __name__ == '__main__':
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1'], cwd=ROOT))
    errors = validate(metadata)
    if errors:
        raise SystemExit('\n'.join(errors))
    print('Four-crate dependency direction verified')
