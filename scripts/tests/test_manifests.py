# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import tomllib
import unittest
from pathlib import Path

from support import ROOT

def discover_crates():
    crates = {}
    for manifest in sorted((ROOT / 'crates').glob('*/Cargo.toml')):
        with manifest.open('rb') as stream:
            name = tomllib.load(stream)['package']['name']
        crates[name] = str(manifest.relative_to(ROOT))
    return crates


CRATES = discover_crates()

NATIVE_FEATURES = ('native-route', 'native-layer2', 'native-layer3')


def read_manifest(root, relative):
    with (root / relative).open('rb') as stream:
        return tomllib.load(stream)


def netio_closure(manifests, crate, feature):
    """The netio features enabled by `feature` of `crate`, following forwards."""
    reached = set()
    pending = [(crate, feature)]
    seen = set()
    while pending:
        current, name = pending.pop()
        if (current, name) in seen:
            continue
        seen.add((current, name))
        if current == 'packetcraftr-netio':
            reached.add(name)
        for entry in manifests[current].get('features', {}).get(name, []):
            if '/' in entry:
                target, forwarded = entry.split('/', 1)
                pending.append((target, forwarded))
            elif not entry.startswith('dep:'):
                pending.append((current, entry))
    return reached


class ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = read_manifest(ROOT, 'Cargo.toml')
        cls.manifests = {name: read_manifest(ROOT, relative)
                         for name, relative in CRATES.items()}

    def test_the_four_workspace_version_pins_agree(self):
        version = self.workspace['workspace']['package']['version']
        dependencies = self.workspace['workspace']['dependencies']
        for crate in ('packetcraftr', 'packetcraftr-core', 'packetcraftr-netio'):
            self.assertEqual(dependencies[crate]['version'], version, crate)

    def test_crates_match_workspace_pins(self):
        pins = self.workspace['workspace']['package']
        for name, manifest in self.manifests.items():
            package = manifest['package']
            for field in ('version', 'edition', 'rust-version'):
                value = package[field]
                if isinstance(value, dict) and value.get('workspace') is True:
                    value = pins[field]
                self.assertEqual(value, pins[field], f'{name}: {field}')

    def test_native_features_forward_identically_to_netio(self):
        for feature in NATIVE_FEATURES:
            expected = netio_closure(self.manifests, 'packetcraftr-netio', feature)
            self.assertIn(feature, expected)
            for crate in ('packetcraftr', 'packetcraftr-cli'):
                reached = netio_closure(self.manifests, crate, feature)
                self.assertEqual(reached, expected, f'{crate}: {feature}')

    def test_defaults_reach_the_same_netio_features(self):
        expected = netio_closure(self.manifests, 'packetcraftr', 'default')
        self.assertEqual(netio_closure(self.manifests, 'packetcraftr-cli', 'default'), expected)
        self.assertEqual(expected, {'native-route'})


if __name__ == '__main__':
    unittest.main()
