# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from support import load_script

assets = load_script('release_assets')
ROOT = Path(__file__).resolve().parents[2]


class ReleaseAssetTests(unittest.TestCase):
    def setUp(self):
        self.inventory = assets.load_inventory(ROOT)
        self.manifest = self.inventory.manifest()

    def test_minimal_valid_inventory_is_accepted(self):
        manifest = {'schema': 'packetcraftr.release-assets/v1',
                    'source_assets': ['source.txt'],
                    'generated_assets': ['generated/out.txt']}
        inventory = assets.validate_manifest(manifest)
        self.assertEqual(inventory.source_assets, ('source.txt',))
        self.assertEqual(inventory.generated_assets, ('generated/out.txt',))
        self.assertEqual(inventory.manifest(), manifest)

    def test_inventory_shape_is_explicit(self):
        for value in ([], {}, {'schema': 'packetcraftr.release-assets/v1', 'source_assets': 'LICENSE'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                assets.validate_manifest(value)

    def test_paths_are_safe_portable_and_canonical(self):
        for entry in ('../escape', '/absolute', 'C:file', 'a\\b', 'a//b', './a', '.', 'a/../b', 'a\nb', ''):
            manifest = copy.deepcopy(self.manifest)
            manifest['source_assets'][0] = entry
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                assets.validate_manifest(manifest)

    def test_asset_name_collisions_are_rejected(self):
        for category in ('source_assets', 'generated_assets'):
            manifest = copy.deepcopy(self.manifest)
            manifest[category].append(manifest['source_assets'][0])
            with self.subTest(category=category), self.assertRaises(ValueError):
                assets.validate_manifest(manifest)

    def test_device_paths_and_ancestor_collisions_rejected(self):
        for entry in ('CON', 'dir/nUl.txt', 'COM1.log', 'lpt9', 'CONIN$', 'a/COM¹.txt', 'CON .txt', 'AUX .log'):
            manifest = copy.deepcopy(self.manifest)
            manifest['source_assets'].append(entry)
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                assets.validate_manifest(manifest)
        for first, second in [('a', 'A/b'), ('a/B', 'A')]:
            manifest = copy.deepcopy(self.manifest)
            manifest['source_assets'].append(first)
            manifest['generated_assets'].append(second)
            with self.subTest(first=first), self.assertRaisesRegex(ValueError, 'collision'):
                assets.validate_manifest(manifest)

    def test_protocol_fixtures_exist_and_are_packaged(self):
        assets.validate_protocol_fixtures(ROOT, self.inventory)
        manifest = copy.deepcopy(self.manifest)
        manifest['source_assets'].remove('examples/documents/packet-mqtt.json')
        with self.assertRaisesRegex(ValueError, 'packet-mqtt.json'):
            assets.validate_protocol_fixtures(ROOT, assets.validate_manifest(manifest))
        original_is_file = Path.is_file
        with patch.object(Path, 'is_file', lambda path: False if path.name == 'packet-mqtt.json' else original_is_file(path)):
            with self.assertRaisesRegex(ValueError, 'must exist'):
                assets.validate_protocol_fixtures(ROOT, self.inventory)


    def test_checked_in_manifest_matches_the_worktree(self):
        assets.validate_generated(ROOT, self.inventory)
        manifest = copy.deepcopy(self.manifest)
        manifest['source_assets'].remove('examples/documents/packet-mqtt.json')
        with self.assertRaisesRegex(ValueError, 'drifted'):
            assets.validate_generated(ROOT, assets.validate_manifest(manifest))

    def test_all_source_assets_exist(self):
        assets.validate_source_assets_exist(ROOT, self.inventory)
        manifest = copy.deepcopy(self.manifest)
        manifest['source_assets'].append('examples/documents/no-such-file.json')
        with self.assertRaisesRegex(ValueError, 'no-such-file'):
            assets.validate_source_assets_exist(ROOT, assets.validate_manifest(manifest))

    def test_loader_validates_the_supplied_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for entry in assets.FIXED_ASSETS:
                path = root / entry
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('')
            fixtures = root / 'examples/captures/protocols.manifest.json'
            fixtures.parent.mkdir(parents=True)
            fixtures.write_text(json.dumps({'protocols': []}))
            expected = assets.generated_inventory(root)
            (root / 'scripts/release-assets.json').write_text(json.dumps(expected.manifest()))
            self.assertEqual(assets.load_inventory(root), expected)
            (root / 'LICENSE').unlink()
            with self.assertRaisesRegex(ValueError, 'source asset must exist: LICENSE'):
                assets.load_inventory(root)
            (root / 'LICENSE').write_text('')
            (root / 'examples/documents').mkdir()
            (root / 'examples/documents/new.txt').write_text('unlisted')
            with self.assertRaisesRegex(ValueError, 'drifted'):
                assets.load_inventory(root)


if __name__ == '__main__':
    unittest.main()
