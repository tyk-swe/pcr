# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from support import load_script

assets = load_script('release_assets')


class ReleaseAssetTests(unittest.TestCase):
    def test_repository_inventory_is_valid(self):
        assets.validate_manifest(assets.MANIFEST)

    def test_inventory_shape_is_explicit(self):
        for value in ([], {}, {'schema': 'packetcraftr.release-assets/v1', 'source_assets': 'LICENSE'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                assets.validate_manifest(value)

    def test_paths_are_safe_portable_and_canonical(self):
        for entry in ('../escape', '/absolute', 'C:file', 'a\\b', 'a//b', './a', '.', 'a/../b', 'a\nb', ''):
            manifest = copy.deepcopy(assets.MANIFEST)
            manifest['source_assets'][0] = entry
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                assets.validate_manifest(manifest)

    def test_duplicates_and_source_generated_collisions_are_rejected(self):
        for category in ('source_assets', 'generated_assets'):
            manifest = copy.deepcopy(assets.MANIFEST)
            manifest[category].append(manifest['source_assets'][0])
            with self.subTest(category=category), self.assertRaises(ValueError):
                assets.validate_manifest(manifest)

    def test_device_components_and_ancestor_collisions_are_rejected(self):
        for entry in ('CON', 'dir/nUl.txt', 'COM1.log', 'lpt9', 'CONIN$', 'a/COM¹.txt', 'CON .txt', 'AUX .log'):
            manifest = copy.deepcopy(assets.MANIFEST)
            manifest['source_assets'].append(entry)
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                assets.validate_manifest(manifest)
        for first, second in [('a', 'A/b'), ('a/B', 'A')]:
            manifest = copy.deepcopy(assets.MANIFEST)
            manifest['source_assets'].append(first)
            manifest['generated_assets'].append(second)
            with self.subTest(first=first), self.assertRaisesRegex(ValueError, 'collision'):
                assets.validate_manifest(manifest)

    def test_all_protocol_fixture_references_exist_and_are_packaged(self):
        root = Path(assets.__file__).resolve().parent.parent
        assets.validate_protocol_fixtures(root, assets.MANIFEST)
        manifest = copy.deepcopy(assets.MANIFEST)
        manifest['source_assets'].remove('examples/documents/packet-mqtt.json')
        with self.assertRaisesRegex(ValueError, 'packet-mqtt.json'):
            assets.validate_protocol_fixtures(root, manifest)
        original_is_file = Path.is_file
        with patch.object(Path, 'is_file', lambda path: False if path.name == 'packet-mqtt.json' else original_is_file(path)):
            with self.assertRaisesRegex(ValueError, 'must exist'):
                assets.validate_protocol_fixtures(root, assets.MANIFEST)


if __name__ == '__main__':
    unittest.main()
