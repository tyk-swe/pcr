# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import copy
import unittest

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


if __name__ == '__main__':
    unittest.main()
