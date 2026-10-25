# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from support import ROOT, load_script

assets = load_script('release_assets')


def fixture_inventory(root: Path) -> tuple[Path, dict[str, list[str]]]:
    manifest = 'examples/captures/protocols.manifest.json'
    capture = 'examples/captures/fixture.pcap'
    packet = 'examples/documents/packet.json'
    for name in (manifest, capture, packet):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'')
    path = root / manifest
    path.write_text(json.dumps(dict(protocols=[dict(capture='fixture.pcap', packet_document=packet)])))
    return path, dict(source_assets=[manifest, capture, packet], generated_assets=['generated/report.json'])


class ReleaseAssetTests(unittest.TestCase):
    def test_repository_inventory_is_valid(self) -> None:
        assets.validate_manifest(assets.MANIFEST)
        self.assertEqual(assets.SOURCE_ASSETS, tuple(assets.MANIFEST['source_assets']))
        self.assertEqual(assets.GENERATED_ASSETS, tuple(assets.MANIFEST['generated_assets']))

    def test_inventory_shape_is_explicit(self) -> None:
        for value in ([], {}, {'schema': 'packetcraftr.release-assets/v1', 'source_assets': 'LICENSE'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                assets.validate_manifest(value)
        valid = dict(schema='packetcraftr.release-assets/v1', source_assets=['LICENSE'], generated_assets=['report.json'])
        self.assertEqual(assets.validate_manifest(valid), valid)
        for schema in ('packetcraftr.release-assets/v0', 'packetcraftr.release-assets/v2', 'unknown', None, True):
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                assets.validate_manifest(valid | {'schema': schema})
        for category in ('source_assets', 'generated_assets'):
            for invalid in ([], [''], [None], [True], {'LICENSE': 1}, ('LICENSE',)):
                with self.subTest(category=category, invalid=invalid), self.assertRaises(ValueError):
                    assets.validate_manifest(valid | {category: invalid})

    def test_paths_are_safe_portable_and_canonical(self) -> None:
        for entry in ('../escape', '/absolute', 'C:file', 'a\\b', 'a//b', './a', '.', 'a/../b', 'a\nb', '', 'a/', 'a/b/'):
            manifest = copy.deepcopy(assets.MANIFEST)
            manifest['source_assets'][0] = entry
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                assets.validate_manifest(manifest)

    def test_duplicates_and_source_generated_collisions_are_rejected(self) -> None:
        for category in ('source_assets', 'generated_assets'):
            manifest = copy.deepcopy(assets.MANIFEST)
            manifest[category].append(manifest['source_assets'][0])
            with self.subTest(category=category), self.assertRaises(ValueError):
                assets.validate_manifest(manifest)

    def test_device_components_and_ancestor_collisions_are_rejected(self) -> None:
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

    def test_all_protocol_fixture_references_exist_and_are_packaged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, manifest = fixture_inventory(root)
            assets.validate_protocol_fixtures(root, manifest)
            for name in manifest['source_assets']:
                missing = manifest | {'source_assets': [entry for entry in manifest['source_assets'] if entry != name]}
                with self.subTest(missing_from_inventory=name), self.assertRaisesRegex(ValueError, 'must exist and be packaged'):
                    assets.validate_protocol_fixtures(root, missing)
                data = (root / name).read_bytes()
                (root / name).unlink()
                with self.subTest(missing_file=name), self.assertRaises(ValueError):
                    assets.validate_protocol_fixtures(root, manifest)
                (root / name).write_bytes(data)

    def test_protocol_fixture_manifest_enforces_its_byte_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, manifest = fixture_inventory(root)
            encoded = path.read_bytes()
            limit = 1024 * 1024
            path.write_bytes(encoded + b' ' * (limit - len(encoded)))
            assets.validate_protocol_fixtures(root, manifest)
            path.write_bytes(path.read_bytes() + b' ')
            with self.assertRaisesRegex(ValueError, 'JSON exceeds'):
                assets.validate_protocol_fixtures(root, manifest)

    def test_loaded_release_inventory_is_bounded_and_exports_supplied_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, manifest = fixture_inventory(root)
            scripts = root / 'scripts'
            scripts.mkdir()
            for name in ('release_assets.py', 'script_support.py'):
                (scripts / name).write_bytes((ROOT / 'scripts' / name).read_bytes())
            path = scripts / 'release-assets.json'
            encoded = json.dumps(manifest | {'schema': 'packetcraftr.release-assets/v1'}).encode()
            limit = 1024 * 1024
            path.write_bytes(encoded + b' ' * (limit - len(encoded)))
            command = [sys.executable, '-c',
                       'import json,release_assets\nprint(json.dumps(dict(source_assets=release_assets.SOURCE_ASSETS, '
                       'generated_assets=release_assets.GENERATED_ASSETS)))']
            result = subprocess.run(command, cwd=scripts, capture_output=True, text=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), manifest)
            path.write_bytes(path.read_bytes() + b' ')
            result = subprocess.run(command, cwd=scripts, capture_output=True, text=True, timeout=5, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, '')
            self.assertIn('JSON exceeds', result.stderr)


if __name__ == '__main__':
    unittest.main()
