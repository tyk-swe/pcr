# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Validated inventory for release packaging."""
from pathlib import Path, PurePosixPath

from script_support import portable_basename, read_json


def validate_manifest(manifest):
    if not isinstance(manifest, dict) or manifest.get('schema') != 'packetcraftr.release-assets/v1':
        raise ValueError('unsupported release asset manifest')
    seen = set()
    for category in ('source_assets', 'generated_assets'):
        entries = manifest.get(category)
        if not isinstance(entries, list) or not entries:
            raise ValueError(f'{category} must be a non-empty list')
        for entry in entries:
            if not isinstance(entry, str) or not entry:
                raise ValueError(f'{category} entries must be non-empty paths')
            path = PurePosixPath(entry)
            if (not path.parts or path.is_absolute() or str(path) != entry
                    or any(not portable_basename(part) for part in path.parts)):
                raise ValueError(f'unsafe or noncanonical release asset path: {entry!r}')
            folded = entry.casefold()
            if folded in seen:
                raise ValueError(f'duplicate release asset across inventories: {entry}')
            if any(folded.startswith(other + '/') or other.startswith(folded + '/')
                   for other in seen):
                raise ValueError(f'file/directory collision across inventories: {entry}')
            seen.add(folded)
    return manifest


def validate_protocol_fixtures(root, manifest):
    """Require the fixture manifest and every referenced file in the package."""
    fixture_path = 'examples/captures/protocols.manifest.json'
    required = {fixture_path}
    fixtures = read_json(root / fixture_path, max_bytes=1024 * 1024)
    for fixture in fixtures['protocols']:
        required.add(str(PurePosixPath(fixture_path).parent / fixture['capture']))
        required.add(fixture['packet_document'])
    packaged = set(manifest['source_assets'])
    for path in sorted(required):
        if path not in packaged or not (root / path).is_file():
            raise ValueError(f'protocol fixture must exist and be packaged: {path}')


MANIFEST = validate_manifest(read_json(Path(__file__).with_name('release-assets.json'), max_bytes=1024 * 1024))
validate_protocol_fixtures(Path(__file__).resolve().parent.parent, MANIFEST)
SOURCE_ASSETS = tuple(MANIFEST['source_assets'])
GENERATED_ASSETS = tuple(MANIFEST['generated_assets'])
