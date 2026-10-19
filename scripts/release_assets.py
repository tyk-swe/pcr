# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared, validated inventory for packaging and extracted-archive validation."""
from pathlib import Path, PurePosixPath

from script_support import read_json


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
                    or any(part in ('.', '..') for part in path.parts)
                    or any(char in entry for char in '\\:*?\"<>|')
                    or any(part.endswith((' ', '.')) for part in path.parts)
                    or any(ord(char) < 32 or ord(char) == 127 for char in entry)):
                raise ValueError(f'unsafe or noncanonical release asset path: {entry!r}')
            folded = entry.casefold()
            if folded in seen:
                raise ValueError(f'duplicate release asset across inventories: {entry}')
            seen.add(folded)
    return manifest


MANIFEST = validate_manifest(read_json(Path(__file__).with_name('release-assets.json'), max_bytes=1024 * 1024))
SOURCE_ASSETS = tuple(MANIFEST['source_assets'])
GENERATED_ASSETS = tuple(MANIFEST['generated_assets'])
