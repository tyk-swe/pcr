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


def validate_source_assets_exist(root, manifest):
    """Require every inventoried source asset to exist at packaging time."""
    for entry in manifest['source_assets']:
        if not (root / entry).is_file():
            raise ValueError(f'source asset must exist: {entry}')


FIXED_ASSETS = (
    'Cargo.lock',
    'LICENSE',
    'README.md',
    'THIRD_PARTY_NOTICES.md',
    'scripts/release-assets.json',
)

BUILT_ASSETS = (
    'BUILD-METADATA.json',
    'completions/packetcraftr.bash',
    'completions/packetcraftr.elv',
    'completions/packetcraftr.fish',
    'completions/_packetcraftr',
    'completions/_packetcraftr.ps1',
    'man/packetcraftr.1',
)

DERIVED_TREES = (
    'crates/packetcraftr/data',
    'examples/captures',
    'examples/consumers',
    'examples/documents',
)


def _tree_files(root, relative):
    base = root / relative
    return sorted(
        str(path.relative_to(root)).replace('\\', '/')
        for path in base.rglob('*')
        if path.is_file() and '__pycache__' not in path.parts
    )


def generated_manifest(root):
    """The manifest derived from the worktree: fixed files, the embedded
    datasets, the examples trees, and the published schemas."""
    source_assets = set(FIXED_ASSETS)
    for tree in DERIVED_TREES:
        source_assets.update(_tree_files(root, tree))
    source_assets.update(
        str(path.relative_to(root)).replace('\\', '/')
        for path in (root / 'schemas').glob('*.json')
    )
    return {
        'schema': 'packetcraftr.release-assets/v1',
        'source_assets': sorted(source_assets),
        'generated_assets': sorted(BUILT_ASSETS),
    }


def validate_generated(root, manifest):
    """Fail on drift between the checked-in manifest and the worktree."""
    expected = generated_manifest(root)
    for category in ('source_assets', 'generated_assets'):
        if manifest.get(category) != expected[category]:
            missing = sorted(set(expected[category]) - set(manifest.get(category, [])))
            extra = sorted(set(manifest.get(category, [])) - set(expected[category]))
            raise ValueError(
                f'release-assets.json drifted from the worktree: '
                f'unlisted {missing}, stale {extra}; regenerate with '
                f'python3 scripts/release_assets.py'
            )


ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = Path(__file__).with_name('release-assets.json')

if __name__ == '__main__':
    import json
    import sys

    MANIFEST_PATH.write_text(json.dumps(generated_manifest(ROOT), indent=2) + '\n')
    sys.exit(0)

MANIFEST = validate_manifest(read_json(MANIFEST_PATH, max_bytes=1024 * 1024))
validate_protocol_fixtures(ROOT, MANIFEST)
validate_source_assets_exist(ROOT, MANIFEST)
validate_generated(ROOT, MANIFEST)
SOURCE_ASSETS = tuple(MANIFEST['source_assets'])
GENERATED_ASSETS = tuple(MANIFEST['generated_assets'])
