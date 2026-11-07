# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Validated inventory for release packaging."""
from pathlib import Path, PurePosixPath
from typing import NamedTuple

from script_support import portable_basename, read_json

SCHEMA = 'packetcraftr.release-assets/v1'


class Inventory(NamedTuple):
    source_assets: tuple[str, ...]
    generated_assets: tuple[str, ...]

    def manifest(self) -> dict[str, str | list[str]]:
        return {
            'schema': SCHEMA,
            'source_assets': list(self.source_assets),
            'generated_assets': list(self.generated_assets),
        }


def _paths(entries: object, category: str) -> tuple[str, ...]:
    if not isinstance(entries, list) or not entries:
        raise ValueError(f'{category} must be a non-empty list')
    for entry in entries:
        if not isinstance(entry, str) or not entry:
            raise ValueError(f'{category} entries must be non-empty paths')
        path = PurePosixPath(entry)
        if (not path.parts or path.is_absolute() or str(path) != entry
                or any(not portable_basename(part) for part in path.parts)):
            raise ValueError(f'unsafe or noncanonical release asset path: {entry!r}')
    return tuple(entries)


def validate_manifest(manifest: object) -> Inventory:
    if not isinstance(manifest, dict) or manifest.get('schema') != SCHEMA:
        raise ValueError('unsupported release asset manifest')
    inventory = Inventory(
        _paths(manifest.get('source_assets'), 'source_assets'),
        _paths(manifest.get('generated_assets'), 'generated_assets'),
    )
    paths = inventory.source_assets + inventory.generated_assets
    folded = tuple(path.casefold() for path in paths)
    for index, entry in enumerate(folded):
        if entry in folded[:index]:
            raise ValueError(f'duplicate release asset across inventories: {paths[index]}')
        if any(entry.startswith(other + '/') or other.startswith(entry + '/')
               for other in folded[:index]):
            raise ValueError(f'file/directory collision across inventories: {paths[index]}')
    return inventory


def _fixture_paths(fixture: object) -> tuple[str, str]:
    if not isinstance(fixture, dict):
        raise ValueError('invalid protocol fixture entry')
    capture, document = fixture.get('capture'), fixture.get('packet_document')
    if not isinstance(capture, str) or not isinstance(document, str):
        raise ValueError('protocol fixture paths must be strings')
    return str(PurePosixPath('examples/captures') / capture), document


def validate_protocol_fixtures(root: Path, inventory: Inventory) -> None:
    fixture_path = 'examples/captures/protocols.manifest.json'
    fixtures = read_json(root / fixture_path, max_bytes=1024 * 1024)
    if not isinstance(fixtures, dict) or not isinstance(fixtures.get('protocols'), list):
        raise ValueError('invalid protocol fixture manifest')
    required = frozenset((fixture_path,)) | frozenset(
        path for fixture in fixtures['protocols'] for path in _fixture_paths(fixture)
    )
    for path in sorted(required):
        if path not in inventory.source_assets or not (root / path).is_file():
            raise ValueError(f'protocol fixture must exist and be packaged: {path}')


def validate_source_assets_exist(root: Path, inventory: Inventory) -> None:
    for entry in inventory.source_assets:
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


def _tree_files(root: Path, relative: str) -> tuple[str, ...]:
    return tuple(
        path.relative_to(root).as_posix()
        for path in (root / relative).rglob('*')
        if path.is_file() and '__pycache__' not in path.parts
    )


def generated_inventory(root: Path) -> Inventory:
    source_assets = frozenset(FIXED_ASSETS) | frozenset(
        path for tree in DERIVED_TREES for path in _tree_files(root, tree)
    ) | frozenset(path.relative_to(root).as_posix() for path in (root / 'schemas').glob('*.json'))
    return Inventory(tuple(sorted(source_assets)), tuple(sorted(BUILT_ASSETS)))


def validate_generated(root: Path, inventory: Inventory) -> None:
    expected = generated_inventory(root)
    for category, entries, expected_entries in (
        ('source_assets', inventory.source_assets, expected.source_assets),
        ('generated_assets', inventory.generated_assets, expected.generated_assets),
    ):
        if entries != expected_entries:
            missing = sorted(set(expected_entries) - set(entries))
            extra = sorted(set(entries) - set(expected_entries))
            raise ValueError(
                f'release-assets.json {category} drifted from the worktree, '
                f'unlisted {missing}, stale {extra}. Regenerate with '
                f'python3 scripts/release_assets.py'
            )


def load_inventory(root: Path) -> Inventory:
    inventory = validate_manifest(read_json(root / 'scripts/release-assets.json', max_bytes=1024 * 1024))
    validate_protocol_fixtures(root, inventory)
    validate_source_assets_exist(root, inventory)
    validate_generated(root, inventory)
    return inventory


if __name__ == '__main__':
    import json

    root = Path(__file__).resolve().parent.parent
    (root / 'scripts/release-assets.json').write_text(
        json.dumps(generated_inventory(root).manifest(), indent=2) + '\n'
    )
