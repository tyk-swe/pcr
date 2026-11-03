#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Check or regenerate the Claude and Devin skill discovery paths."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import sys

from script_support import portable_basename

ADAPTERS = ('.claude', '.devin')


def directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f'expected a real directory: {path}')


def tree(path: Path) -> dict[str, tuple[bytes, bool] | None]:
    directory(path)
    result = {}
    for child in sorted(path.iterdir()):
        if child.is_symlink():
            raise ValueError(f'unexpected symlink inside skill: {child}')
        if child.is_dir():
            result[child.name] = None
            result.update({f'{child.name}/{name}': value for name, value in tree(child).items()})
        elif child.is_file():
            executable = os.name != 'nt' and bool(child.stat().st_mode & 0o111)
            result[child.name] = (child.read_bytes(), executable)
        else:
            raise ValueError(f'expected a regular skill file: {child}')
    return result


def sources(root: Path) -> dict[str, dict[str, tuple[bytes, bool] | None]]:
    directory(root / '.agents')
    base = root / '.agents' / 'skills'
    directory(base)
    entries = sorted(base.iterdir())
    if not entries:
        raise ValueError(f'no canonical skills: {base}')
    names = [entry.name for entry in entries]
    if len({name.casefold() for name in names}) != len(names):
        raise ValueError('canonical skill names collide on case-insensitive filesystems')
    result = {}
    for entry in entries:
        if not portable_basename(entry.name):
            raise ValueError(f'invalid skill name: {entry.name!r}')
        content = tree(entry)
        if content.get('SKILL.md') is None:
            raise ValueError(f'missing SKILL.md: {entry}')
        result[entry.name] = content
    return result


def adapter(root: Path, name: str, *, create: bool) -> Path:
    parent = root / name
    base = parent / 'skills'
    if create:
        parent.mkdir(exist_ok=True)
    directory(parent)
    if create:
        base.mkdir(exist_ok=True)
    directory(base)
    return base


def target(name: str) -> str:
    return f'../../.agents/skills/{name}'


def check(root: Path) -> None:
    expected = sources(root)
    for name in ADAPTERS:
        base = adapter(root, name, create=False)
        entries = {entry.name: entry for entry in base.iterdir()}
        missing = expected.keys() - entries.keys()
        stale = entries.keys() - expected.keys()
        if missing or stale:
            raise ValueError(f'{base}: missing {sorted(missing)}, unexpected {sorted(stale)}')
        for skill, content in expected.items():
            entry = entries[skill]
            if entry.is_symlink():
                if os.readlink(entry) != target(skill):
                    raise ValueError(f'incorrect skill link: {entry}')
            elif entry.is_dir():
                if tree(entry) != content:
                    raise ValueError(f'skill copy differs from canonical source: {entry}')
            else:
                raise ValueError(f'expected a skill link or copy: {entry}')


def generate(root: Path, *, copies: bool) -> None:
    expected = sources(root)
    bases = [adapter(root, name, create=True) for name in ADAPTERS]
    for base in bases:
        stale = {entry.name for entry in base.iterdir()} - expected.keys()
        if stale:
            raise ValueError(f'{base}: unexpected entries {sorted(stale)}')
        for skill in expected:
            entry = base / skill
            if entry.is_file() and not entry.is_symlink() and entry.read_bytes() not in (
                target(skill).encode(), (target(skill) + '\n').encode()
            ):
                raise ValueError(f'refusing to replace an unrelated file: {entry}')
    for base in bases:
        for skill in expected:
            entry = base / skill
            if entry.is_symlink() or entry.is_file():
                entry.unlink()
            elif entry.is_dir():
                shutil.rmtree(entry)
            elif entry.exists():
                raise ValueError(f'cannot replace skill entry: {entry}')
            if copies:
                shutil.copytree(root / '.agents' / 'skills' / skill, entry)
            else:
                entry.symlink_to(target(skill), target_is_directory=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true', help='check links or copies without writing (default)')
    mode.add_argument('--write-links', action='store_true', help='regenerate discovery links')
    mode.add_argument('--write-copies', action='store_true', help='regenerate copies when symlinks are unavailable')
    args = parser.parse_args(argv)
    try:
        if args.write_links or args.write_copies:
            generate(args.root, copies=args.write_copies)
        check(args.root)
    except (OSError, ValueError) as error:
        print(f'agent skills: {error}', file=sys.stderr)
        return 1
    print('agent skills are in sync')
    return 0


if __name__ == '__main__':
    sys.exit(main())
