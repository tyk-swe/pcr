from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re
import subprocess
import tomllib
from typing import Literal


@dataclass(frozen=True)
class Target:
    group: str
    language: Literal['rust', 'python']
    files: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class Change:
    path: str
    previous: str = ''


def configuration(root: Path) -> dict[str, object]:
    with (root / '.config/mutation.toml').open('rb') as source:
        return tomllib.load(source)


def python_modules(root: Path) -> dict[str, tuple[str, ...]]:
    config = configuration(root)
    section = config.get('python')
    if not isinstance(section, dict) or not isinstance(section.get('modules'), dict):
        raise ValueError('missing Python mutation ownership')
    modules = section['modules']
    if any(not isinstance(path, str) or not isinstance(tests, list)
           or not tests or any(not isinstance(test, str) or not test.strip() for test in tests)
           for path, tests in modules.items()):
        raise ValueError('invalid Python mutation ownership')
    discovered = {path.relative_to(root).as_posix()
                  for folder in ('scripts', 'examples/consumers')
                  for path in (root / folder).rglob('*.py')
                  if 'tests' not in path.relative_to(root).parts}
    if discovered != set(modules):
        raise ValueError(f'Python ownership does not match production modules: {discovered ^ set(modules)}')
    return {path: tuple(tests) for path, tests in modules.items()}


def changes_since(root: Path, base: str) -> tuple[Change, ...]:
    result = subprocess.run(
        ['git', 'diff', '--name-only', '--no-renames', '-z', f'{base}...HEAD'],
        cwd=root, check=True, stdout=subprocess.PIPE,
    )
    paths = tuple(path for path in result.stdout.decode().split('\0') if path)
    return tuple(Change(path, subprocess.run(
        ['git', 'show', f'{base}:{path}'], cwd=root, check=False,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    ).stdout.decode(errors='replace')) for path in paths)


def select(root: Path, changes: tuple[Change, ...], *, full: bool = False) -> tuple[Target, ...]:
    crates = tuple(sorted(path.parent.name for path in (root / 'crates').glob('*/Cargo.toml')))
    modules = python_modules(root)
    tests = {test for owned in modules.values() for test in owned}
    deleted_python = {change.path for change in changes if change.path.endswith('.py')
                      and not change.path.startswith('scripts/tests/')
                      and not (root / change.path).is_file()}
    unknown = tuple(change.path for change in changes
                    if change.path.endswith('.py') and change.path not in modules
                    and change.path not in tests and not change.path.startswith('scripts/tests/')
                    and change.path not in deleted_python)
    if unknown:
        raise ValueError(f'Python files have no mutation ownership: {unknown}')
    shared = any(change.path.startswith(('.config/', '.github/', 'examples/captures/',
                                         'examples/documents/', 'examples/consumers/fixtures/', 'schemas/'))
                 or change.path in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
                                    'requirements-dev.txt', 'AGENTS.md', 'TESTING.md')
                 for change in changes)
    shared_python = bool(deleted_python) or any(change.path.startswith('scripts/tests/')
                        and change.path not in tests
                        or change.path.startswith('scripts/') and not change.path.endswith('.py')
                        for change in changes)
    shared_rust = any(change.path.endswith('/Cargo.toml') for change in changes)
    rust = tuple(target for crate in crates
                 if (target := rust_target(root, crate, changes, full or shared or shared_rust)) is not None)
    python = tuple(Target(module, 'python', (module,),
                          'full audit or shared inputs' if full or shared or shared_python
                          else 'production module or mapped test changed')
                   for module, tests in sorted(modules.items())
                   if full or shared or shared_python
                   or any(change.path in (module, *tests) for change in changes))
    return rust + python


def has_rust_tests(source: str) -> bool:
    if any(marker in source for marker in ('#[cfg(test)]', '#[test]', '```', '~~~', '/**', '/*!')):
        return True
    if re.search(r'#\s*!?\s*\[[^]]*\b(?:doc|test)\b', source) is not None:
        return True
    return any(line.startswith(('///    ', '//!    '))
               or line.startswith(('///', '//!')) and '\t' in line
               for line in map(str.lstrip, source.splitlines()))


def rust_target(root: Path, crate: str, changes: tuple[Change, ...], full: bool) -> Target | None:
    prefix = f'crates/{crate}/'
    affected = tuple(change for change in changes if change.path.startswith(prefix))
    if not full and not affected:
        return None
    test_change = any(
        not change.path.endswith('.rs')
        or 'test' in Path(change.path).stem
        or 'tests' in Path(change.path).parts
        or has_rust_tests(change.previous)
        or ((root / change.path).is_file()
            and has_rust_tests((root / change.path).read_text()))
        for change in affected
    )
    if full or test_change:
        return Target(crate, 'rust', (), 'full crate, tests or shared inputs changed')
    files = tuple(change.path for change in affected if (root / change.path).is_file())
    if not files:
        return Target(crate, 'rust', (), 'deleted production files may change test coverage')
    return Target(crate, 'rust', files, 'changed production files')


def serialize(targets: tuple[Target, ...]) -> list[dict[str, object]]:
    return [asdict(target) for target in targets]
