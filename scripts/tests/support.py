# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Load standalone tool scripts without executing their command-line entrypoints."""
from __future__ import annotations

import importlib.util
import os
import shlex
import subprocess
from pathlib import Path
import sys
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))

from mutation_results import Outcome, Report


def load_script(name: str, relative: str | None = None) -> ModuleType:
    path = ROOT / (relative or f'scripts/{name}.py')
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path)
    if spec is None or spec.loader is None:
        raise ImportError(f'cannot load script {path}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def report(killed: int = 9, survived: int = 1, group: str = 'core') -> Report:
    outcomes = tuple(Outcome(str(i), 'killed' if i < killed else 'survived', 'test result')
                     for i in range(killed + survived))
    return Report(group, 'revision', 'version', 'changed production',
                  tuple(outcome.identity for outcome in outcomes), outcomes, True, True)


def mutation_workspace(root: Path) -> None:
    files = {
        'crates/sample/Cargo.toml': '[package]\nname="sample"\n',
        'crates/sample/src/lib.rs': 'pub fn value() -> u8 { 1 }\n',
        'crates/sample/src/tests.rs': '#[test]\nfn protects_value() { assert_eq!(crate::value(), 1); }\n',
        'crates/other/Cargo.toml': '[package]\nname="other"\n',
        'crates/other/src/lib.rs': 'pub fn value() -> u8 { 2 }\n',
        'scripts/alpha.py': 'value = 1\n',
        'scripts/beta.py': 'value = 2\n',
        'scripts/tests/test_alpha.py': 'from alpha import value\ndef test_value(): assert value == 1\n',
        'scripts/tests/test_beta.py': 'from beta import value\ndef test_value(): assert value == 2\n',
        '.config/mutation.toml': '[python.modules]\n"scripts/alpha.py" = ["scripts/tests/test_alpha.py"]\n'
                                 '"scripts/beta.py" = ["scripts/tests/test_beta.py"]\n',
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


def mutation_checkout(root: Path) -> str:
    mutation_workspace(root)
    for name in ('mutation_results.py', 'mutation_scope.py', 'run_mutation.py'):
        (root / 'scripts' / name).write_bytes((ROOT / 'scripts' / name).read_bytes())
    with (root / '.config/mutation.toml').open('a') as config:
        config.write('\n[tools]\ncosmic-ray = "version"\ncargo-mutants = "version"\n')
    (root / '.config/mutation-exclusions.json').write_text('[]\n')
    (root / '.gitignore').write_text('/artifacts/\n__pycache__/\n*.py[cod]\n')
    environment = os.environ | {'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}
    commands = (('init', '-q'), ('add', '.'),
                ('-c', 'user.name=Test', '-c', 'user.email=test@example.test', 'commit', '-qm', 'initial'))
    for command in commands:
        subprocess.run(['git', *command], cwd=root, env=environment, check=True, capture_output=True)
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, env=environment, text=True).strip()


def mutation_tools(root: Path, tools_root: Path) -> tuple[Path, dict[str, str]]:
    tools_root.mkdir(parents=True)
    executable = tools_root / 'python'
    executable.symlink_to(sys.executable)
    fixture = ROOT / 'scripts/tests/fixtures/mutation_tools.py'
    for name, mode in (('cargo', 'cargo'), ('cosmic-ray', 'cosmic')):
        path = tools_root / name
        path.write_text('#!/bin/sh\nexec ' + shlex.join((sys.executable, str(fixture), mode)) + ' "$@"\n')
        path.chmod(0o755)
    (root / 'Cargo.toml').write_text('[workspace]\nmembers = ["crates/sample", "crates/other"]\nresolver = "3"\n')
    for name in ('sample', 'other'):
        (root / f'crates/{name}/Cargo.toml').write_text(f'[package]\nname="{name}"\nversion="0.1.0"\nedition="2024"\n')
    (root / 'crates/sample/src/extra.rs').write_text('pub fn other() -> u8 { 2 }\n')
    (root / 'crates/sample/build.rs').write_text('fn main() {}\n')
    (root / 'marker.txt').write_text('original')
    test = root / 'scripts/tests/test_alpha.py'
    test.write_text('from pathlib import Path\nimport sys\nimport unittest\n'
                    'sys.path.insert(0, str(Path(__file__).resolve().parents[1]))\nfrom alpha import value\n'
                    'class ValueTests(unittest.TestCase):\n'
                    '    def test_value(self) -> None:\n        self.assertEqual(value, 1)\n')
    (root / 'scripts/mutation_test_runner.py').write_bytes((ROOT / 'scripts/mutation_test_runner.py').read_bytes())
    config = root / '.config/mutation.toml'
    config.write_text(config.read_text().replace('[tools]',
        '"scripts/mutation_test_runner.py" = ["scripts/tests/test_alpha.py"]\n\n[tools]'))
    return executable, os.environ | {'PATH': str(tools_root) + os.pathsep + os.environ.get('PATH', ''),
                                    'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}
