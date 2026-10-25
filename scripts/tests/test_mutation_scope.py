# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from support import ROOT, mutation_workspace
from mutation_scope import Change, changes_since, select


class MutationSelectionTests(unittest.TestCase):
    def test_production_changes_select_their_files_without_unrelated_groups(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mutation_workspace(root)
            rust = 'crates/sample/src/lib.rs'
            python = 'scripts/beta.py'
            targets = select(root, (Change(rust), Change(python)))
            self.assertEqual({(target.group, target.language, target.files) for target in targets},
                             {('sample', 'rust', (rust,)), (python, 'python', (python,))})

    def test_adding_inline_tests_expands_selection_to_their_complete_crate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mutation_workspace(root)
            path = 'crates/sample/src/lib.rs'
            original = (root / path).read_text()
            for test in ('#[test]\nfn checks_value() { assert_eq!(value(), 1); }\n',
                         '#[cfg(test)]\nmod tests { #[test] fn checks_value() {} }\n'):
                (root / path).write_text(original + test)
                targets = select(root, (Change(path, original),))
                with self.subTest(test=test):
                    self.assertEqual({(target.group, target.files) for target in targets}, {('sample', ())})
                (root / path).write_text(original)
                removed = select(root, (Change(path, original + test),))
                self.assertEqual({(target.group, target.files) for target in removed}, {('sample', ())})

    def test_shared_changes_select_complete_owned_language_groups(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mutation_workspace(root)
            rust = {'sample', 'other'}
            python = {'scripts/alpha.py', 'scripts/beta.py'}
            shared = ('.config/mutation.toml', '.github/workflows/ci.yml', 'Cargo.toml', 'Cargo.lock',
                      'rust-toolchain.toml', 'requirements-dev.txt', 'AGENTS.md', 'TESTING.md',
                      'schemas/contract.json', 'examples/captures/fixture.pcap',
                      'examples/documents/fixture.json', 'examples/consumers/fixtures/fixture.json')
            cases = tuple((path, rust | python) for path in shared) + (
                ('scripts/tests/support.py', python), ('scripts/tests/fixture.json', python),
                ('scripts/fixtures/input.json', python), ('scripts/tests/test_alpha.py', {'scripts/alpha.py'}),
                ('crates/sample/Cargo.toml', rust), ('crates/sample/src/fixture.pcap', {'sample'}),
                ('crates/sample/src/tests.rs', {'sample'}),
            )
            helper_paths = ('crates/sample/src/test_helpers.rs', 'crates/sample/src/tests/support.rs')
            for path in helper_paths:
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text('pub fn fixture_value() -> u8 { 1 }\n')
            cases += tuple((path, {'sample'}) for path in helper_paths)
            full = select(root, (), full=True)
            full_reasons = {target.group: target.reason for target in full}
            self.assertEqual({target.group for target in full}, rust | python)
            for path, expected in cases:
                targets = select(root, (Change(path),))
                with self.subTest(path=path):
                    self.assertEqual({target.group for target in targets}, expected)
                    self.assertTrue(all(not target.files for target in targets if target.language == 'rust'))
                    for target in targets:
                        if target.language != 'python':
                            continue
                        if path == 'scripts/tests/test_alpha.py':
                            self.assertNotEqual(target.reason, full_reasons[target.group])
                        else:
                            self.assertEqual(target.reason, full_reasons[target.group])

    def test_malformed_ownership_cannot_silently_remove_production_modules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mutation_workspace(root)
            path = root / '.config/mutation.toml'
            original = path.read_text()
            for invalid in ('', '[python]\nmodules = []\n',
                            original.replace('["scripts/tests/test_alpha.py"]', '[]'),
                            original.replace('["scripts/tests/test_alpha.py"]', '[1]'),
                            original.replace('["scripts/tests/test_alpha.py"]', '"scripts/tests/test_alpha.py"'),
                            original.replace('["scripts/tests/test_alpha.py"]', '[""]'),
                            original.replace('["scripts/tests/test_alpha.py"]', '[" "]'),
                            original.replace('scripts/alpha.py', 'scripts/absent.py')):
                path.write_text(invalid)
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    select(root, (), full=True)
            path.write_text(original)
            path.write_text(original.replace('scripts/alpha.py', 'scripts/absent.py'))
            with self.assertRaises(ValueError) as mismatch:
                select(root, (), full=True)
            self.assertIn('scripts/alpha.py', str(mismatch.exception))
            self.assertIn('scripts/absent.py', str(mismatch.exception))
            self.assertNotIn('scripts/beta.py', str(mismatch.exception))
            path.write_text(original)
            (root / 'scripts/unowned.py').write_text('value = 3\n')
            with self.assertRaises(ValueError):
                select(root, (), full=True)

    def test_committed_additions_and_test_deletions_schedule_their_owners(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
                'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}):
            root = Path(directory)
            mutation_workspace(root)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            commit = ['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.test', 'commit', '-qm']
            subprocess.run([*commit, 'initial'], cwd=root, check=True)
            base = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
            (root / 'crates/sample/src/tests.rs').unlink()
            (root / 'scripts/tests/test_alpha.py').unlink()
            added = 'crates/sample/src/new_source.rs'
            (root / added).write_text('pub fn value() -> u8 { 2 }\n')
            subprocess.run(['git', 'add', added], cwd=root, check=True)
            subprocess.run(['git', 'add', '-u'], cwd=root, check=True)
            subprocess.run([*commit, 'delete tests'], cwd=root, check=True)
            changes = changes_since(root, base)
            self.assertEqual(next(change for change in changes if change.path == added).previous, '')
            selected = select(root, changes)
            self.assertEqual({target.group for target in selected}, {'sample', 'scripts/alpha.py'})
            self.assertEqual(next(target for target in selected if target.language == 'rust').files, ())

    def test_deleted_tests_select_their_production_owners(self) -> None:
        rust = select(ROOT, (Change('crates/packetcraftr-core/src/analysis/messages/tests.rs'),))
        self.assertEqual({target.group for target in rust}, {'packetcraftr-core'})
        self.assertEqual(rust[0].files, ())
        python = select(ROOT, (Change('scripts/tests/test_forwarding_consumer.py'),))
        self.assertEqual({target.group for target in python}, {'examples/consumers/forwarding.py'})
        inline = select(ROOT, (Change('crates/packetcraftr-core/src/old.rs', '#[cfg(test)] mod tests {}'),))
        self.assertEqual(inline[0].files, ())

    def test_shared_inputs_schedule_every_affected_language(self) -> None:
        all_targets = select(ROOT, (), full=True)
        for path in ('.config/mutation.toml', 'Cargo.lock', 'examples/captures/example.pcap', 'AGENTS.md'):
            with self.subTest(path=path):
                self.assertEqual({t.group for t in select(ROOT, (Change(path),))},
                                 {t.group for t in all_targets})
        support = select(ROOT, (Change('scripts/tests/support.py'),))
        self.assertEqual({t.group for t in support}, {t.group for t in all_targets if t.language == 'python'})

    def test_unmapped_python_files_cannot_bypass_mutation_checks(self) -> None:
        with self.assertRaisesRegex(ValueError, 'no mutation ownership'):
            select(ROOT, (Change('tools/new_helper.py'),))

    def test_documentation_only_change_has_no_mutants(self) -> None:
        self.assertEqual(select(ROOT, (Change('README.md'),)), ())
