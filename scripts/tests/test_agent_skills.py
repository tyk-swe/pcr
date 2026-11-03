# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest

from support import load_script

skills = load_script('agent_skills')


class AgentSkillsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / '.agents' / 'skills' / 'example'
        (self.source / 'agents').mkdir(parents=True)
        (self.source / 'SKILL.md').write_text('canonical skill\n')
        (self.source / 'agents' / 'openai.yaml').write_text('adapter settings\n')

    def require_symlinks(self) -> None:
        probe = self.root / 'symlink-probe'
        try:
            probe.symlink_to(self.source, target_is_directory=True)
        except OSError as error:
            self.skipTest(f'symlinks unavailable: {error}')
        probe.unlink()

    def test_links_are_reproducible(self) -> None:
        self.require_symlinks()
        skills.generate(self.root, copies=False)
        skills.check(self.root)
        for name in skills.ADAPTERS:
            self.assertEqual(os.readlink(self.root / name / 'skills' / 'example'), skills.target('example'))
        skills.generate(self.root, copies=False)
        skills.check(self.root)

    def test_copies_are_reproducible(self) -> None:
        skills.generate(self.root, copies=True)
        skills.check(self.root)
        skills.generate(self.root, copies=True)
        skills.check(self.root)
        for name in skills.ADAPTERS:
            copy = self.root / name / 'skills' / 'example'
            self.assertFalse(copy.is_symlink())
            self.assertEqual((copy / 'SKILL.md').read_text(), 'canonical skill\n')

    def test_check_detects_missing_stale_and_divergent_copies(self) -> None:
        skills.generate(self.root, copies=True)
        copy = self.root / '.claude' / 'skills' / 'example'
        (copy / 'SKILL.md').write_text('edited copy')
        with self.assertRaisesRegex(ValueError, 'differs'):
            skills.check(self.root)
        self.assertEqual((copy / 'SKILL.md').read_text(), 'edited copy')
        skills.generate(self.root, copies=True)
        (copy / 'agents' / 'stale').write_text('old')
        with self.assertRaisesRegex(ValueError, 'differs'):
            skills.check(self.root)
        skills.generate(self.root, copies=True)
        if os.name != 'nt':
            path = copy / 'agents' / 'openai.yaml'
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
            with self.assertRaisesRegex(ValueError, 'differs'):
                skills.check(self.root)
            skills.generate(self.root, copies=True)
        (copy / 'agents' / 'openai.yaml').unlink()
        with self.assertRaisesRegex(ValueError, 'differs'):
            skills.check(self.root)
        skills.generate(self.root, copies=True)
        (self.root / '.devin' / 'skills' / 'example' / 'SKILL.md').unlink()
        with self.assertRaisesRegex(ValueError, 'differs'):
            skills.check(self.root)
        shutil.rmtree(self.root / '.devin' / 'skills' / 'example')
        with self.assertRaisesRegex(ValueError, 'missing'):
            skills.check(self.root)
        skills.generate(self.root, copies=True)
        (self.root / '.devin' / 'skills' / 'stale').mkdir()
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            skills.check(self.root)
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            skills.generate(self.root, copies=True)

    def test_materialized_git_links_can_be_replaced_with_copies(self) -> None:
        for name in skills.ADAPTERS:
            base = self.root / name / 'skills'
            base.mkdir(parents=True)
            (base / 'example').write_text(skills.target('example'))
        with self.assertRaisesRegex(ValueError, 'expected a skill link or copy'):
            skills.check(self.root)
        skills.generate(self.root, copies=True)
        skills.check(self.root)

    def test_missing_and_malformed_sources_are_rejected(self) -> None:
        (self.source / 'SKILL.md').unlink()
        with self.assertRaisesRegex(ValueError, 'missing SKILL.md'):
            skills.generate(self.root, copies=True)
        (self.source / 'agents' / 'openai.yaml').unlink()
        (self.source / 'agents').rmdir()
        self.source.rmdir()
        with self.assertRaisesRegex(ValueError, 'no canonical skills'):
            skills.check(self.root)

    def test_symlinked_source_cannot_be_traversed(self) -> None:
        self.require_symlinks()
        (self.source / 'external').symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'unexpected symlink'):
            skills.generate(self.root, copies=True)
        self.assertFalse((self.root / '.claude').exists())

    def test_symlinked_adapter_root_cannot_be_traversed(self) -> None:
        self.require_symlinks()
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'marker').write_text('preserved')
        (self.root / '.claude').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'real directory'):
            skills.generate(self.root, copies=True)
        self.assertEqual((outside / 'marker').read_text(), 'preserved')
        self.assertFalse((outside / 'skills').exists())

    def test_wrong_link_and_unrelated_file_are_rejected(self) -> None:
        self.require_symlinks()
        skills.generate(self.root, copies=False)
        path = self.root / '.claude' / 'skills' / 'example'
        path.unlink()
        path.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'incorrect skill link'):
            skills.check(self.root)
        path.unlink()
        path.write_text('unrelated')
        with self.assertRaisesRegex(ValueError, 'unrelated file'):
            skills.generate(self.root, copies=True)
        self.assertEqual(path.read_text(), 'unrelated')


if __name__ == '__main__':
    unittest.main()
