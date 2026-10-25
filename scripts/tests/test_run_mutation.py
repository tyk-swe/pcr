# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from contextlib import redirect_stdout
from dataclasses import asdict, replace
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from support import ROOT, mutation_checkout, report
from mutation_results import Exclusion, Outcome, score
from mutation_scope import Target
from run_mutation import check, merge_reports, snapshot


class MutationScoreTests(unittest.TestCase):
    def test_threshold_is_strict_and_applies_to_every_group(self) -> None:
        self.assertFalse(score(report()).passed)
        self.assertTrue(score(report(10)).passed)
        with tempfile.TemporaryDirectory() as directory:
            paths = tuple(Path(directory) / f'{group}.json' for group in ('strong', 'weak'))
            for path, value in zip(paths, (report(99, 1, 'strong'), report(9, 1, 'weak'))):
                path.write_text(json.dumps(dict(platform='Linux', profile='all', shard=1, shards=1,
                                               report=asdict(value))))
            targets = tuple(Target(group, 'rust', (), 'test') for group in ('strong', 'weak'))
            self.assertFalse(check(targets, paths, 'rust', ('Linux',), ('all',), 1, (), 'revision', 'version'))

    def test_empty_selection_is_reported_with_its_reason(self) -> None:
        result = score(report(0, 0))
        self.assertEqual(result.eligible, 0)
        self.assertEqual(result.reason, 'changed production')
        self.assertTrue(result.passed)
        invalid = replace(report(0, 1), outcomes=(Outcome('0', 'invalid', 'compiler diagnostic'),))
        result = score(invalid)
        self.assertEqual((result.killed, result.eligible, result.invalid), (0, 0, 1))
        self.assertTrue(result.passed)
        self.assertFalse(score(report(0, 1)).passed)
        value = report(0, 0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'run.json'
            path.write_text(json.dumps(dict(platform='Linux', profile='all', shard=1, shards=1,
                                           report=asdict(value))))
            output = io.StringIO()
            with redirect_stdout(output):
                passed = check((Target('core', 'rust', (), value.reason),), (path,), 'rust',
                               ('Linux',), ('all',), 1, (), value.revision, value.tool_version)
            summary = json.loads(output.getvalue())
            self.assertTrue(passed)
            self.assertEqual(summary['status'], 'not_applicable')
            self.assertIsNone(summary['percentage'])
            self.assertEqual(summary['reason'], value.reason)

    def test_all_shards_must_agree_and_complete_the_inventory(self) -> None:
        value = report(10, 0)
        target = (Target('core', 'rust', (), 'test'),)
        with tempfile.TemporaryDirectory() as directory:
            paths = tuple(Path(directory) / f'{i}.json' for i in (1, 2))
            for i, path in enumerate(paths):
                partial = replace(value, outcomes=value.outcomes[i::2])
                path.write_text(json.dumps(dict(platform='Linux', profile='all', shard=i + 1,
                                               shards=2, report=asdict(partial))))
            self.assertTrue(check(target, paths, 'rust', ('Linux',), ('all',), 2, (), 'revision', 'version'))
            with self.assertRaises(ValueError):
                check(target, paths[:1], 'rust', ('Linux',), ('all',), 2, (), 'revision', 'version')
            with self.assertRaises(ValueError):
                check(target, (paths[0], paths[0]), 'rust', ('Linux',), ('all',), 2, (), 'revision', 'version')

    def test_reports_from_another_revision_or_tool_cannot_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'run.json'
            path.write_text(json.dumps(dict(platform='Linux', profile='all', shard=1, shards=1,
                                           report=asdict(report(10, 0)))))
            for revision, version in (('other', 'version'), ('revision', 'other')):
                with self.subTest(revision=revision, version=version), self.assertRaises(ValueError):
                    check((Target('core', 'rust', (), 'test'),), (path,), 'rust', ('Linux',), ('all',),
                          1, (), revision, version)

    def test_required_feature_runs_can_detect_different_mutants(self) -> None:
        first = report()
        second = replace(first, outcomes=tuple(replace(outcome, status='survived' if i < 9 else 'killed')
                                               for i, outcome in enumerate(first.outcomes)))
        result = score(merge_reports((first, second)))
        self.assertEqual((result.killed, result.eligible), (10, 10))
        with self.assertRaises(ValueError):
            merge_reports((first, replace(second, revision='another revision')))
        with self.assertRaises(ValueError):
            merge_reports((replace(first, revision='revision tree first'),
                           replace(second, revision='revision tree second')))
        for incomplete in (replace(first, outcomes=()), replace(first, baseline=False),
                           replace(first, complete=False)):
            with self.subTest(incomplete=incomplete), self.assertRaises(ValueError):
                merge_reports((incomplete, second))


class MutationReportTests(unittest.TestCase):
    def test_reviewed_exclusions_can_be_committed_without_referring_to_their_own_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            mutation_checkout(root)
            with tempfile.TemporaryDirectory() as snapshot_directory:
                tree = snapshot(root, Path(snapshot_directory))
            group = 'scripts/alpha.py'
            exclusion = Exclusion(group, tree, '9', 'same result for every allowed input')
            policy = root / '.config/mutation-exclusions.json'
            policy.write_text(json.dumps([asdict(exclusion)]))
            environment = os.environ | {'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}
            subprocess.run(['git', 'add', str(policy)], cwd=root, env=environment, check=True, capture_output=True)
            subprocess.run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.test',
                            'commit', '-qm', 'review equivalent'], cwd=root, env=environment, check=True, capture_output=True)
            revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, env=environment, text=True).strip()
            with tempfile.TemporaryDirectory() as snapshot_directory:
                current_tree = snapshot(root, Path(snapshot_directory))
            value = replace(report(9, 1, group), revision=f'{revision} tree {current_tree}')
            artifacts = root / 'artifacts'
            artifacts.mkdir()
            (artifacts / 'run.json').write_text(json.dumps(dict(platform=sys.platform, profile='all', shard=1,
                                                              shards=1, report=asdict(value))))
            plan = Path(directory) / 'plan.json'
            plan.write_text(json.dumps([asdict(Target(group, 'python', (group,), 'changed production'))]))
            result = subprocess.run([sys.executable, str(root / 'scripts/run_mutation.py'), 'check',
                                     '--plan', str(plan), '--language', 'python', '--platforms', sys.platform,
                                     '--output', str(artifacts)], cwd=root, capture_output=True, text=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual((summary['killed'], summary['eligible'], summary['equivalent']), (9, 9, 1))
            self.assertEqual(summary['source_revision'], tree)
            self.assertEqual(summary['exclusions'], [asdict(exclusion)])

    def test_cli_rejects_cached_results_after_uncommitted_source_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            revision = mutation_checkout(root)
            plan = Path(directory) / 'plan.json'
            target = Target('scripts/alpha.py', 'python', ('scripts/alpha.py',), 'changed production')
            plan.write_text(json.dumps([asdict(target)]))
            with tempfile.TemporaryDirectory() as snapshot_directory:
                tree = snapshot(root, Path(snapshot_directory))
            value = replace(report(2, 0, target.group), revision=f'{revision} tree {tree}')
            artifacts = root / 'artifacts'
            artifacts.mkdir()
            (artifacts / 'run.json').write_text(json.dumps(dict(platform=sys.platform, profile='all', shard=1,
                                                              shards=1, report=asdict(value))))
            command = [sys.executable, str(root / 'scripts/run_mutation.py'), 'check', '--plan', str(plan),
                       '--language', 'python', '--platforms', sys.platform, '--output', str(artifacts)]
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['status'], 'passed')
            for invalid in (root, root / 'unignored-reports'):
                result = subprocess.run(command[:-1] + [str(invalid)], cwd=root, capture_output=True,
                                        text=True, timeout=5, check=False)
                with self.subTest(invalid=invalid):
                    self.assertEqual(result.returncode, 1)
                    self.assertIn('ignored or outside', result.stderr)
            (root / 'scripts/alpha.py').write_text('value = 2\n')
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, '')
            self.assertIn('source snapshot', result.stderr)

    @unittest.skipUnless(os.name == 'posix', 'fixture executables use POSIX shebangs')
    def test_cli_reports_external_command_failure_without_a_success_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable, plan = root / 'git', root / 'plan.json'
            executable.write_text(f'#!{sys.executable}\nimport sys\nsys.exit(13)\n')
            executable.chmod(0o755)
            result = subprocess.run(
                [sys.executable, str(ROOT / 'scripts/run_mutation.py'), 'select',
                 '--base', 'HEAD', '--plan', str(plan)],
                env=os.environ | {'PATH': str(root) + os.pathsep + os.environ.get('PATH', '')},
                capture_output=True, text=True, timeout=5, check=False,
            )
            command = ['git', 'diff', '--name-only', '--no-renames', '-z', 'HEAD...HEAD']
            cause = subprocess.CalledProcessError(13, command)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, '')
            self.assertEqual(result.stderr, f'Mutation audit failed. {cause}\n')
            self.assertFalse(plan.exists())


class MutationSelectionTests(unittest.TestCase):
    def test_disposable_snapshot_includes_working_changes(self) -> None:
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
                'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}):
            root, destination = Path(source), Path(directory)
            (root / 'module.py').write_text('original')
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'add', 'module.py'], cwd=root, check=True)
            (root / 'module.py').write_text('edited')
            (root / 'new.py').write_text('new module')
            first = snapshot(root, destination)
            self.assertEqual((destination / 'module.py').read_text(), 'edited')
            self.assertEqual((destination / 'new.py').read_text(), 'new module')
            (root / 'module.py').write_text('second edit')
            self.assertNotEqual(snapshot(root, destination), first)
