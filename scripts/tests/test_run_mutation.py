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
from mutation_results import Exclusion, Outcome, Report, parse_report, score
from mutation_scope import Target
from run_mutation import check, merge_reports, seed_proofs, snapshot


def measurement(value: Report, target: Target, platform: str = 'Linux',
                shard: int = 1, shards: int = 1) -> dict[str, object]:
    return dict(platform=platform, profile='all', shard=shard, shards=shards,
                report=asdict(value), target=asdict(target))


class MutationScoreTests(unittest.TestCase):
    def test_seed_proofs_require_complete_direct_workspace_execution(self) -> None:
        value = report(1, 3)
        target = Target(value.group, 'rust', (), value.reason)
        with tempfile.TemporaryDirectory() as directory:
            paths = tuple(Path(directory) / f'{shard}.json' for shard in (1, 2))
            for index, path in enumerate(paths):
                partial = replace(value, outcomes=value.outcomes[index::2])
                path.write_text(json.dumps(measurement(partial, target, platform='ubuntu-24.04',
                                                      shard=index + 1, shards=2) | {'workspace_baseline': True}))
            proofs = seed_proofs((target,), paths, 2, value.revision, value.tool_version)
            measured = parse_report(json.loads(json.dumps(proofs[target.group]))['report'])
            self.assertEqual({outcome.identity: outcome.status for outcome in measured.outcomes},
                             {'0': 'killed', '1': 'survived', '2': 'survived', '3': 'survived'})
            self.assertEqual((score(measured).killed, score(measured).eligible), (1, 4))
            self.assertEqual(proofs[target.group]['target'], asdict(target))
            self.assertEqual(proofs[target.group]['schema'], 'packetcraftr.mutation-seed/v1')
            self.assertFalse(score(value).passed)
            with self.assertRaises(ValueError):
                seed_proofs((target,), paths[:1], 2, value.revision, value.tool_version)
            second = json.loads(paths[1].read_text())
            for invalid in (None, False, 'true'):
                paths[1].write_text(json.dumps(second | {'workspace_baseline': invalid}))
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    seed_proofs((target,), paths, 2, value.revision, value.tool_version)
            paths[1].write_text(json.dumps(second | {'reused_kills': ['0']}))
            with self.assertRaisesRegex(ValueError, 'direct execution'):
                seed_proofs((target,), paths, 2, value.revision, value.tool_version)
            for nested in (
                second['report'] | {'reused_kills': ['1']},
                second['report'] | {'outcomes': [second['report']['outcomes'][0] | {'donor': 'other-context'}]},
            ):
                paths[1].write_text(json.dumps(second | {'report': nested}))
                with self.subTest(nested=nested), self.assertRaises(ValueError):
                    seed_proofs((target,), paths, 2, value.revision, value.tool_version)
            paths[1].write_text(json.dumps(second | {'target': second['target'] | {'donor': 'other-context'}}))
            with self.assertRaises(ValueError):
                seed_proofs((target,), paths, 2, value.revision, value.tool_version)
            duplicate = json.dumps(second).replace('"workspace_baseline": true',
                                                   '"workspace_baseline": false, "workspace_baseline": true')
            paths[1].write_text(duplicate)
            with self.assertRaises(ValueError):
                seed_proofs((target,), paths, 2, value.revision, value.tool_version)

    def test_published_scores_preserve_fractional_percentages_and_evidence_counts(self) -> None:
        original = report(20, 2)
        outcomes = (*original.outcomes[:-1], replace(original.outcomes[-1], status='timeout'),
                    Outcome('invalid-a', 'invalid', 'compiler error'), Outcome('invalid-b', 'invalid', 'compiler error'))
        value = replace(original, outcomes=outcomes, expected=tuple(outcome.identity for outcome in outcomes))
        target = Target(value.group, 'rust', (), value.reason)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'run.json'
            path.write_text(json.dumps(measurement(value, target)))
            output = io.StringIO()
            with redirect_stdout(output):
                passed = check((target,), (path,), 'rust', ('Linux',), ('all',), 1, (), value.revision, value.tool_version)
            published = json.loads(output.getvalue())
            self.assertTrue(passed)
            self.assertAlmostEqual(published['percentage'], 100 * 20 / 22)
            self.assertEqual((published['killed'], published['eligible'], published['invalid'], published['equivalent']),
                             (20, 22, 2, 0))
            self.assertEqual(published['survivors'], ['20'])
            self.assertEqual(published['timeouts'], ['21'])
            self.assertEqual(published['tool_versions'], [value.tool_version])
            self.assertEqual(published['status'], 'passed')

    def test_threshold_is_strict_and_applies_to_every_group(self) -> None:
        self.assertFalse(score(report()).passed)
        self.assertTrue(score(report(10)).passed)
        with tempfile.TemporaryDirectory() as directory:
            paths = tuple(Path(directory) / f'{group}.json' for group in ('strong', 'weak'))
            values = (report(99, 1, 'strong'), report(9, 1, 'weak'))
            targets = tuple(Target(value.group, 'rust', (), value.reason) for value in values)
            for path, value, target in zip(paths, values, targets):
                path.write_text(json.dumps(measurement(value, target)))
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
            path.write_text(json.dumps(measurement(value, Target('core', 'rust', (), value.reason))))
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
        target = (Target('core', 'rust', (), value.reason),)
        with tempfile.TemporaryDirectory() as directory:
            paths = tuple(Path(directory) / f'{i}.json' for i in (1, 2))
            for i, path in enumerate(paths):
                partial = replace(value, outcomes=value.outcomes[i::2])
                path.write_text(json.dumps(measurement(partial, target[0], shard=i + 1, shards=2)))
            self.assertTrue(check(target, paths, 'rust', ('Linux',), ('all',), 2, (), 'revision', 'version'))
            with self.assertRaises(ValueError):
                check(target, paths[:1], 'rust', ('Linux',), ('all',), 2, (), 'revision', 'version')
            with self.assertRaises(ValueError):
                check(target, (paths[0], paths[0]), 'rust', ('Linux',), ('all',), 2, (), 'revision', 'version')
            second = measurement(replace(value, outcomes=value.outcomes[1::2]), target[0], shard=2, shards=2)
            for field, invalid in (('shard', 0), ('shard', 3), ('shards', 1), ('shards', 3)):
                paths[1].write_text(json.dumps(second | {field: invalid}))
                with self.subTest(field=field, value=invalid), self.assertRaises(ValueError):
                    check(target, paths, 'rust', ('Linux',), ('all',), 2, (), 'revision', 'version')
            for inconsistent in (
                replace(value, outcomes=value.outcomes[1::2], expected=(*value.expected, 'unreported-mutant')),
                replace(value, outcomes=value.outcomes[1::2], baseline=False),
                replace(value, outcomes=value.outcomes[1::2], complete=False),
            ):
                paths[1].write_text(json.dumps(measurement(inconsistent, target[0], shard=2, shards=2)))
                with self.subTest(report=inconsistent), self.assertRaises(ValueError):
                    check(target, paths, 'rust', ('Linux',), ('all',), 2, (), 'revision', 'version')

    def test_reports_from_another_revision_or_tool_cannot_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'run.json'
            value = report(10, 0)
            target = Target('core', 'rust', (), value.reason)
            path.write_text(json.dumps(measurement(value, target)))
            for revision, version in (('other', 'version'), ('revision', 'other')):
                with self.subTest(revision=revision, version=version), self.assertRaises(ValueError):
                    check((target,), (path,), 'rust', ('Linux',), ('all',),
                          1, (), revision, version)

    def test_platform_and_profile_cohorts_combine_only_their_own_shards(self) -> None:
        value = report(0, 4)
        target = Target(value.group, 'rust', (), value.reason)
        platforms, profiles = ('Linux', 'Windows'), ('all', 'portable')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = tuple(root / f'{platform}-{profile}-{shard}.json'
                          for platform in platforms for profile in profiles for shard in (1, 2))
            for index, (platform, profile) in enumerate((platform, profile)
                    for platform in platforms for profile in profiles):
                outcomes = tuple(replace(outcome, status='killed' if number == index else 'survived')
                                 for number, outcome in enumerate(value.outcomes))
                for shard in (1, 2):
                    partial = replace(value, outcomes=outcomes[shard - 1::2])
                    (root / f'{platform}-{profile}-{shard}.json').write_text(json.dumps(
                        measurement(partial, target, platform=platform, shard=shard, shards=2)
                        | {'profile': profile}))
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertTrue(check((target,), paths, 'rust', platforms, profiles, 2, (), 'revision', 'version'))
            summary = json.loads(output.getvalue())
            self.assertEqual((summary['killed'], summary['eligible']), (4, 4))
            foreign = root / 'foreign.json'
            for changed in ({'platform': 'FreeBSD'}, {'profile': 'unknown'}):
                foreign.write_text(json.dumps(measurement(value, target) | changed))
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    check((target,), (*paths, foreign), 'rust', platforms, profiles, 2, (), 'revision', 'version')

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

    def test_artifacts_cannot_replace_a_full_or_different_file_selection(self) -> None:
        first = Target('core', 'rust', ('crates/core/src/first.rs',), 'changed production files')
        value = replace(report(10, 0), reason=first.reason)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'run.json'
            path.write_text(json.dumps(measurement(value, first)))
            self.assertTrue(check((first,), (path,), 'rust', ('Linux',), ('all',), 1, (), 'revision', 'version'))
            for target in (replace(first, files=()), replace(first, files=('crates/core/src/second.rs',)),
                           replace(first, reason='full crate, tests or shared inputs changed')):
                with self.subTest(target=target), self.assertRaises(ValueError):
                    check((target,), (path,), 'rust', ('Linux',), ('all',), 1, (), 'revision', 'version')
            with self.assertRaises(ValueError):
                check((first, replace(first, files=('crates/core/src/second.rs',))), (path,),
                      'rust', ('Linux',), ('all',), 1, (), 'revision', 'version')
            raw = measurement(value, first)
            for invalid_target in (None, asdict(replace(first, language='python'))):
                path.write_text(json.dumps(raw | {'target': invalid_target}))
                with self.subTest(target=invalid_target), self.assertRaises(ValueError):
                    check((first,), (path,), 'rust', ('Linux',), ('all',), 1, (), 'revision', 'version')


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
            target = Target(group, 'python', (group,), value.reason)
            artifacts = root / 'artifacts'
            artifacts.mkdir()
            (artifacts / 'run.json').write_text(json.dumps(measurement(value, target, platform=sys.platform)))
            plan = Path(directory) / 'plan.json'
            plan.write_text(json.dumps([asdict(target)]))
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
            (artifacts / 'run.json').write_text(json.dumps(measurement(value, target, platform=sys.platform)))
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
            early = root / '.config/aaa.toml'
            early.parent.mkdir()
            early.write_text('value=1\n')
            subprocess.run(['git', 'add', '.config/aaa.toml'], cwd=root, check=True)
            first = snapshot(root, destination)
            self.assertEqual((destination / 'module.py').read_text(), 'edited')
            self.assertEqual((destination / 'new.py').read_text(), 'new module')
            early.write_text('value=2\n')
            self.assertNotEqual(snapshot(root, destination), first)
            (root / 'module.py').unlink()
            with tempfile.TemporaryDirectory() as fresh:
                snapshot(root, Path(fresh))
                self.assertEqual((Path(fresh) / 'new.py').read_text(), 'new module')
            (root / 'module.py').write_text('edited')
            unchanged_module = snapshot(root, destination)
            (root / 'module.py').write_text('second edit')
            self.assertNotEqual(snapshot(root, destination), unchanged_module)
