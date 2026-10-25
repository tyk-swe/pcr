from __future__ import annotations

from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from support import ROOT
from mutation_results import (Exclusion, Outcome, Report, cosmic_identity, cosmic_results, parse_report,
                              rust_results, score)
from mutation_scope import Change, Target, changes_since, select
from run_mutation import check, merge_reports, snapshot


def report(killed: int = 9, survived: int = 1, group: str = 'core') -> Report:
    outcomes = tuple(Outcome(str(i), 'killed' if i < killed else 'survived', 'test result')
                     for i in range(killed + survived))
    return Report(group, 'revision', 'version', 'changed production',
                  tuple(outcome.identity for outcome in outcomes), outcomes, True, True)


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

    def test_missing_duplicate_and_unfinished_results_fail_closed(self) -> None:
        value = report(10)
        for invalid in (replace(value, baseline=False), replace(value, complete=False),
                        replace(value, outcomes=value.outcomes[:-1]),
                        replace(value, outcomes=value.outcomes + value.outcomes[:1]),
                        replace(value, expected=value.expected + value.expected[:1]),
                        replace(value, reason=''), replace(value, tool_version='')):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                score(invalid)
        with self.assertRaises(ValueError):
            parse_report({'group': 'core'})

    def test_timeouts_stay_in_the_denominator(self) -> None:
        value = report()
        value = replace(value, outcomes=value.outcomes[:-1] + (Outcome('9', 'timeout', 'timeout'),))
        result = score(value)
        self.assertFalse(result.passed)
        self.assertEqual((result.killed, result.eligible, result.timeouts), (9, 10, ('9',)))

    def test_only_evidenced_equivalents_and_invalid_compilations_are_excluded(self) -> None:
        value = report()
        exclusion = Exclusion(value.group, value.revision, '9', 'expression is identical for all inputs')
        self.assertTrue(score(value, (exclusion,)).passed)
        self.assertFalse(score(value, (replace(exclusion, revision='old'),)).passed)
        for invalid in (replace(exclusion, evidence=''), replace(exclusion, identity='missing'),
                        replace(exclusion, identity='0')):
            with self.assertRaises(ValueError):
                score(value, (invalid,))
        invalid = replace(value, outcomes=value.outcomes[:-1] + (Outcome('9', 'invalid', 'compiler error'),))
        self.assertEqual(score(invalid).eligible, 9)

    def test_empty_selection_is_reported_with_its_reason(self) -> None:
        result = score(report(0, 0))
        self.assertEqual(result.eligible, 0)
        self.assertEqual(result.reason, 'changed production')

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

    def test_cosmic_ray_requires_actual_completed_test_results(self) -> None:
        evidence = 'MUTATION_RESULT ' + json.dumps(dict(kind='tests', run=3, failures=1, errors=0))
        item = dict(job_id='job', mutations=[dict(module_path='module.py', operator_name='replace',
                                                occurrence=0, start_pos=[1, 0], end_pos=[1, 1],
                                                operator_args={})])
        row: list[object] = [item, dict(worker_outcome='normal', test_outcome='killed', output=evidence)]
        self.assertEqual(cosmic_results([row])[0].status, 'killed')
        for result in (None, dict(worker_outcome='exception'),
                       dict(worker_outcome='normal', test_outcome='killed', output='runner crashed'),
                       dict(worker_outcome='normal', test_outcome='survived', output=evidence)):
            with self.subTest(result=result), self.assertRaises(ValueError):
                cosmic_results([[item, result]])
        timeout = dict(worker_outcome='normal', test_outcome='killed', output='timeout')
        self.assertEqual(cosmic_results([[item, timeout]])[0].status, 'timeout')

    def test_python_mutant_identity_survives_a_new_session(self) -> None:
        mutation = dict(module_path='module.py', operator_name='replace', occurrence=0,
                        start_pos=[1, 0], end_pos=[1, 1], operator_args={})
        first = cosmic_identity(dict(job_id='first', mutations=[mutation]))
        self.assertEqual(first, cosmic_identity(dict(job_id='second', mutations=[mutation])))
        for change in (dict(module_path='other.py'), dict(operator_name='remove'),
                       dict(occurrence=1), dict(start_pos=[0, 0]), dict(operator_args={'value': 1})):
            with self.subTest(change=change):
                self.assertNotEqual(first, cosmic_identity(dict(job_id='first', mutations=[mutation | change])))

    def test_rust_inventory_and_baseline_are_required(self) -> None:
        mutant = dict(name='mutation')
        outcome = dict(scenario=dict(Mutant=mutant), summary='CaughtMutant', log_path='log',
                       phase_results=[dict(phase='Test', process_status={'Failure': 101})])
        raw = dict(end_time='finished', total_mutants=1,
                   outcomes=[dict(scenario='Baseline', summary='Success',
                                  phase_results=[dict(phase='Test', process_status='Success')]), outcome])
        self.assertEqual(rust_results([mutant], raw, {})[0].status, 'killed')
        for invalid in ({**raw, 'end_time': None}, {**raw, 'outcomes': [outcome]},
                        {**raw, 'total_mutants': 0}):
            with self.assertRaises(ValueError):
                rust_results([mutant], invalid, {})
        outcome['summary'] = 'Unviable'
        outcome['phase_results'] = [dict(phase='Build', process_status={'Failure': 101})]
        with self.assertRaises(ValueError):
            rust_results([mutant], raw, {'log': 'network failed'})
        self.assertEqual(rust_results([mutant], raw, {'log': 'error[E0308]: could not compile'})[0].status,
                         'invalid')


class MutationSelectionTests(unittest.TestCase):
    def test_committed_test_deletions_schedule_their_owners(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for folder in ('crates/sample/src', '.config', 'scripts/tests'):
                (root / folder).mkdir(parents=True)
            (root / 'crates/sample/Cargo.toml').write_text('[package]\nname="sample"\n')
            (root / 'crates/sample/src/lib.rs').write_text('pub fn value() -> u8 { 1 }\n')
            (root / 'crates/sample/src/tests.rs').write_text('#[test]\nfn protects_value() { assert_eq!(crate::value(), 1); }\n')
            (root / 'scripts/alpha.py').write_text('value = 1\n')
            (root / 'scripts/tests/test_alpha.py').write_text('from alpha import value\ndef test_value(): assert value == 1\n')
            (root / '.config/mutation.toml').write_text(
                '[python.modules]\n"scripts/alpha.py" = ["scripts/tests/test_alpha.py"]\n')
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            commit = ['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.test', 'commit', '-qm']
            subprocess.run([*commit, 'initial'], cwd=root, check=True)
            base = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
            (root / 'crates/sample/src/tests.rs').unlink()
            (root / 'scripts/tests/test_alpha.py').unlink()
            subprocess.run(['git', 'add', '-u'], cwd=root, check=True)
            subprocess.run([*commit, 'delete tests'], cwd=root, check=True)
            selected = select(root, changes_since(root, base))
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

    def test_disposable_snapshot_includes_working_changes(self) -> None:
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as directory:
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
