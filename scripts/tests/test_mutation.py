from __future__ import annotations

from dataclasses import asdict, replace
from contextlib import redirect_stdout
import io
from itertools import product
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

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


class MutationScoreTests(unittest.TestCase):
    def test_outcome_counts_and_evidenced_exclusions_keep_their_own_groups(self) -> None:
        outcomes = (Outcome('caught', 'killed', 'test failed'),
                    Outcome('missed', 'survived', 'test passed'),
                    Outcome('equivalent', 'survived', 'test passed'),
                    Outcome('timed', 'timeout', 'timeout'),
                    Outcome('invalid', 'invalid', 'compiler diagnostic'))
        value = replace(report(), expected=tuple(outcome.identity for outcome in outcomes), outcomes=outcomes)
        result = score(value)
        self.assertEqual((result.killed, result.eligible, result.invalid, result.equivalent), (1, 4, 1, 0))
        self.assertEqual(result.survivors, ('missed', 'equivalent'))
        self.assertEqual(result.timeouts, ('timed',))
        self.assertFalse(result.passed)
        exclusion = Exclusion(value.group, value.revision, 'equivalent', 'same observable result for every input')
        reviewed = score(value, (exclusion,))
        self.assertEqual((reviewed.killed, reviewed.eligible, reviewed.invalid, reviewed.equivalent), (1, 3, 1, 1))
        self.assertEqual(reviewed.survivors, ('missed',))
        self.assertEqual(reviewed.timeouts, ('timed',))
        for unrelated in (replace(exclusion, group='a'), replace(exclusion, group='z'),
                          replace(exclusion, revision='a'), replace(exclusion, revision='z')):
            with self.subTest(unrelated=unrelated):
                self.assertEqual(score(value, (unrelated,)), result)
        for invalid in ((exclusion, exclusion), (replace(exclusion, identity='timed'),),
                        (replace(exclusion, identity='invalid'),)):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                score(value, invalid)

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

    def test_artifact_parser_preserves_false_completion_and_rejects_invalid_values(self) -> None:
        raw = json.loads(json.dumps(asdict(report(2, 0))))
        parsed = parse_report(raw)
        self.assertEqual((score(parsed).killed, score(parsed).eligible), (2, 2))
        for flag in ('baseline', 'complete'):
            unfinished = parse_report(raw | {flag: False})
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                score(unfinished)
        missing = tuple({key: value for key, value in raw.items() if key != name} for name in raw)
        invalid_flags = tuple(raw | {name: invalid} for name, invalid in product(
            ('baseline', 'complete'), (None, 0, 1, 'true')))
        invalid_text = tuple(raw | {name: invalid} for name, invalid in product(
            ('group', 'revision', 'tool_version', 'reason'), (None, '', ' ', 1)))
        invalid_results = tuple(raw | {'outcomes': [raw['outcomes'][0] | {name: invalid}]} for name, invalid in (
            ('identity', ''), ('status', 'unknown'), ('evidence', ''), ('evidence', None)))
        for invalid in (None, [], 1, raw | {'expected': [None]}, raw | {'outcomes': [None]},
                        *missing, *invalid_flags, *invalid_text, *invalid_results):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse_report(invalid)

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
    def test_cosmic_ray_classifies_failures_errors_and_invalid_syntax_independently(self) -> None:
        item = dict(job_id='job', mutations=[dict(module_path='module.py', operator_name='replace',
                                                occurrence=0, start_pos=[1, 0], end_pos=[1, 1],
                                                operator_args={})])
        for failures, errors, status in ((0, 0, 'survived'), (1, 0, 'killed'), (0, 1, 'killed'),
                                        (1, 1, 'killed'), (2, 1, 'killed'), (1, 2, 'killed')):
            output = 'MUTATION_RESULT ' + json.dumps(dict(kind='tests', run=3, failures=failures, errors=errors))
            result = dict(worker_outcome='normal', test_outcome=status, output=output)
            with self.subTest(failures=failures, errors=errors):
                outcome = cosmic_results([[item, result]])[0]
                self.assertEqual(outcome.status, status)
                self.assertEqual(outcome.evidence, output)
                with self.assertRaises(ValueError):
                    cosmic_results([[item, result | {'test_outcome': 'killed' if status == 'survived' else 'survived'}]])
        for name, invalid in product(('run', 'failures', 'errors'), (None, True, -1, 1.5, '1')):
            evidence = dict(kind='tests', run=3, failures=1, errors=0) | {name: invalid}
            result = dict(worker_outcome='normal', test_outcome='killed',
                          output='MUTATION_RESULT ' + json.dumps(evidence))
            with self.subTest(name=name, invalid=invalid), self.assertRaises(ValueError):
                cosmic_results([[item, result]])
        syntax = dict(worker_outcome='normal', test_outcome='killed', output='MUTATION_RESULT ' +
                      json.dumps(dict(kind='syntax_error', message='controlled invalid syntax')))
        self.assertEqual(cosmic_results([[item, syntax]])[0].status, 'invalid')
        for invalid in (syntax | {'test_outcome': 'survived'}, syntax | {'worker_outcome': 'exception'},
                        syntax | {'output': syntax['output'] + '\n' + syntax['output']},
                        syntax | {'output': 'MUTATION_RESULT ' + json.dumps(dict(kind='tests', run=0, failures=0, errors=0))}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                cosmic_results([[item, invalid]])

    def test_rust_survival_timeout_and_compilation_failure_are_distinct(self) -> None:
        # https://github.com/sourcefrog/cargo-mutants/blob/v27.1.0/src/outcome.rs, checked 2026-10-25.
        mutant = dict(name='mutation')
        baseline = dict(scenario='Baseline', summary='Success', phase_results=[
            dict(phase='Build', process_status='Success'), dict(phase='Test', process_status='Success')])
        cases = (('CaughtMutant', 'Test', {'Failure': 101}, 'killed'),
                 ('MissedMutant', 'Test', 'Success', 'survived'),
                 ('Timeout', 'Test', 'Timeout', 'timeout'),
                 ('Unviable', 'Build', {'Failure': 101}, 'invalid'))
        for summary, phase, process, expected in cases:
            outcome = dict(scenario=dict(Mutant=mutant), summary=summary, log_path='mutant.log',
                           phase_results=[dict(phase='Build', process_status='Success'),
                                          dict(phase=phase, process_status=process)])
            raw = dict(end_time='finished', total_mutants=1, outcomes=[baseline, outcome])
            logs = {'mutant.log': 'error[E0308]: mismatched types\nerror: could not compile sample'}
            with self.subTest(summary=summary):
                result = rust_results([mutant], raw, logs)[0]
                self.assertEqual((result.identity, result.status, result.evidence), ('mutation', expected, 'mutant.log'))
                invalid_phases = ((phase, 'Success'),) if summary == 'Timeout' else (('Check', process),)
                for bad_phase, bad_process in (*invalid_phases, (phase, {'Failure': 13})):
                    invalid = dict(outcome, phase_results=[dict(phase=bad_phase, process_status=bad_process)])
                    with self.assertRaises(ValueError):
                        rust_results([mutant], raw | {'outcomes': [baseline, invalid]}, logs)
        for log in ('error[E0308]: mismatched types', 'could not compile sample', 'network failed'):
            with self.subTest(log=log), self.assertRaises(ValueError):
                rust_results([mutant], raw, {'mutant.log': log})
        self.assertEqual(rust_results([mutant], raw, {'mutant.log': 'error: expected expression\ncould not compile sample'})[0].status,
                         'invalid')

    def test_rust_baseline_requires_successful_test_execution(self) -> None:
        mutant = dict(name='mutation')
        outcome = dict(scenario=dict(Mutant=mutant), summary='MissedMutant', log_path='mutant.log',
                       phase_results=[dict(phase='Test', process_status='Success')])
        baseline = dict(scenario='Baseline', summary='Success', phase_results=[dict(phase='Test', process_status='Success')])
        raw = dict(end_time='finished', total_mutants=1, outcomes=[baseline, outcome])
        self.assertEqual(rust_results([mutant], raw, {})[0].status, 'survived')
        for phases in ([], [dict(phase='Build', process_status='Success')],
                       [dict(phase='Test', process_status={'Failure': 101})],
                       [dict(phase='Build', process_status={'Failure': 101}), dict(phase='Test', process_status='Success')]):
            invalid = baseline | {'phase_results': phases}
            with self.subTest(phases=phases), self.assertRaises(ValueError):
                rust_results([mutant], raw | {'outcomes': [invalid, outcome]}, {})
        for outcomes in ([baseline, baseline, outcome], [outcome], [baseline, outcome | {'summary': 'Success'}]):
            with self.subTest(outcomes=outcomes), self.assertRaises(ValueError):
                rust_results([mutant], raw | {'outcomes': outcomes}, {})

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
                       dict(occurrence=1), dict(start_pos=[0, 0]), dict(end_pos=[1, 2]), dict(operator_args={'value': 1})):
            with self.subTest(change=change):
                self.assertNotEqual(first, cosmic_identity(dict(job_id='first', mutations=[mutation | change])))
        for change in (dict(module_path=''), dict(operator_name=''), dict(occurrence=-1), dict(occurrence=True),
                       dict(start_pos=[-1, 0]), dict(start_pos=[True, 0]), dict(start_pos=[1]),
                       dict(end_pos=[1, 0]), dict(end_pos=[0, 1]), dict(end_pos=[1, 1, 0]), dict(operator_args=[])):
            with self.subTest(change=change), self.assertRaises(ValueError):
                cosmic_identity(dict(job_id='first', mutations=[mutation | change]))
        for mutations in ([], [mutation, mutation]):
            with self.subTest(mutations=mutations), self.assertRaises(ValueError):
                cosmic_identity(dict(job_id='first', mutations=mutations))

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
            self.assertEqual({target.group for target in select(root, (), full=True)}, rust | python)
            for path, expected in cases:
                targets = select(root, (Change(path),))
                with self.subTest(path=path):
                    self.assertEqual({target.group for target in targets}, expected)
                    self.assertTrue(all(not target.files for target in targets if target.language == 'rust'))

    def test_malformed_ownership_cannot_silently_remove_production_modules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mutation_workspace(root)
            path = root / '.config/mutation.toml'
            original = path.read_text()
            for invalid in ('', '[python]\nmodules = []\n',
                            original.replace('["scripts/tests/test_alpha.py"]', '[]'),
                            original.replace('["scripts/tests/test_alpha.py"]', '[1]'),
                            original.replace('["scripts/tests/test_alpha.py"]', '[""]'),
                            original.replace('["scripts/tests/test_alpha.py"]', '[" "]'),
                            original.replace('scripts/alpha.py', 'scripts/absent.py')):
                path.write_text(invalid)
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    select(root, (), full=True)
            path.write_text(original)
            (root / 'scripts/unowned.py').write_text('value = 3\n')
            with self.assertRaises(ValueError):
                select(root, (), full=True)

    def test_committed_test_deletions_schedule_their_owners(self) -> None:
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
