# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from dataclasses import asdict, replace
from itertools import product
import json
import unittest

from support import report
from mutation_results import (Exclusion, Outcome, cosmic_baseline, cosmic_identity, cosmic_results, parse_report,
                              rust_results, score)


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
        compilation_invalid = replace(value, outcomes=value.outcomes[:-1] + (Outcome('9', 'invalid', 'compiler error'),))
        self.assertEqual(score(compilation_invalid).eligible, 9)

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


class MutationReportTests(unittest.TestCase):
    def test_cosmic_baseline_requires_successful_unmutated_test_evidence(self) -> None:
        item = dict(job_id='baseline', mutations=[])
        output = 'MUTATION_RESULT ' + json.dumps(dict(kind='tests', run=3, failures=0, errors=0))
        result = dict(worker_outcome='normal', test_outcome='survived', output=output)
        cosmic_baseline([[item, result]])
        rows: tuple[list[object], ...] = ([], [[item, result], [item, result]], [[item, None]],
                [[item | {'mutations': [dict(module_path='module.py')]}, result]],
                [[item, result | {'test_outcome': 'incompetent'}]],
                [[item, result | {'worker_outcome': 'exception'}]],
                [[item, result | {'test_outcome': 'killed', 'output': 'timeout'}]],
                [[item, result | {'output': 'MUTATION_RESULT ' + json.dumps(dict(kind='tests', run=0, failures=0, errors=0))}]],
                [[item, result | {'test_outcome': 'killed', 'output': 'MUTATION_RESULT ' +
                                 json.dumps(dict(kind='tests', run=3, failures=1, errors=0))}]],
                [[item, result | {'test_outcome': 'killed', 'output': 'MUTATION_RESULT ' +
                                 json.dumps(dict(kind='syntax_error', message='controlled syntax failure'))}]])
        for invalid in rows:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                cosmic_baseline(invalid)

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
        for invalid_result in (syntax | {'test_outcome': 'survived'}, syntax | {'worker_outcome': 'exception'},
                        syntax | {'output': syntax['output'] + '\n' + syntax['output']},
                        syntax | {'output': 'MUTATION_RESULT ' + json.dumps(dict(kind='tests', run=0, failures=0, errors=0))},
                        syntax | {'test_outcome': 'survived', 'output': 'MUTATION_RESULT ' +
                                  json.dumps(dict(kind='tests', run=0, failures=0, errors=0))},
                        syntax | {'test_outcome': 'incompetent'}):
            with self.subTest(invalid=invalid_result), self.assertRaises(ValueError):
                cosmic_results([[item, invalid_result]])
        for kind in ('runner_error', 'compile_error', 'unknown'):
            invalid_result = syntax | {'output': 'MUTATION_RESULT ' + json.dumps(dict(kind=kind, message='controlled failure'))}
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                cosmic_results([[item, invalid_result]])

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
        for status in (None, 'survived', 'incompetent'):
            with self.subTest(status=status), self.assertRaises(ValueError):
                cosmic_results([[item, timeout | {'test_outcome': status}]])

    def test_python_mutant_identity_survives_a_new_session(self) -> None:
        mutation = dict(module_path='module.py', operator_name='replace', occurrence=0,
                        start_pos=[1, 0], end_pos=[1, 1], operator_args={})
        first = cosmic_identity(dict(job_id='first', mutations=[mutation]))
        self.assertEqual(first, cosmic_identity(dict(job_id='second', mutations=[mutation])))
        for change in (dict(module_path='other.py'), dict(operator_name='remove'),
                       dict(occurrence=1), dict(start_pos=[0, 0]), dict(end_pos=[1, 2]), dict(operator_args={'value': 1})):
            with self.subTest(change=change):
                self.assertNotEqual(first, cosmic_identity(dict(job_id='first', mutations=[mutation | change])))
        for invalid_change in (dict(module_path=''), dict(operator_name=''), dict(occurrence=-1), dict(occurrence=True),
                       dict(start_pos=[-1, 0]), dict(start_pos=[True, 0]), dict(start_pos=[1]),
                       dict(end_pos=[1, 0]), dict(end_pos=[0, 1]), dict(end_pos=[1, 1, 0]),
                       dict(operator_args='invalid'), dict(operator_args=['invalid'])):
            with self.subTest(change=invalid_change), self.assertRaises(ValueError):
                cosmic_identity(dict(job_id='first', mutations=[mutation | invalid_change]))
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
