from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Literal, Mapping, cast


Status = Literal['killed', 'survived', 'timeout', 'invalid']


def record(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError('expected an object with string keys')
    return cast(dict[str, object], value)


def sequence(value: object) -> list[object]:
    if not isinstance(value, list):
        raise ValueError('expected an array')
    return cast(list[object], value)


def text(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError('expected nonempty text')
    return value


def integer(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError('expected a nonnegative integer')
    return value


@dataclass(frozen=True)
class Outcome:
    identity: str
    status: Status
    evidence: str


@dataclass(frozen=True)
class Report:
    group: str
    revision: str
    tool_version: str
    reason: str
    expected: tuple[str, ...]
    outcomes: tuple[Outcome, ...]
    baseline: bool
    complete: bool


@dataclass(frozen=True)
class Exclusion:
    group: str
    revision: str
    identity: str
    evidence: str


@dataclass(frozen=True)
class Score:
    group: str
    killed: int
    eligible: int
    invalid: int
    equivalent: int
    survivors: tuple[str, ...]
    timeouts: tuple[str, ...]
    reason: str
    source_revision: str
    exclusions: tuple[Exclusion, ...]

    @property
    def passed(self) -> bool:
        return self.eligible == 0 or self.killed * 10 > self.eligible * 9


def score(report: Report, exclusions: tuple[Exclusion, ...] = ()) -> Score:
    for required in (report.group, report.revision, report.tool_version, report.reason):
        text(required)
    if not report.baseline or not report.complete:
        raise ValueError(f'{report.group} has an unsuccessful baseline or unfinished run')
    identities = tuple(outcome.identity for outcome in report.outcomes)
    if (len(set(report.expected)) != len(report.expected)
            or len(set(identities)) != len(identities) or set(identities) != set(report.expected)):
        raise ValueError(f'{report.group} has missing, duplicate or unexpected results')
    source_revision = text(report.revision.rsplit(' tree ', 1)[-1])
    relevant = tuple(exclusion for exclusion in exclusions
                     if exclusion.group == report.group and exclusion.revision == source_revision)
    excluded = {exclusion.identity for exclusion in relevant}
    if len(excluded) != len(relevant) or not excluded <= set(identities):
        raise ValueError('duplicate or unknown equivalent mutant')
    for exclusion in relevant:
        text(exclusion.evidence)
    for outcome in report.outcomes:
        text(outcome.identity)
        text(outcome.evidence)
        if outcome.status not in ('killed', 'survived', 'timeout', 'invalid'):
            raise ValueError('unknown mutation outcome')
        if outcome.identity in excluded and outcome.status != 'survived':
            raise ValueError('only a reviewed surviving mutant may be equivalent')
    eligible = tuple(outcome for outcome in report.outcomes
                     if outcome.status != 'invalid' and outcome.identity not in excluded)
    return Score(
        report.group, sum(outcome.status == 'killed' for outcome in eligible), len(eligible),
        sum(outcome.status == 'invalid' for outcome in report.outcomes), len(excluded),
        tuple(outcome.identity for outcome in eligible if outcome.status == 'survived'),
        tuple(outcome.identity for outcome in eligible if outcome.status == 'timeout'), report.reason,
        source_revision, relevant,
    )


def rust_phases(raw: object) -> tuple[dict[str, object], ...]:
    phases = tuple(record(phase) for phase in sequence(raw))
    names = tuple(phase.get('phase') for phase in phases)
    if names not in (('Build',), ('Test',), ('Build', 'Test')):
        raise ValueError('cargo-mutants has inconsistent execution phases')
    if any(phase.get('process_status') != 'Success' for phase in phases[:-1]):
        raise ValueError('cargo-mutants continued after an unsuccessful phase')
    return phases


def rust_results(inventory: object, raw: object, logs: Mapping[str, str]) -> tuple[Outcome, ...]:
    expected = tuple(text(record(mutant).get('name')) for mutant in sequence(inventory))
    report = record(raw)
    if not report.get('end_time'):
        raise ValueError('cargo-mutants did not finish')
    outcomes = tuple(record(outcome) for outcome in sequence(report.get('outcomes')))
    baselines = tuple(outcome for outcome in outcomes if outcome.get('scenario') == 'Baseline')
    if len(baselines) != 1 or baselines[0].get('summary') != 'Success':
        raise ValueError('cargo-mutants baseline failed or is missing')
    baseline_phases = rust_phases(baselines[0].get('phase_results'))
    if (baseline_phases[-1].get('phase') != 'Test'
            or baseline_phases[-1].get('process_status') != 'Success'):
        raise ValueError('cargo-mutants baseline did not successfully run tests')
    results = tuple(rust_outcome(outcome, logs) for outcome in outcomes if outcome not in baselines)
    if integer(report.get('total_mutants')) != len(expected) or set(expected) != {r.identity for r in results}:
        raise ValueError('cargo-mutants did not run every discovered mutant')
    return results


def rust_outcome(outcome: dict[str, object], logs: Mapping[str, str]) -> Outcome:
    mutant = record(record(outcome.get('scenario')).get('Mutant'))
    identity = text(mutant.get('name'))
    log_path = text(outcome.get('log_path'))
    phases = rust_phases(outcome.get('phase_results'))
    last = phases[-1]
    summary = outcome.get('summary')
    match summary:
        case 'CaughtMutant' | 'MissedMutant':
            status: Status = 'killed' if summary == 'CaughtMutant' else 'survived'
            expected_exit: object = {'Failure': 101} if status == 'killed' else 'Success'
            if last.get('phase') != 'Test' or last.get('process_status') != expected_exit:
                raise ValueError('cargo-mutants test phase failed unexpectedly')
        case 'Timeout':
            if last.get('process_status') != 'Timeout':
                raise ValueError('cargo-mutants timeout has no evidence')
            status = 'timeout'
        case 'Unviable':
            log = logs.get(log_path, '')
            if (last.get('phase') != 'Build' or last.get('process_status') != {'Failure': 101}
                    or not re.search(r'error(?:\[E\d{4}\]|: expected)', log)
                    or 'could not compile' not in log):
                raise ValueError('build failure is not a confirmed compilation-invalid mutant')
            status = 'invalid'
        case _:
            raise ValueError('cargo-mutants has an unclassified result')
    return Outcome(identity, status, log_path)


def cosmic_results(raw: object) -> tuple[Outcome, ...]:
    return tuple(cosmic_outcome(sequence(row)) for row in sequence(raw))


def cosmic_identity(raw: object) -> str:
    item = record(raw)
    mutations = tuple(record(value) for value in sequence(item.get('mutations')))
    if len(mutations) != 1:
        raise ValueError('expected one mutation per Cosmic Ray job')
    mutation = mutations[0]
    path = text(mutation.get('module_path'))
    operator = text(mutation.get('operator_name'))
    occurrence = integer(mutation.get('occurrence'))
    start = tuple(integer(value) for value in sequence(mutation.get('start_pos')))
    end = tuple(integer(value) for value in sequence(mutation.get('end_pos')))
    if len(start) != 2 or len(end) != 2 or start >= end:
        raise ValueError('invalid Cosmic Ray source span')
    arguments = record(mutation.get('operator_args'))
    return json.dumps((path, operator, occurrence, start, end, arguments), sort_keys=True)


def cosmic_outcome(row: list[object]) -> Outcome:
    if len(row) != 2:
        raise ValueError('invalid Cosmic Ray work item')
    item, result = record(row[0]), record(row[1])
    identity = cosmic_identity(item)
    status, evidence = cosmic_test_result(result)
    return Outcome(identity, status, evidence)


def cosmic_baseline(raw: object) -> None:
    rows = sequence(raw)
    if len(rows) != 1:
        raise ValueError('Cosmic Ray baseline must have exactly one result')
    row = sequence(rows[0])
    if len(row) != 2 or sequence(record(row[0]).get('mutations')):
        raise ValueError('Cosmic Ray baseline contains mutations or is incomplete')
    status, _ = cosmic_test_result(record(row[1]))
    if status != 'survived':
        raise ValueError('Cosmic Ray baseline did not execute successful tests')


def cosmic_test_result(result: dict[str, object]) -> tuple[Status, str]:
    if result.get('worker_outcome') != 'normal':
        raise ValueError('Cosmic Ray worker did not complete normally')
    output = text(result.get('output'))
    if output == 'timeout':
        if result.get('test_outcome') != 'killed':
            raise ValueError('Cosmic Ray timeout has contradictory test status')
        return 'timeout', output
    markers = tuple(line.removeprefix('MUTATION_RESULT ') for line in output.splitlines()
                    if line.startswith('MUTATION_RESULT '))
    if len(markers) != 1:
        raise ValueError('Cosmic Ray test execution evidence is missing')
    evidence = record(json.loads(markers[0]))
    if evidence.get('kind') == 'syntax_error' and result.get('test_outcome') == 'killed':
        return 'invalid', text(evidence.get('message'))
    if evidence.get('kind') != 'tests' or integer(evidence.get('run')) == 0:
        raise ValueError('Cosmic Ray did not execute tests')
    failures = integer(evidence.get('failures')) + integer(evidence.get('errors'))
    status: Status = 'killed' if failures else 'survived'
    if result.get('test_outcome') != status:
        raise ValueError('Cosmic Ray outcome disagrees with test evidence')
    return status, output


def parse_report(raw: object) -> Report:
    value = record(raw)
    outcomes = tuple(parse_outcome(outcome) for outcome in sequence(value.get('outcomes')))
    if type(value.get('baseline')) is not bool or type(value.get('complete')) is not bool:
        raise ValueError('report is missing completion evidence')
    return Report(text(value.get('group')), text(value.get('revision')), text(value.get('tool_version')),
                  text(value.get('reason')), tuple(text(item) for item in sequence(value.get('expected'))),
                  outcomes, value['baseline'] is True, value['complete'] is True)


def parse_outcome(raw: object) -> Outcome:
    value = record(raw)
    status = value.get('status')
    if status not in ('killed', 'survived', 'timeout', 'invalid'):
        raise ValueError('unknown mutation status')
    return Outcome(text(value.get('identity')), cast(Status, status), text(value.get('evidence')))
