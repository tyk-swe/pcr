# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, replace
import hashlib
import json
import unittest

from support import ROOT
from mutation_results import Outcome, Report, record, score, sequence, text
from mutation_reuse import (ContextGroup, ContextPlan, Seed, context_shards, coverage_digest,
                            parse_context, parse_direct_report, parse_seed, partition_inventory, validate_coverage)
from mutation_scope import Target

TARGET = Target('packetcraftr-core', 'rust', ('crates/packetcraftr-core/src/lib.rs',), 'changed production files')
REVISION = 'a' * 40
SOURCE_DIGEST = 'b' * 64
TOOL_VERSION = '27.1.0'
REPORT = Report(TARGET.group, f'{REVISION} tree {SOURCE_DIGEST}', TOOL_VERSION, TARGET.reason,
                ('killed', 'survivor', 'timeout', 'invalid', 'equivalent'), (
                    Outcome('killed', 'killed', 'failed workspace test'),
                    Outcome('survivor', 'survived', 'successful workspace test'),
                    Outcome('timeout', 'timeout', 'test deadline exceeded'),
                    Outcome('invalid', 'invalid', 'compiler diagnostic'),
                    Outcome('equivalent', 'survived', 'reviewed equivalent, no actual kill'),
                ), True, True)


def receipt(report: Report = REPORT, target: Target = TARGET) -> dict[str, object]:
    return record(json.loads(json.dumps(dict(
        schema='packetcraftr.mutation-seed/v1', target=asdict(target), platform='ubuntu-24.04',
        profile='all', shard=1, shards=1, workspace_baseline=True, report=asdict(report),
    ))))


def encode(value: dict[str, object]) -> bytes:
    return json.dumps(value).encode()


def parse(data: bytes, *, target: Target = TARGET, revision: str = REVISION,
          source_digest: str = SOURCE_DIGEST, tool_version: str = TOOL_VERSION) -> Seed:
    return parse_seed(data, target=target, revision=revision, source_digest=source_digest, tool_version=tool_version)


def receiver_runs(data: bytes, inventory: tuple[str, ...]) -> tuple[tuple[dict[str, object], Report], ...]:
    plan = partition_inventory(parse(data), inventory)
    coverage: dict[str, object] = dict(inventory=list(inventory), reused_ids=list(plan.reused_ids),
                                      seed=data.decode('utf-8'))
    reports = tuple(replace(REPORT, expected=plan.executable_ids,
                           outcomes=tuple(Outcome(identity, 'killed', 'receiver test failure')
                                          for identity in plan.executable_ids[index::2])) for index in range(2))
    return tuple((dict(platform='windows-2022', profile='portable', shard=index + 1, shards=2,
                       target=asdict(TARGET), workspace_baseline=True, report=asdict(report),
                       coverage=coverage if index == 0 else None, coverage_digest=coverage_digest(coverage)), report)
                 for index, report in enumerate(reports))


def context_group(name: str, count: int, remaining: int) -> tuple[ContextGroup, Seed]:
    target = replace(TARGET, group=name, files=(f'crates/{name}/src/lib.rs',))
    inventory = tuple(f'{name}-{index}' for index in range(count))
    report = replace(REPORT, group=name, expected=inventory,
                     outcomes=tuple(Outcome(identity, 'killed' if index < count - remaining else 'survived',
                                            'controlled seed result') for index, identity in enumerate(inventory)))
    seed = parse(encode(receipt(report, target)), target=target)
    return ContextGroup(target, inventory, seed.donor_digest), seed


def context_value(groups: tuple[ContextGroup, ...], shards: int) -> dict[str, object]:
    return record(json.loads(json.dumps(dict(schema='packetcraftr.mutation-context/v1',
        platform='windows-2022', profile='portable', revision=REPORT.revision,
        tool_version=TOOL_VERSION, shards=shards, groups=[asdict(group) for group in groups]))))


def parse_plan(data: bytes, targets: tuple[Target, ...], seeds: Mapping[str, Seed], *,
               platform: str = 'windows-2022', profile: str = 'portable',
               revision: str = REPORT.revision, tool_version: str = TOOL_VERSION) -> ContextPlan:
    return parse_context(data, targets=targets, seeds=seeds, platform=platform, profile=profile,
                         revision=revision, tool_version=tool_version)


class MutationReuseTests(unittest.TestCase):
    def test_context_shards_choose_every_supported_count_without_increasing_work(self) -> None:
        cases = ((0, 1), (1, 1), (2, 4), (4, 4), (5, 8), (7, 8)) + tuple(
            (remaining, remaining) for remaining in range(8, 65, 4))
        for remaining, expected in cases:
            group, seed = context_group('core', 64, remaining)
            with self.subTest(remaining=remaining):
                self.assertEqual(context_shards((group,), {'core': seed}), expected)
        empty, seed = context_group('empty', 0, 0)
        self.assertEqual(context_shards((empty,), {'empty': seed}), 1)
        for count, expected in ((64, 64), (65, 36)):
            group, seed = context_group('boundary', count, count)
            with self.subTest(inventory=count):
                self.assertEqual(context_shards((group,), {'boundary': seed}), expected)

    def test_context_shards_preserve_the_largest_group_requirement(self) -> None:
        wide, wide_seed = context_group('wide', 512, 8)
        narrow, narrow_seed = context_group('narrow', 64, 13)
        empty, empty_seed = context_group('empty', 0, 0)
        self.assertEqual(context_shards((wide, empty, narrow),
                         {'wide': wide_seed, 'narrow': narrow_seed, 'empty': empty_seed}), 16)
        rounded, rounded_seed = context_group('rounded', 129, 12)
        self.assertEqual(context_shards((rounded,), {'rounded': rounded_seed}), 4)
        exact, exact_seed = context_group('exact', 128, 12)
        self.assertEqual(context_shards((exact,), {'exact': exact_seed}), 8)

    def test_context_plan_preserves_exact_groups_and_receiver_provenance(self) -> None:
        first, first_seed = context_group('first', 64, 4)
        second, second_seed = context_group('second', 128, 1)
        groups = (first, second)
        targets = (first.target, second.target, Target('scripts/other.py', 'python', (), 'other language'))
        seeds = {'first': first_seed, 'second': second_seed}
        for ordered in (groups, tuple(reversed(groups))):
            plan = parse_plan(encode(context_value(ordered, 4)), targets, seeds)
            self.assertEqual((plan.platform, plan.profile, plan.revision, plan.tool_version, plan.shards),
                             ('windows-2022', 'portable', REPORT.revision, TOOL_VERSION, 4))
            self.assertEqual({group.target.group: group for group in plan.groups},
                             {'first': first, 'second': second})

    def test_context_plan_requires_each_selected_group_once(self) -> None:
        first, first_seed = context_group('first', 64, 4)
        second, second_seed = context_group('second', 64, 1)
        targets = (first.target, second.target)
        seeds = {'first': first_seed, 'second': second_seed}
        for groups in ((), (first,), (first, first), (first, second, second)):
            with self.subTest(groups=groups), self.assertRaises(ValueError):
                parse_plan(encode(context_value(groups, 4)), targets, seeds)
        other, _ = context_group('other', 64, 1)
        with self.assertRaises(ValueError):
            parse_plan(encode(context_value((first, other), 4)), targets, seeds)
        with self.assertRaises(ValueError):
            parse_plan(encode(context_value((first,), 4)), (first.target, first.target), seeds)
        with self.assertRaises(ValueError):
            context_shards((first, first), seeds)

    def test_context_plan_rejects_changed_targets_and_seed_evidence(self) -> None:
        group, seed = context_group('core', 64, 4)
        value = context_value((group,), 4)
        raw_group = record(sequence(value['groups'])[0])
        raw_target = record(raw_group['target'])
        target_changes: tuple[dict[str, object], ...] = (
            {'group': 'a'}, {'group': 'z'}, {'language': 'python'}, {'files': []},
            {'files': ['crates/core/src/other.rs']}, {'reason': 'a'}, {'reason': 'z'}, {'donor': 'unexpected'},
        )
        for update in target_changes:
            changed = value | {'groups': [raw_group | {'target': raw_target | update}]}
            with self.subTest(update=update), self.assertRaises(ValueError):
                parse_plan(encode(changed), (group.target,), {'core': seed})
        for digest in ('0' * 64, 'f' * 64):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                parse_plan(encode(value | {'groups': [raw_group | {'seed_digest': digest}]}),
                           (group.target,), {'core': seed})
        with self.assertRaises(ValueError):
            parse_plan(encode(value), (group.target,), {})
        for changed_seed in (replace(seed, target=replace(group.target, reason='other')),
                             replace(seed, report=replace(seed.report, group='other')),
                             replace(seed, report=replace(seed.report, reason='other')),
                             replace(seed, report=replace(seed.report, revision='0' * 40 + ' tree ' + SOURCE_DIGEST)),
                             replace(seed, report=replace(seed.report, revision='c' * 40 + ' tree ' + SOURCE_DIGEST)),
                             replace(seed, report=replace(seed.report, tool_version='0')),
                             replace(seed, report=replace(seed.report, tool_version='other'))):
            with self.subTest(seed=changed_seed), self.assertRaises(ValueError):
                parse_plan(encode(value), (group.target,), {'core': changed_seed})

    def test_context_plan_rejects_wrong_context_source_or_tool(self) -> None:
        group, seed = context_group('core', 64, 4)
        value = context_value((group,), 4)
        for field, invalid in (('schema', 'packetcraftr.mutation-context/v0'),
                               ('schema', 'packetcraftr.mutation-context/v2'),
                               ('platform', 'ubuntu-24.04'), ('platform', 'z'),
                               ('profile', 'all'), ('profile', 'z'),
                               ('revision', '0' * 40 + ' tree ' + SOURCE_DIGEST),
                               ('revision', 'f' * 40 + ' tree ' + SOURCE_DIGEST),
                               ('revision', REVISION + ' tree ' + 'c' * 64),
                               ('tool_version', '0'), ('tool_version', 'z')):
            with self.subTest(field=field, value=invalid), self.assertRaises(ValueError):
                parse_plan(encode(value | {field: invalid}), (group.target,), {'core': seed})
        for invalid in ('short', 'a' * 40 + ' tree short'):
            with self.subTest(revision=invalid), self.assertRaises(ValueError):
                parse_plan(encode(value | {'revision': invalid}), (group.target,), {'core': seed}, revision=invalid)
        with self.assertRaises(ValueError):
            parse_plan(encode(value | {'platform': 'ubuntu-24.04', 'profile': 'all'}),
                       (group.target,), {'core': seed}, platform='ubuntu-24.04', profile='all')

    def test_context_plan_recomputes_shards_and_rejects_malformed_records(self) -> None:
        group, seed = context_group('core', 64, 4)
        value = context_value((group,), 4)
        for shards in (0, 1, 2, 3, 8, 65, True, 4.0, '4'):
            with self.subTest(shards=shards), self.assertRaises(ValueError):
                parse_plan(encode(value | {'shards': shards}), (group.target,), {'core': seed})
        for missing in value:
            invalid = {key: item for key, item in value.items() if key != missing}
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                parse_plan(encode(invalid), (group.target,), {'core': seed})
        raw_group = record(sequence(value['groups'])[0])
        invalid_values = (value | {'extra': True}, value | {'groups': 'core'},
            value | {'groups': [raw_group | {'extra': True}]},
            value | {'groups': [raw_group | {'inventory': ['same', 'same']}]},
            value | {'groups': [raw_group | {'inventory': ['']}]},
            value | {'groups': [raw_group | {'inventory': 'core'}]},
            value | {'groups': [{key: item for key, item in raw_group.items() if key != 'seed_digest'}]},
            value | {'groups': [raw_group | {'target': {'group': 'core'}}]})
        for invalid in invalid_values:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse_plan(encode(invalid), (group.target,), {'core': seed})
        duplicated = encode(value)[:-1] + b', "shards": 4}'
        for data in (b'\xff', b'[]', duplicated):
            with self.subTest(data=data[:30]), self.assertRaises(ValueError):
                parse_plan(data, (group.target,), {'core': seed})

    def test_receiver_coverage_cannot_replace_the_context_inventory(self) -> None:
        data = encode(receipt())
        inventory = ('killed', 'timeout', 'new')
        seed = parse(data)
        runs = receiver_runs(data, inventory)
        self.assertEqual(validate_coverage(seed, data, runs, expected_inventory=inventory).executable_ids,
                         ('timeout', 'new'))
        changed = receiver_runs(data, ('killed', 'replacement'))
        self.assertEqual(validate_coverage(seed, data, changed).executable_ids, ('replacement',))
        with self.assertRaises(ValueError):
            validate_coverage(seed, data, changed, expected_inventory=inventory)

    def test_coverage_digest_binds_values_and_ignores_object_key_order(self) -> None:
        coverage: dict[str, object] = dict(seed='caf\u00e9', reused_ids=['first'], inventory=['second', 'first'])
        expected = hashlib.sha256(b'{"inventory":["second","first"],"reused_ids":["first"],"seed":"caf\xc3\xa9"}').hexdigest()
        actual = coverage_digest(coverage)
        self.assertEqual(actual, expected)
        self.assertEqual(coverage_digest(dict(reversed(tuple(coverage.items())))), actual)
        for changed in (coverage | {'seed': 'caf\u00e9\n'}, coverage | {'inventory': ['first', 'second']},
                        coverage | {'reused_ids': []}):
            with self.subTest(changed=changed):
                self.assertNotEqual(coverage_digest(changed), actual)

    def test_receiver_coverage_binds_actual_partition_and_exact_seed_bytes(self) -> None:
        data = encode(receipt())
        inventory = ('killed', 'timeout', 'new')
        runs = receiver_runs(data, inventory)
        plan = validate_coverage(parse(data), data, tuple(reversed(runs)))
        self.assertEqual(plan.executable_ids, ('timeout', 'new'))
        self.assertEqual(plan.reused_ids, ('killed',))
        self.assertEqual(plan.donor_digest, hashlib.sha256(data).hexdigest())
        with self.assertRaises(ValueError):
            validate_coverage(parse(data), data + b'\n', runs)

    def test_receiver_requires_one_coverage_record_and_own_successful_baselines(self) -> None:
        data = encode(receipt())
        runs = receiver_runs(data, ('killed',))
        plan = validate_coverage(parse(data), data, runs)
        self.assertEqual(plan.executable_ids, ())
        for index in range(2):
            for update in ({'workspace_baseline': False}, {'workspace_baseline': 1},
                           {'coverage_digest': 'wrong'}, {'unexpected_proof': True},
                           {'coverage_digest': text(runs[0][0]['coverage_digest'])[:-1]},
                           {'target': asdict(TARGET) | {'donor': 'other'}}):
                changed = tuple((run | update if item == index else run, report)
                                for item, (run, report) in enumerate(runs))
                with self.subTest(shard=index + 1, update=update), self.assertRaises(ValueError):
                    validate_coverage(parse(data), data, changed)
        for changed in (runs[1:], (runs[0], runs[0]),
                        ((runs[0][0] | {'coverage': None}, runs[0][1]), runs[1]),
                        (runs[0], (runs[1][0] | {'coverage': runs[0][0]['coverage']}, runs[1][1]))):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_coverage(parse(data), data, changed)

    def test_recomputed_digest_cannot_turn_non_kills_into_reused_coverage(self) -> None:
        data = encode(receipt())
        runs = receiver_runs(data, ('killed', 'timeout', 'new'))
        original = record(runs[0][0]['coverage'])
        updates: tuple[dict[str, object], ...] = (
            {'reused_ids': ['killed', 'timeout']}, {'reused_ids': []},
            {'inventory': ['killed', 'timeout', 'timeout']},
            {'inventory': ['killed', 'unreported']}, {'donor': 'other'}, {'seed': ' '},
            {'seed': data.decode('utf-8') + '\n'}, {'inventory': 'killed'}, {'reused_ids': 'killed'},
        )
        for update in updates:
            coverage = original | update
            changed = tuple((run | {'coverage': coverage if index == 0 else None,
                                    'coverage_digest': coverage_digest(coverage)}, report)
                            for index, (run, report) in enumerate(runs))
            with self.subTest(update=update), self.assertRaises(ValueError):
                validate_coverage(parse(data), data, changed)
        for expected in (('timeout',), ('timeout', 'new', 'unreported')):
            changed = tuple((run, replace(report, expected=expected)) for run, report in runs)
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                validate_coverage(parse(data), data, changed)

    def test_direct_report_accepts_partial_shards_without_making_them_complete_seeds(self) -> None:
        for complete in (False, True):
            partial = replace(REPORT, outcomes=REPORT.outcomes[:2], complete=complete)
            value = receipt(partial)
            with self.subTest(complete=complete):
                self.assertEqual(parse_direct_report(value['report']), partial)
                with self.assertRaises(ValueError):
                    parse(encode(value))

    def test_direct_report_refuses_reuse_or_exclusion_claims_before_normalization(self) -> None:
        for field in ('reused_kills', 'donor', 'exclusions'):
            value = receipt()
            report = record(value['report'])
            report[field] = ['killed']
            with self.subTest(report_field=field), self.assertRaises(ValueError):
                parse_direct_report(report)
            value = receipt()
            report = record(value['report'])
            record(sequence(report['outcomes'])[0])[field] = ['killed']
            with self.subTest(outcome_field=field), self.assertRaises(ValueError):
                parse_direct_report(report)

    def test_completed_weak_seed_reuses_only_actual_kills(self) -> None:
        self.assertFalse(score(REPORT).passed)
        data = encode(receipt())
        language = text(record(json.loads(json.dumps(asdict(TARGET))))['language'])
        match language:
            case 'rust':
                target = replace(TARGET, language=language)
            case _:
                self.fail('controlled target must select Rust')
        seed = parse(data, target=target)
        inventory = ('new', 'timeout', 'killed', 'invalid', 'equivalent', 'survivor')
        selected = partition_inventory(seed, inventory)
        self.assertEqual(selected.reused_ids, ('killed',))
        self.assertEqual(selected.executable_ids, ('new', 'timeout', 'invalid', 'equivalent', 'survivor'))
        self.assertEqual(set(selected.reused_ids) | set(selected.executable_ids), set(inventory))
        self.assertFalse(set(selected.reused_ids) & set(selected.executable_ids))
        self.assertEqual(selected.donor_digest, hashlib.sha256(data).hexdigest())
        self.assertEqual(selected.donor_target, TARGET)
        self.assertEqual(selected.donor_revision, REPORT.revision)
        self.assertEqual(selected.donor_tool_version, TOOL_VERSION)

    def test_removed_seed_ids_and_new_receiver_ids_preserve_receiver_order(self) -> None:
        seed = parse(encode(receipt()))
        selected = partition_inventory(seed, ('new-b', 'new-a'))
        self.assertEqual(selected.executable_ids, ('new-b', 'new-a'))
        self.assertEqual(selected.reused_ids, ())
        self.assertEqual(partition_inventory(seed, ()).executable_ids, ())
        self.assertEqual(partition_inventory(seed, ('killed',)).executable_ids, ())
        many = tuple(f'new-{index}' for index in range(1000))
        self.assertEqual(partition_inventory(seed, many).executable_ids, many)

    def test_empty_completed_seed_never_invents_a_kill(self) -> None:
        seed = parse(encode(receipt(replace(REPORT, expected=(), outcomes=()))))
        selected = partition_inventory(seed, ('killed', 'new'))
        self.assertEqual(selected.reused_ids, ())
        self.assertEqual(selected.executable_ids, ('killed', 'new'))

    def test_original_receipt_bytes_are_bound_by_the_donor_digest(self) -> None:
        data = encode(receipt())
        first, second = parse(data), parse(data + b'\n')
        self.assertEqual(first.report, second.report)
        self.assertNotEqual(first.donor_digest, second.donor_digest)

    def test_schema_context_workspace_and_shards_must_be_direct_and_complete(self) -> None:
        for field, invalid in (
            ('schema', 'packetcraftr.mutation-seed/v0'), ('schema', 'packetcraftr.mutation-seed/v2'),
            ('platform', 'Linux'), ('platform', 'windows-2022'), ('profile', '0'), ('profile', 'portable'),
            ('shard', 0), ('shard', 2), ('shard', True), ('shards', 0), ('shards', 2), ('shards', True),
            ('workspace_baseline', False), ('workspace_baseline', 1),
        ):
            with self.subTest(field=field, value=invalid), self.assertRaises(ValueError):
                parse(encode(receipt() | {field: invalid}))
        for field in receipt():
            value = receipt()
            del value[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                parse(encode(value))

    def test_every_target_component_and_report_binding_must_match(self) -> None:
        for target in (replace(TARGET, group='other'), replace(TARGET, language='python'),
                       replace(TARGET, files=()), replace(TARGET, files=('crates/other.rs',)),
                       replace(TARGET, reason='full audit')):
            with self.subTest(target=target), self.assertRaises(ValueError):
                parse(encode(receipt(target=target)))
        for report in (replace(REPORT, group='other'), replace(REPORT, group='z-other'),
                       replace(REPORT, reason='a reason'), replace(REPORT, reason='full audit'),
                       replace(REPORT, revision=f'{"0" * 40} tree {SOURCE_DIGEST}'),
                       replace(REPORT, revision=f'{"c" * 40} tree {SOURCE_DIGEST}'),
                       replace(REPORT, revision=f'{REVISION} tree {"c" * 64}'),
                       replace(REPORT, tool_version='0'), replace(REPORT, tool_version='other')):
            with self.subTest(report=report), self.assertRaises(ValueError):
                parse(encode(receipt(report)))

    def test_expected_source_identity_requires_complete_lowercase_digests(self) -> None:
        for revision, source in (('short', SOURCE_DIGEST), ('A' * 40, SOURCE_DIGEST),
                                 (REVISION, 'short'), (REVISION, 'B' * 64)):
            data = encode(receipt(replace(REPORT, revision=f'{revision} tree {source}')))
            with self.subTest(revision=revision, source=source), self.assertRaises(ValueError):
                parse(data, revision=revision, source_digest=source)
        revision = 'c' * 64
        seed = parse(encode(receipt(replace(REPORT, revision=f'{revision} tree {SOURCE_DIGEST}'))), revision=revision)
        self.assertEqual(seed.report.revision, f'{revision} tree {SOURCE_DIGEST}')

    def test_matching_python_seed_is_outside_the_supported_reuse_scope(self) -> None:
        target = Target('scripts/example.py', 'python', ('scripts/example.py',), 'changed production module')
        report = replace(REPORT, group=target.group, reason=target.reason, tool_version='8.7.0')
        with self.assertRaises(ValueError):
            parse(encode(receipt(report, target)), target=target, tool_version=report.tool_version)

    def test_missing_duplicate_and_unfinished_outcomes_cannot_supply_reuse(self) -> None:
        for report in (replace(REPORT, baseline=False), replace(REPORT, complete=False),
                       replace(REPORT, expected=(*REPORT.expected, 'killed')),
                       replace(REPORT, outcomes=REPORT.outcomes[:-1]),
                       replace(REPORT, outcomes=(*REPORT.outcomes, REPORT.outcomes[0])),
                       replace(REPORT, outcomes=(*REPORT.outcomes, Outcome('extra', 'killed', 'test failure')))):
            with self.subTest(report=report), self.assertRaises(ValueError):
                parse(encode(receipt(report)))

    def test_transitive_or_exclusion_proofs_are_rejected_at_every_level(self) -> None:
        for field, proof in (('reused_ids', ['killed']), ('donor_digest', 'c' * 64), ('exclusions', ['survivor'])):
            with self.subTest(field=field), self.assertRaises(ValueError):
                parse(encode(receipt() | {field: proof}))
        value = receipt()
        raw_report = record(value['report'])
        raw_report['reused_kills'] = ['killed']
        with self.assertRaises(ValueError):
            parse(encode(value))
        value = receipt()
        outcome = record(sequence(record(value['report'])['outcomes'])[0])
        outcome['donor'] = 'c' * 64
        with self.assertRaises(ValueError):
            parse(encode(value))

    def test_malformed_receipts_fail_instead_of_supplying_a_plan(self) -> None:
        data = encode(receipt())
        duplicate = data[:-1] + b', "schema": "packetcraftr.mutation-seed/v1"}'
        for invalid in (b'\xff', b'[]', b'null', data + data, duplicate):
            with self.subTest(data=invalid[:40]), self.assertRaises(ValueError):
                parse(invalid)
        for field, invalid_field in (('baseline', 1), ('complete', 'true'), ('expected', 'killed')):
            value = receipt()
            record(value['report'])[field] = invalid_field
            with self.subTest(field=field), self.assertRaises(ValueError):
                parse(encode(value))
            with self.subTest(direct_field=field), self.assertRaises(ValueError):
                parse_direct_report(value['report'])
        for field, invalid_outcome in (('status', 'equivalent'), ('evidence', ''), ('identity', None)):
            value = receipt()
            record(sequence(record(value['report'])['outcomes'])[0])[field] = invalid_outcome
            with self.subTest(field=field), self.assertRaises(ValueError):
                parse(encode(value))
            with self.subTest(direct_outcome_field=field), self.assertRaises(ValueError):
                parse_direct_report(value['report'])

    def test_invalid_receiver_inventory_is_not_silently_deduplicated(self) -> None:
        seed = parse(encode(receipt()))
        for inventory in (('killed', 'killed'), ('',), (' ',), 'killed'):
            with self.subTest(inventory=inventory), self.assertRaises(ValueError):
                partition_inventory(seed, inventory)


if __name__ == '__main__':
    unittest.main()
