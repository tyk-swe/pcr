# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
import unittest

from support import ROOT
from mutation_results import Outcome, Report, record, score, sequence
from mutation_reuse import Seed, coverage_digest, parse_direct_report, parse_seed, partition_inventory, validate_coverage
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


class MutationReuseTests(unittest.TestCase):
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
        for update in ({'reused_ids': ['killed', 'timeout']}, {'inventory': ['killed', 'timeout', 'timeout']},
                       {'inventory': ['killed', 'unreported']}, {'donor': 'other'}, {'seed': ' '},
                       {'inventory': 'killed'}, {'reused_ids': 'killed'}):
            coverage = original | update
            changed = tuple((run | {'coverage': coverage if index == 0 else None,
                                    'coverage_digest': coverage_digest(coverage)}, report)
                            for index, (run, report) in enumerate(runs))
            with self.subTest(update=update), self.assertRaises(ValueError):
                validate_coverage(parse(data), data, changed)
        changed = tuple((run, replace(report, expected=('timeout',))) for run, report in runs)
        with self.assertRaises(ValueError):
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
        seed = parse(data)
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
            ('schema', 'packetcraftr.mutation-seed/v2'), ('platform', 'Linux'), ('platform', 'windows-2022'),
            ('profile', 'portable'), ('shard', 0), ('shard', 2), ('shard', True),
            ('shards', 2), ('shards', True), ('workspace_baseline', False), ('workspace_baseline', 1),
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
        for report in (replace(REPORT, group='other'), replace(REPORT, reason='full audit'),
                       replace(REPORT, revision=f'{"c" * 40} tree {SOURCE_DIGEST}'),
                       replace(REPORT, revision=f'{REVISION} tree {"c" * 64}'),
                       replace(REPORT, tool_version='other')):
            with self.subTest(report=report), self.assertRaises(ValueError):
                parse(encode(receipt(report)))

    def test_expected_source_identity_requires_complete_lowercase_digests(self) -> None:
        data = encode(receipt())
        for revision, source in (('short', SOURCE_DIGEST), ('A' * 40, SOURCE_DIGEST),
                                 (REVISION, 'short'), (REVISION, 'B' * 64)):
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
