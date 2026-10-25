# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import re

from mutation_results import Report, integer, parse_report, record, score, sequence, text
from mutation_scope import Target
from script_support import strict_json

SEED_SCHEMA = 'packetcraftr.mutation-seed/v1'
SEED_PLATFORM = 'ubuntu-24.04'
SEED_PROFILE = 'all'
CONTEXT_SCHEMA = 'packetcraftr.mutation-context/v1'
MAX_CONTEXT_SHARDS = 64


@dataclass(frozen=True)
class Seed:
    target: Target
    report: Report
    donor_digest: str


@dataclass(frozen=True)
class ReusePlan:
    executable_ids: tuple[str, ...]
    reused_ids: tuple[str, ...]
    donor_digest: str
    donor_target: Target
    donor_revision: str
    donor_tool_version: str


@dataclass(frozen=True)
class ContextGroup:
    target: Target
    inventory: tuple[str, ...]
    seed_digest: str


@dataclass(frozen=True)
class ContextPlan:
    platform: str
    profile: str
    revision: str
    tool_version: str
    shards: int
    groups: tuple[ContextGroup, ...]


def _fields(raw: object, names: frozenset[str]) -> dict[str, object]:
    value = record(raw)
    if set(value) != names:
        raise ValueError('seed receipt has missing or unsupported fields')
    return value


def _source_identity(revision: str, source_digest: str) -> str:
    if (re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', revision) is None
            or re.fullmatch(r'[0-9a-f]{64}', source_digest) is None):
        raise ValueError('source identity must contain full revision and source digests')
    return f'{revision} tree {source_digest}'


def _target_value(target: Target) -> dict[str, object]:
    return dict(group=text(target.group), language=target.language,
                files=[text(file) for file in target.files], reason=text(target.reason))


def parse_direct_report(raw: object) -> Report:
    """Parse direct-execution fields without requiring an individual shard to be complete."""
    value = _fields(raw, frozenset((
        'group', 'revision', 'tool_version', 'reason', 'expected', 'outcomes', 'baseline', 'complete',
    )))
    for outcome in sequence(value.get('outcomes')):
        _fields(outcome, frozenset(('identity', 'status', 'evidence')))
    return parse_report(value)


def parse_seed(data: bytes, *, target: Target, revision: str, source_digest: str,
               tool_version: str) -> Seed:
    """Validate a direct completed Rust seed against the receiver's exact source and scope."""
    if not isinstance(data, bytes):
        raise ValueError('seed receipt must be bytes')
    source = _source_identity(revision, source_digest)
    value = _fields(strict_json(data), frozenset((
        'schema', 'target', 'platform', 'profile', 'shard', 'shards', 'workspace_baseline', 'report',
    )))
    if value['schema'] != SEED_SCHEMA or value['platform'] != SEED_PLATFORM or value['profile'] != SEED_PROFILE:
        raise ValueError('seed receipt is not the supported Linux/all context')
    if (type(value['shard']) is not int or value['shard'] != 1
            or type(value['shards']) is not int or value['shards'] != 1
            or value['workspace_baseline'] is not True):
        raise ValueError('seed requires one complete run and a successful workspace baseline')
    if target.language != 'rust' or value['target'] != _target_value(target):
        raise ValueError('seed target does not match the requested scope')
    report = parse_direct_report(value['report'])
    if (report.group != target.group or report.reason != target.reason
            or report.revision != source or report.tool_version != text(tool_version)):
        raise ValueError('seed report does not match the requested source, scope or pinned tool')
    score(report)
    return Seed(target, report, hashlib.sha256(data).hexdigest())


def partition_inventory(seed: Seed, inventory: Sequence[str]) -> ReusePlan:
    """Reuse only actual seed kills; every other receiver identity must execute."""
    if isinstance(inventory, (str, bytes)):
        raise ValueError('receiver inventory must be a sequence of identities')
    identities = tuple(text(identity) for identity in inventory)
    if len(set(identities)) != len(identities):
        raise ValueError('receiver inventory contains duplicate identities')
    score(seed.report)
    killed = frozenset(outcome.identity for outcome in seed.report.outcomes if outcome.status == 'killed')
    return ReusePlan(tuple(identity for identity in identities if identity not in killed),
                     tuple(identity for identity in identities if identity in killed),
                     seed.donor_digest, seed.target, seed.report.revision, seed.report.tool_version)


def coverage_digest(coverage: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(coverage, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode('utf-8')).hexdigest()


def _context_seed(group: ContextGroup, seeds: Mapping[str, Seed]) -> Seed:
    seed = seeds.get(group.target.group)
    if (seed is None or group.target.language != 'rust' or seed.target != group.target
            or seed.donor_digest != group.seed_digest or seed.report.group != group.target.group
            or seed.report.reason != group.target.reason):
        raise ValueError('context group does not match its direct seed')
    return seed


def context_shards(groups: tuple[ContextGroup, ...], seeds: Mapping[str, Seed]) -> int:
    """Preserve each group's full-inventory work ceiling with fewer receiver jobs."""
    if len({group.target.group for group in groups}) != len(groups):
        raise ValueError('context contains duplicate groups')
    sizes = tuple((len(group.inventory),
                   len(partition_inventory(_context_seed(group, seeds), group.inventory).executable_ids))
                  for group in groups)
    candidates: tuple[int, ...] = (1, *range(4, MAX_CONTEXT_SHARDS + 1, 4))
    return next(shards for shards in candidates
                if all((remaining + shards - 1) // shards
                       <= (total + MAX_CONTEXT_SHARDS - 1) // MAX_CONTEXT_SHARDS
                       for total, remaining in sizes))


def _context_group(raw: object, targets: Mapping[str, Target]) -> ContextGroup:
    value = _fields(raw, frozenset(('target', 'inventory', 'seed_digest')))
    target_value = _fields(value['target'], frozenset(('group', 'language', 'files', 'reason')))
    target = targets.get(text(target_value['group']))
    if target is None or target_value != _target_value(target):
        raise ValueError('context target does not match the requested scope')
    return ContextGroup(target, tuple(text(item) for item in sequence(value['inventory'])),
                        text(value['seed_digest']))


def parse_context(data: bytes, *, targets: tuple[Target, ...], platform: str, profile: str,
                  revision: str, tool_version: str, seeds: Mapping[str, Seed]) -> ContextPlan:
    """Bind complete receiver discovery and shard count to its exact source and seeds."""
    if not isinstance(data, bytes):
        raise ValueError('context plan must be bytes')
    commit, separator, source_digest = revision.partition(' tree ')
    if not separator:
        raise ValueError('context source identity is incomplete')
    source = _source_identity(commit, source_digest)
    value = _fields(strict_json(data), frozenset((
        'schema', 'platform', 'profile', 'revision', 'tool_version', 'shards', 'groups',
    )))
    if ((platform, profile) == (SEED_PLATFORM, SEED_PROFILE)
            or value['schema'] != CONTEXT_SCHEMA or value['platform'] != text(platform)
            or value['profile'] != text(profile) or value['revision'] != source
            or value['tool_version'] != text(tool_version)):
        raise ValueError('context plan does not match the requested receiver or source')
    requested = tuple(target for target in targets if target.language == 'rust')
    owned = {target.group: target for target in requested}
    if len(owned) != len(requested):
        raise ValueError('duplicate requested context groups')
    groups = tuple(_context_group(group, owned) for group in sequence(value['groups']))
    if {group.target.group for group in groups} != set(owned):
        raise ValueError('context plan has missing or extra groups')
    if any(seed.report.revision != source or seed.report.tool_version != tool_version
           for group in groups for seed in (_context_seed(group, seeds),)):
        raise ValueError('context seed does not match the requested source or tool')
    shards = context_shards(groups, seeds)
    if integer(value['shards']) != shards:
        raise ValueError('context shard count does not match complete inventories')
    return ContextPlan(platform, profile, source, tool_version, shards, groups)


def validate_coverage(seed: Seed, seed_data: bytes,
                      runs: tuple[tuple[dict[str, object], Report], ...],
                      expected_inventory: tuple[str, ...] | None = None) -> ReusePlan:
    first = tuple(run for run, _ in runs if run.get('shard') == 1)
    if len(first) != 1:
        raise ValueError('receiver is missing its coverage shard')
    coverage = _fields(first[0].get('coverage'), frozenset(('inventory', 'reused_ids', 'seed')))
    if text(coverage['seed']).encode('utf-8') != seed_data:
        raise ValueError('receiver coverage does not match the supplied seed')
    inventory = tuple(text(value) for value in sequence(coverage['inventory']))
    if expected_inventory is not None and inventory != expected_inventory:
        raise ValueError('receiver inventory does not match its context plan')
    plan = partition_inventory(seed, inventory)
    if tuple(text(value) for value in sequence(coverage['reused_ids'])) != plan.reused_ids:
        raise ValueError('receiver reused identities do not match actual seed kills')
    digest = coverage_digest(coverage)
    for run, report in runs:
        _fields(run, frozenset(('platform', 'profile', 'shard', 'shards', 'target', 'workspace_baseline',
                                'report', 'coverage', 'coverage_digest')))
        _fields(run['target'], frozenset(('group', 'language', 'files', 'reason')))
        if (run.get('coverage_digest') != digest or run.get('workspace_baseline') is not True
                or 'coverage' not in run or run.get('shard') != 1 and run['coverage'] is not None):
            raise ValueError('receiver coverage or workspace baseline is inconsistent')
        if report.expected != plan.executable_ids:
            raise ValueError('receiver inventory is missing required executable mutants')
    return plan
