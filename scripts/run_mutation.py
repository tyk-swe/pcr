from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
from subprocess import SubprocessError
import sys
import tempfile
from typing import Sequence

from mutation_results import (Exclusion, Outcome, Report, Status, cosmic_baseline, cosmic_identity, cosmic_results,
                              integer, record, rust_results, score, sequence, text)
from mutation_scope import Target, changes_since, configuration, select, serialize
from mutation_reuse import (SEED_PLATFORM, SEED_PROFILE, SEED_SCHEMA, Seed, coverage_digest,
                            parse_direct_report, parse_seed, partition_inventory, validate_coverage)
from script_support import read_json

ROOT = Path(__file__).resolve().parents[1]
PROFILES = {
    'portable': ('--no-default-features',),
    'default': (),
    'layer2': ('--no-default-features', '--features', 'packetcraftr-cli/native-layer2'),
    'layer3': ('--no-default-features', '--features', 'packetcraftr-cli/native-layer3'),
    'all': ('--all-features',),
}


def read(path: Path) -> object:
    return json.loads(path.read_text(encoding='utf-8'))


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def command(argv: Sequence[str], cwd: Path, log: Path) -> int:
    with log.open('w', encoding='utf-8') as output:
        return subprocess.run(argv, cwd=cwd, stdout=output, stderr=subprocess.STDOUT,
                              check=False).returncode


def rust_inventory(argv: Sequence[str], root: Path, output: Path) -> list[object]:
    with output.open('w', encoding='utf-8') as stdout, output.with_suffix('.stderr.log').open('w', encoding='utf-8') as stderr:
        status = subprocess.run([*argv, '--list', '--json'], cwd=root, stdout=stdout, stderr=stderr,
                                check=False).returncode
    if status:
        raise ValueError('Rust mutation discovery failed')
    return sequence(read(output))


def identities(inventory: list[object]) -> tuple[str, ...]:
    values = tuple(text(record(mutant).get('name')) for mutant in inventory)
    if len(set(values)) != len(values):
        raise ValueError('Rust inventory contains duplicate identities')
    return values


def parse_target(raw: object) -> Target:
    value = record(raw)
    if value.get('language') not in ('rust', 'python'):
        raise ValueError('invalid mutation language')
    return Target(text(value.get('group')), 'rust' if value['language'] == 'rust' else 'python',
                  tuple(text(file) for file in sequence(value.get('files'))), text(value.get('reason')))


def targets_from(path: Path) -> tuple[Target, ...]:
    targets = tuple(parse_target(value) for value in sequence(read(path)))
    if len({(target.language, target.group) for target in targets}) != len(targets):
        raise ValueError('duplicate mutation targets')
    return targets


def snapshot(root: Path, destination: Path) -> str:
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
    added = subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard', '-z'],
                                    cwd=root).decode().split('\0')
    digest = hashlib.sha256()
    for name in sorted(set(tracked + added) - {''}):
        source = root / name
        if not source.is_file():
            continue
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        # Review policy cannot contain its own source fingerprint.
        if name != '.config/mutation-exclusions.json':
            digest.update(name.encode() + b'\0' + target.read_bytes())
    return digest.hexdigest()


def rust(target: Target, root: Path, output: Path, profile: str, shard: int, shards: int,
         seed: tuple[bytes, Seed] | None) -> tuple[Report, dict[str, object] | None]:
    package = root / 'crates' / target.group
    if (package / 'build.rs').is_file():
        manifest = package / 'Cargo.toml'
        with manifest.open('a', encoding='utf-8') as destination:
            destination.write('\n[[bin]]\nname = ' + json.dumps(f'mutation-build-{target.group}')
                              + '\npath = "build.rs"\ntest = false\n')
        shutil.copy2(manifest, output / 'mutation-Cargo.toml')
    args = ['cargo', 'mutants', '--package', target.group, '--test-workspace=true',
            '--cargo-arg=--locked', *PROFILES[profile]]
    for file in target.files:
        args.extend(('--file', file))
    inventory = identities(rust_inventory(args, root, output / 'inventory.json'))
    coverage: dict[str, object] | None = None
    execution = output
    if seed is not None:
        seed_data, proof = seed
        plan = partition_inventory(proof, inventory)
        coverage = dict(inventory=inventory, reused_ids=plan.reused_ids, seed=seed_data.decode('utf-8'))
        execution = Path(tempfile.mkdtemp(prefix='execution-', dir=output))
        (execution / 'mutants.out').mkdir()
        (execution / 'mutants.out/previously_caught.txt').write_text(
            ''.join(identity + '\n' for identity in plan.reused_ids), encoding='utf-8')
        args.extend(('--iterate', '--output', str(execution)))
        remaining = identities(rust_inventory(args, root, output / 'remaining.json'))
        if remaining != plan.executable_ids:
            raise ValueError('Rust iteration omitted required executable mutants')
        inventory = remaining
    partition = ['--shard', f'{shard - 1}/{shards}']
    selected = rust_inventory([*args, *partition], root, output / 'selected.json')
    if not set(identities(selected)) <= set(inventory):
        raise ValueError('Rust shard contains an unknown mutant')
    if command(['cargo', 'test', '--locked', '--workspace', *PROFILES[profile]],
               root, output / 'baseline.log'):
        raise ValueError('Rust workspace baseline failed')
    if not selected:
        version = subprocess.check_output(['cargo', 'mutants', '--version'], text=True).split()[-1]
        return Report(target.group, '', version, target.reason, inventory, (), True, True), coverage
    output_args = () if seed is not None else ('--output', str(execution))
    exit_code = command([*args, *partition, '--jobs', '1', *output_args,
                         '--minimum-test-timeout', '30'], root, output / 'execution.log')
    if exit_code not in (0, 2, 3):
        raise ValueError(f'cargo-mutants runner failed with {exit_code}')
    raw = record(read(execution / 'mutants.out/outcomes.json'))
    log_paths = tuple(text(record(outcome).get('log_path'))
                      for outcome in sequence(raw.get('outcomes')))
    logs = {path: (execution / 'mutants.out' / path).read_text(encoding='utf-8') for path in log_paths}
    outcomes = rust_results(selected, raw, logs)
    if seed is not None:
        outcomes = tuple(replace(outcome, evidence=(execution.relative_to(output) / 'mutants.out'
                                                    / outcome.evidence).as_posix()) for outcome in outcomes)
    return Report(target.group, '', text(raw.get('cargo_mutants_version')), target.reason,
                  inventory, outcomes, True, True), coverage


def python(target: Target, root: Path, output: Path, version: str) -> Report:
    config = output / 'cosmic.toml'
    runner = output / 'test_runner.py'
    shutil.copy2(root / 'scripts/mutation_test_runner.py', runner)
    test_command = shlex.join((sys.executable, str(runner), '--module', target.group))
    config.write_text('[cosmic-ray]\nmodule-path = ' + json.dumps(target.group)
                      + '\ntimeout = 30.0\nexcluded-modules = []\ntest-command = '
                      + json.dumps(test_command) + '\n[cosmic-ray.distributor]\nname = "local"\n',
                      encoding='utf-8')
    session = output / 'session.sqlite'
    cosmic = [str(Path(sys.executable).with_name('cosmic-ray'))]
    if command([*cosmic, 'init', str(config), str(session)], root, output / 'init.log'):
        raise ValueError('Cosmic Ray init failed')
    inventory = output / 'inventory.jsonl'
    if command([*cosmic, 'dump', str(session)], root, inventory):
        raise ValueError('Cosmic Ray inventory export failed')
    expected = tuple(cosmic_identity(sequence(json.loads(line))[0])
                     for line in inventory.read_text(encoding='utf-8').splitlines())
    baseline_session = output / 'baseline.sqlite'
    if command([*cosmic, 'baseline', str(config), '--session-file', str(baseline_session)], root, output / 'baseline.log'):
        raise ValueError('Cosmic Ray baseline failed')
    baseline_dump = output / 'baseline.jsonl'
    if command([*cosmic, 'dump', str(baseline_session)], root, baseline_dump):
        raise ValueError('Cosmic Ray baseline export failed')
    cosmic_baseline([json.loads(line) for line in baseline_dump.read_text(encoding='utf-8').splitlines()])
    if command([*cosmic, 'exec', str(config), str(session)], root, output / 'exec.log'):
        raise ValueError('Cosmic Ray exec failed')
    dump = output / 'cosmic.jsonl'
    if command([*cosmic, 'dump', str(session)], root, dump):
        raise ValueError('Cosmic Ray report export failed')
    rows = [json.loads(line) for line in dump.read_text(encoding='utf-8').splitlines()]
    outcomes = cosmic_results(rows)
    if {outcome.identity for outcome in outcomes} != set(expected):
        raise ValueError('Cosmic Ray did not run every discovered mutant')
    return Report(target.group, '', version, target.reason, expected, outcomes, True, True)


def run(targets: tuple[Target, ...], output: Path, language: str, profile: str,
        shard: int, shards: int, platform_label: str, seed_directory: Path | None = None) -> None:
    if not 1 <= shard <= shards:
        raise ValueError('invalid shard')
    config = record(configuration(ROOT).get('tools'))
    version = text(config.get('cargo-mutants' if language == 'rust' else 'cosmic-ray'))
    tool = ['cargo', 'mutants'] if language == 'rust' else [str(Path(sys.executable).with_name('cosmic-ray'))]
    actual = subprocess.check_output([*tool, '--version'], text=True).strip().split()[-1]
    if actual != version:
        raise ValueError(f'expected mutation tool {version}, got {actual}')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / '.config/mutation-exclusions.json', output / 'exclusions.json')
    with tempfile.TemporaryDirectory(prefix='pcr-mutation-source-') as directory:
        source = Path(directory)
        tree = snapshot(ROOT, source)
        failures = tuple(error for target in targets if target.language == language
                         if (error := run_target(target, source, output, profile, shard, shards,
                                                 platform_label, revision, tree, version, seed_directory)) is not None)
    if failures:
        raise ValueError('\n'.join(failures))


def run_target(target: Target, source: Path, output: Path, profile: str, shard: int, shards: int,
               platform_label: str, revision: str, tree: str, version: str,
               seed_directory: Path | None) -> str | None:
    folder = output / target.group.replace('/', '_').replace('.', '_')
    folder.mkdir(parents=True, exist_ok=True)
    metadata = dict(platform=platform_label, profile=profile, shard=shard, shards=shards, target=asdict(target))
    write(folder / 'run.json', {**metadata, 'group': target.group, 'complete': False})
    try:
        seed = load_seed(target, seed_directory, revision, tree, version) if seed_directory is not None else None
        with tempfile.TemporaryDirectory(prefix='pcr-mutation-') as directory:
            checkout = Path(directory)
            shutil.copytree(source, checkout, dirs_exist_ok=True)
            report, coverage = (rust(target, checkout, folder, profile, shard, shards, seed)
                                if target.language == 'rust' else (python(target, checkout, folder, version), None))
        reuse = (dict(coverage=coverage if shard == 1 else None, coverage_digest=coverage_digest(coverage))
                 if coverage is not None else {})
        write(folder / 'run.json', {**metadata, 'workspace_baseline': target.language == 'rust',
                                   **reuse,
                                   'report': asdict(replace(report, revision=f'{revision} tree {tree}'))})
        return None
    except (OSError, ValueError, SubprocessError) as error:
        return f'{target.group} failed. {error}'


def load_seed(target: Target, directory: Path, revision: str, tree: str, version: str) -> tuple[bytes, Seed]:
    data = (directory / f'{target.group.replace("/", "_").replace(".", "_")}.json').read_bytes()
    return data, parse_seed(data, target=target, revision=revision, source_digest=tree, tool_version=version)


def cohort(runs: tuple[tuple[dict[str, object], Report], ...], group: str,
           system: str, profile: str, shards: int) -> Report:
    matching = tuple((run, report) for run, report in runs
                     if report.group == group and run.get('platform') == system
                     and run.get('profile') == profile)
    if (len(matching) != shards
            or {integer(run.get('shard')) for run, _ in matching} != set(range(1, shards + 1))
            or any(integer(run.get('shards')) != shards for run, _ in matching)):
        raise ValueError(f'{group} is missing a {system}/{profile} shard')
    first = matching[0][1]
    if any((report.expected, report.revision, report.tool_version, report.reason)
           != (first.expected, first.revision, first.tool_version, first.reason)
           or not report.baseline or not report.complete for _, report in matching):
        raise ValueError('mutation shards have inconsistent inventories or execution evidence')
    combined = replace(first, outcomes=tuple(outcome for _, report in matching
                                             for outcome in report.outcomes))
    score(combined)
    return combined


def merge_reports(reports: tuple[Report, ...]) -> Report:
    if not reports:
        raise ValueError('missing mutation runs')
    for report in reports:
        score(report)
    first = reports[0]
    if any(report.tool_version != first.tool_version or report.revision != first.revision
           for report in reports):
        raise ValueError('feature runs have inconsistent versions or revisions')
    expected = tuple(sorted({identity for report in reports for identity in report.expected}))
    indexed = tuple({outcome.identity: outcome for outcome in report.outcomes} for report in reports)
    outcomes = tuple(merge_outcomes(identity, tuple(index[identity] for index in indexed if identity in index))
                     for identity in expected)
    return replace(first, expected=expected, outcomes=outcomes,
                   revision='\n'.join(sorted({report.revision for report in reports})))


def merge_outcomes(identity: str, outcomes: tuple[Outcome, ...]) -> Outcome:
    statuses = {outcome.status for outcome in outcomes}
    status: Status = ('killed' if 'killed' in statuses else 'timeout' if 'timeout' in statuses
                      else 'survived' if 'survived' in statuses else 'invalid')
    return Outcome(identity, status, '\n'.join(outcome.evidence for outcome in outcomes))


def validated_runs(targets: tuple[Target, ...], paths: tuple[Path, ...], language: str,
                   platforms: tuple[str, ...], profiles: tuple[str, ...], shards: int,
                   revision: str, tool_version: str) -> tuple[tuple[dict[str, object], Report], ...]:
    if (shards < 1 or not platforms or not profiles
            or len(set(platforms)) != len(platforms) or len(set(profiles)) != len(profiles)):
        raise ValueError('invalid required mutation matrix')
    runs = tuple(record(read_json(path)) for path in paths)
    reports = tuple(parse_direct_report(run.get('report')) for run in runs)
    if any(report.revision != revision or report.tool_version != tool_version
           for report in reports):
        raise ValueError('mutation artifacts do not match the tested revision, source snapshot or pinned tool version')
    allowed = {target.group: target for target in targets if target.language == language}
    if len(allowed) != sum(target.language == language for target in targets):
        raise ValueError('duplicate required mutation groups')
    if any(report.group not in allowed for report in reports):
        raise ValueError('unexpected mutation group')
    if any(parse_target(run.get('target')) != allowed[report.group]
           or report.reason != allowed[report.group].reason for run, report in zip(runs, reports)):
        raise ValueError('mutation artifacts do not match the requested target scope')
    if any(run.get('platform') not in platforms or run.get('profile') not in profiles for run in runs):
        raise ValueError('unexpected mutation platform or feature profile')
    return tuple(zip(runs, reports))


def seed_proofs(targets: tuple[Target, ...], paths: tuple[Path, ...], shards: int,
                revision: str, tool_version: str) -> dict[str, dict[str, object]]:
    runs = validated_runs(targets, paths, 'rust', (SEED_PLATFORM,), (SEED_PROFILE,), shards,
                          revision, tool_version)
    validate_direct_runs(runs)
    return {target.group: dict(schema=SEED_SCHEMA, target=asdict(target),
                               platform=SEED_PLATFORM, profile=SEED_PROFILE, shard=1, shards=1,
                               workspace_baseline=True,
                               report=asdict(cohort(runs, target.group, SEED_PLATFORM, SEED_PROFILE, shards)))
            for target in targets if target.language == 'rust'}


def validate_direct_runs(runs: tuple[tuple[dict[str, object], Report], ...]) -> None:
    direct_fields = {'platform', 'profile', 'shard', 'shards', 'target', 'workspace_baseline', 'report'}
    if any(set(run) != direct_fields for run, _ in runs):
        raise ValueError('seed requires direct execution receipts without reused evidence')
    if any(set(record(run.get('target'))) != {'group', 'language', 'files', 'reason'} for run, _ in runs):
        raise ValueError('seed target contains unsupported fields')
    if any(run.get('workspace_baseline') is not True for run, _ in runs):
        raise ValueError('seed requires successful workspace baseline evidence')


def reuse_contexts(target: Target, runs: tuple[tuple[dict[str, object], Report], ...], directory: Path,
                   platforms: tuple[str, ...], profiles: tuple[str, ...], shards: int,
                   revision: str, version: str) -> tuple[dict[str, object], ...]:
    commit, separator, tree = revision.partition(' tree ')
    if not separator or SEED_PLATFORM not in platforms or SEED_PROFILE not in profiles:
        raise ValueError('reuse requires the actual canonical seed context')
    data, seed = load_seed(target, directory, commit, tree, version)
    seed_runs = tuple((run, report) for run, report in runs
                      if report.group == target.group and run.get('platform') == SEED_PLATFORM
                      and run.get('profile') == SEED_PROFILE)
    validate_direct_runs(seed_runs)
    canonical = cohort(seed_runs, target.group, SEED_PLATFORM, SEED_PROFILE, shards)
    if (canonical.expected != seed.report.expected
            or {outcome.identity: outcome for outcome in canonical.outcomes}
            != {outcome.identity: outcome for outcome in seed.report.outcomes}):
        raise ValueError('supplied seed does not match the completed canonical context')
    return tuple(reuse_context(seed, data, tuple((run, report) for run, report in runs
                                                if report.group == target.group and run.get('platform') == system
                                                and run.get('profile') == profile), system, profile)
                 for system in platforms for profile in profiles)


def reuse_context(seed: Seed, data: bytes, runs: tuple[tuple[dict[str, object], Report], ...],
                  system: str, profile: str) -> dict[str, object]:
    if (system, profile) == (SEED_PLATFORM, SEED_PROFILE):
        return dict(platform=system, profile=profile, executed=len(seed.report.expected), reused=0)
    plan = validate_coverage(seed, data, runs)
    return dict(platform=system, profile=profile, executed=len(plan.executable_ids),
                reused=len(plan.reused_ids), seed_digest=seed.donor_digest,
                seed_revision=seed.report.revision, seed_tool_version=seed.report.tool_version)


def check(targets: tuple[Target, ...], paths: tuple[Path, ...], language: str,
          platforms: tuple[str, ...], profiles: tuple[str, ...], shards: int,
          exclusions: tuple[Exclusion, ...], revision: str, tool_version: str,
          seed_directory: Path | None = None) -> bool:
    runs = validated_runs(targets, paths, language, platforms, profiles, shards, revision, tool_version)
    groups = tuple(target.group for target in targets if target.language == language)
    if seed_directory is not None and language != 'rust':
        raise ValueError('seed reuse is only supported for Rust')
    if seed_directory is None and any('coverage' in run or 'coverage_digest' in run for run, _ in runs):
        raise ValueError('receiver coverage requires the supplied seed directory')
    contexts = {target.group: reuse_contexts(target, runs, seed_directory, platforms, profiles,
                                            shards, revision, tool_version)
                for target in targets if target.language == language} if seed_directory is not None else {}
    scores = tuple(score(merge_reports(tuple(cohort(runs, group, system, profile, shards)
                                            for system in platforms for profile in profiles)), exclusions)
                   for group in sorted(groups))
    for result in scores:
        print(json.dumps({**asdict(result), 'platforms': platforms, 'profiles': profiles,
                          'execution_contexts': contexts.get(result.group, ()),
                          'percentage': 100 * result.killed / result.eligible if result.eligible else None,
                          'revisions': sorted({report.revision for _, report in runs if report.group == result.group}),
                          'tool_versions': sorted({report.tool_version for _, report in runs if report.group == result.group}),
                          'status': 'not_applicable' if result.eligible == 0 else
                          'passed' if result.passed else 'failed', 'passed': result.passed}))
    return all(result.passed for result in scores)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('select', 'run', 'check', 'seed'))
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--base')
    parser.add_argument('--full', action='store_true')
    parser.add_argument('--output', type=Path, help='artifact directory, ignored by Git or outside the checkout')
    parser.add_argument('--seed', type=Path, help='directory containing complete canonical Rust seed receipts')
    parser.add_argument('--language', choices=('rust', 'python'), default='rust')
    parser.add_argument('--profile', choices=tuple(PROFILES), default='all')
    parser.add_argument('--platforms', nargs='+', default=[platform.system()])
    parser.add_argument('--platform-label', default=platform.system())
    parser.add_argument('--profiles', nargs='+', default=['all'])
    parser.add_argument('--shard', type=int, default=1)
    parser.add_argument('--shards', type=int, default=1)
    args = parser.parse_args(argv)
    try:
        if args.action == 'select':
            if not args.full and not args.base:
                raise ValueError('selection requires --base or --full')
            targets = select(ROOT, changes_since(ROOT, args.base) if args.base else (), full=args.full)
            write(args.plan, serialize(targets))
            print(json.dumps(serialize(targets)))
            return 0
        targets = targets_from(args.plan)
        if args.seed is not None and (args.language != 'rust' or args.action not in ('run', 'check')):
            raise ValueError('seed reuse is only supported for Rust run and check')
        if (args.seed is not None and args.action == 'run'
                and (args.platform_label, args.profile) == (SEED_PLATFORM, SEED_PROFILE)):
            raise ValueError('canonical seed context must execute directly')
        output = (args.output or Path('mutation-results') / args.language).resolve()
        if output.is_relative_to(ROOT) and (output == ROOT or subprocess.run(
                ['git', 'check-ignore', '--quiet', '--', output.relative_to(ROOT).as_posix() + '/'],
                cwd=ROOT, check=False).returncode != 0):
            raise ValueError('mutation output must be ignored or outside the checkout')
        if args.action == 'run':
            run(targets, output, args.language, args.profile, args.shard, args.shards, args.platform_label, args.seed)
            return 0
        exclusions = tuple(Exclusion(text(value.get('group')), text(value.get('revision')),
                                     text(value.get('identity')), text(value.get('evidence')))
                           for item in sequence(read(ROOT / '.config/mutation-exclusions.json'))
                           for value in (record(item),))
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        with tempfile.TemporaryDirectory(prefix='pcr-mutation-check-') as directory:
            tree = snapshot(ROOT, Path(directory))
        revision = f'{revision} tree {tree}'
        version = text(record(configuration(ROOT).get('tools')).get(
            'cargo-mutants' if args.language == 'rust' else 'cosmic-ray'))
        if args.action == 'seed':
            if args.language != 'rust':
                raise ValueError('seed proofs are only supported for Rust')
            for target in targets:
                if target.language == 'rust':
                    (output / 'seed' / f'{target.group.replace("/", "_").replace(".", "_")}.json').unlink(missing_ok=True)
            proofs = seed_proofs(targets, tuple(output.rglob('run.json')), args.shards, revision, version)
            for group, proof in proofs.items():
                write(output / 'seed' / f'{group.replace("/", "_").replace(".", "_")}.json', proof)
            return 0
        return 0 if check(targets, tuple(output.rglob('run.json')), args.language,
                          tuple(args.platforms), tuple(args.profiles), args.shards, exclusions,
                          revision, version, args.seed) else 1
    except (OSError, ValueError, SubprocessError) as error:
        print(f'Mutation audit failed. {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
