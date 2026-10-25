from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
from subprocess import SubprocessError
import sys
import tempfile
from typing import Sequence

from mutation_results import (Exclusion, Outcome, Report, Status, cosmic_identity, cosmic_results,
                              integer, parse_report, record, rust_results, score, sequence, text)
from mutation_scope import Target, changes_since, configuration, select, serialize

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


def targets_from(path: Path) -> tuple[Target, ...]:
    values = tuple(record(value) for value in sequence(read(path)))
    if any(value.get('language') not in ('rust', 'python') for value in values):
        raise ValueError('invalid mutation language')
    return tuple(Target(text(value.get('group')), 'rust' if value['language'] == 'rust' else 'python',
                        tuple(text(file) for file in sequence(value.get('files'))),
                        text(value.get('reason'))) for value in values)


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
        digest.update(name.encode() + b'\0' + target.read_bytes())
    return digest.hexdigest()


def rust(target: Target, root: Path, output: Path, profile: str, shard: int, shards: int) -> Report:
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
    inventory_path = output / 'inventory.json'
    if command([*args, '--list', '--json'], root, inventory_path):
        raise ValueError('Rust mutation discovery failed')
    inventory = read(inventory_path)
    selected_path = output / 'selected.json'
    partition = ['--shard', f'{shard - 1}/{shards}']
    if command([*args, *partition, '--list', '--json'], root, selected_path):
        raise ValueError('Rust shard discovery failed')
    selected = read(selected_path)
    if not sequence(selected):
        if command(['cargo', 'test', '--locked', '--workspace', *PROFILES[profile]],
                   root, output / 'baseline.log'):
            raise ValueError('Rust baseline failed for an empty mutation selection')
        version = subprocess.check_output(['cargo', 'mutants', '--version'], text=True).split()[-1]
        return Report(target.group, '', version, target.reason,
                      tuple(text(record(mutant).get('name')) for mutant in sequence(inventory)),
                      (), True, True)
    exit_code = command([*args, *partition, '--jobs', '1', '--output', str(output),
                         '--minimum-test-timeout', '30'], root, output / 'execution.log')
    if exit_code not in (0, 2, 3):
        raise ValueError(f'cargo-mutants runner failed with {exit_code}')
    raw = record(read(output / 'mutants.out/outcomes.json'))
    log_paths = tuple(text(record(outcome).get('log_path'))
                      for outcome in sequence(raw.get('outcomes')))
    logs = {path: (output / 'mutants.out' / path).read_text(encoding='utf-8') for path in log_paths}
    outcomes = rust_results(selected, raw, logs)
    return Report(target.group, '', text(raw.get('cargo_mutants_version')), target.reason,
                  tuple(text(record(mutant).get('name')) for mutant in sequence(inventory)),
                  outcomes, True, True)


def python(target: Target, root: Path, output: Path, version: str) -> Report:
    config = output / 'cosmic.toml'
    test_command = f'{sys.executable} scripts/tests/mutation_test_runner.py --module {target.group}'
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
    for label, args in (('baseline', [str(config)]), ('exec', [str(config), str(session)])):
        if command([*cosmic, label, *args], root, output / f'{label}.log'):
            raise ValueError(f'Cosmic Ray {label} failed')
    dump = output / 'cosmic.jsonl'
    if command([*cosmic, 'dump', str(session)], root, dump):
        raise ValueError('Cosmic Ray report export failed')
    rows = [json.loads(line) for line in dump.read_text(encoding='utf-8').splitlines()]
    outcomes = cosmic_results(rows)
    if {outcome.identity for outcome in outcomes} != set(expected):
        raise ValueError('Cosmic Ray did not run every discovered mutant')
    return Report(target.group, '', version, target.reason, expected, outcomes, True, True)


def run(targets: tuple[Target, ...], output: Path, language: str, profile: str,
        shard: int, shards: int, platform_label: str) -> None:
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
                                                 platform_label, revision, tree, version)) is not None)
    if failures:
        raise ValueError('\n'.join(failures))


def run_target(target: Target, source: Path, output: Path, profile: str, shard: int, shards: int,
               platform_label: str, revision: str, tree: str, version: str) -> str | None:
    folder = output / target.group.replace('/', '_').replace('.', '_')
    folder.mkdir(parents=True, exist_ok=True)
    metadata = dict(platform=platform_label, profile=profile, shard=shard, shards=shards)
    write(folder / 'run.json', {**metadata, 'group': target.group, 'complete': False})
    try:
        with tempfile.TemporaryDirectory(prefix='pcr-mutation-') as directory:
            checkout = Path(directory)
            shutil.copytree(source, checkout, dirs_exist_ok=True)
            report = (rust(target, checkout, folder, profile, shard, shards) if target.language == 'rust'
                      else python(target, checkout, folder, version))
        write(folder / 'run.json', {**metadata, 'report': asdict(replace(report, revision=f'{revision} tree {tree}'))})
        return None
    except (OSError, ValueError, SubprocessError) as error:
        return f'{target.group} failed. {error}'


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


def check(targets: tuple[Target, ...], paths: tuple[Path, ...], language: str,
          platforms: tuple[str, ...], profiles: tuple[str, ...], shards: int,
          exclusions: tuple[Exclusion, ...], revision: str, tool_version: str) -> bool:
    if (shards < 1 or not platforms or not profiles
            or len(set(platforms)) != len(platforms) or len(set(profiles)) != len(profiles)):
        raise ValueError('invalid required mutation matrix')
    runs = tuple(record(read(path)) for path in paths)
    reports = tuple(parse_report(run.get('report')) for run in runs)
    if any(report.revision.split(' tree ')[0] != revision or report.tool_version != tool_version
           for report in reports):
        raise ValueError('mutation artifacts do not match the tested revision or pinned tool version')
    allowed = {target.group for target in targets if target.language == language}
    if any(report.group not in allowed for report in reports):
        raise ValueError('unexpected mutation group')
    if any(run.get('platform') not in platforms or run.get('profile') not in profiles for run in runs):
        raise ValueError('unexpected mutation platform or feature profile')
    scores = tuple(score(merge_reports(tuple(cohort(tuple(zip(runs, reports)), group, system, profile, shards)
                                            for system in platforms for profile in profiles)), exclusions)
                   for group in sorted(allowed))
    for result in scores:
        print(json.dumps({**asdict(result), 'platforms': platforms, 'profiles': profiles,
                          'percentage': 100 * result.killed / result.eligible if result.eligible else None,
                          'revisions': sorted({report.revision for report in reports if report.group == result.group}),
                          'tool_versions': sorted({report.tool_version for report in reports if report.group == result.group}),
                          'status': 'not_applicable' if result.eligible == 0 else
                          'passed' if result.passed else 'failed', 'passed': result.passed}))
    return all(result.passed for result in scores)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('select', 'run', 'check'))
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--base')
    parser.add_argument('--full', action='store_true')
    parser.add_argument('--output', type=Path)
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
        output = args.output or Path('mutation-results') / args.language
        if args.action == 'run':
            run(targets, output, args.language, args.profile, args.shard, args.shards, args.platform_label)
            return 0
        exclusions = tuple(Exclusion(text(value.get('group')), text(value.get('revision')),
                                     text(value.get('identity')), text(value.get('evidence')))
                           for item in sequence(read(ROOT / '.config/mutation-exclusions.json'))
                           for value in (record(item),))
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        version = text(record(configuration(ROOT).get('tools')).get(
            'cargo-mutants' if args.language == 'rust' else 'cosmic-ray'))
        return 0 if check(targets, tuple(output.rglob('run.json')), args.language,
                          tuple(args.platforms), tuple(args.profiles), args.shards, exclusions,
                          revision, version) else 1
    except (OSError, ValueError, SubprocessError) as error:
        print(f'Mutation audit failed. {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
