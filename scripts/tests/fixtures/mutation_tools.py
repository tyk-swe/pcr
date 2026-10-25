# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tomllib


class CargoArguments(argparse.Namespace):
    version: bool
    listing: bool
    package: str
    file: list[str]
    shard: str | None
    output: Path | None
    jobs: int
    workspace: str
    all_features: bool
    no_default: bool
    features: str
    iterate: bool


def cargo(argv: list[str], failure: str) -> int:
    if argv[0] == 'test':
        print('controlled workspace baseline')
        return 7 if failure == 'empty-baseline' or failure == 'workspace-baseline' and '--workspace' in argv else 0
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='store_true')
    parser.add_argument('--list', dest='listing', action='store_true')
    parser.add_argument('--package', default='sample')
    parser.add_argument('--file', action='append', default=[])
    parser.add_argument('--shard')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--jobs', type=int, default=1)
    parser.add_argument('--test-workspace', dest='workspace', default='false')
    parser.add_argument('--all-features', dest='all_features', action='store_true')
    parser.add_argument('--no-default-features', dest='no_default', action='store_true')
    parser.add_argument('--features', default='')
    parser.add_argument('--iterate', action='store_true')
    args = CargoArguments()
    parser.parse_known_args(argv[1:], namespace=args)
    if args.version:
        print('cargo-mutants ' + os.environ.get('MUTATION_FIXTURE_VERSION', 'rust-fixture'))
        return 0
    if args.jobs != 1 or not Path('Cargo.toml').is_file():
        return 7
    package = Path('crates') / args.package
    features = frozenset(('default',) if not args.no_default else ()) | frozenset(
        name for name in ('layer2', 'layer3') if f'native-{name}' in args.features)
    feature = 'default+layer2+layer3' if args.all_features else '+'.join(sorted(features)) or 'portable'
    files = [path for path in (package / 'src/lib.rs', package / 'src/extra.rs') if path.is_file()]
    manifest = tomllib.loads((package / 'Cargo.toml').read_text())
    if any(target.get('path') == 'build.rs' for target in manifest.get('bin', [])):
        files.append(package / 'build.rs')
    reuse = os.environ.get('MUTATION_FIXTURE_REUSE', '')
    roles = ('shared-kill', 'shared-survivor', 'shared-timeout')
    inventory = [dict(name=f'{path}:1:1: {roles[index] if reuse else "fixture " + feature}', file=str(path))
                 for index, path in enumerate(files) if not args.file or str(path) in args.file]
    if reuse == 'mixed' and not args.all_features and (not args.file or str(files[0]) in args.file):
        inventory.append(dict(name=f'{files[0]}:1:1: shared-kill receiver-only', file=str(files[0])))
    context = os.environ.get('MUTATION_FIXTURE_CONTEXT', '')
    context_caught = 60 if args.package == 'sample' else 3
    if context:
        count = 65 if args.package == 'sample' else 3
        if not args.all_features and context != 'unreused':
            count += 2 if args.package != 'sample' or context == 'changed' else 1
        if context == 'unreused':
            count = 64 if args.package == 'sample' else 3
            context_caught = 0
        inventory = [dict(name=f'{files[index % len(files)]}:1:1: context {index}',
                          file=str(files[index % len(files)])) for index in range(count)
                     if not args.file or str(files[index % len(files)]) in args.file]
    if failure in ('empty', 'empty-baseline'):
        inventory = []
    if args.iterate:
        if args.output is None:
            return 7
        caught_file = args.output / 'mutants.out/previously_caught.txt'
        if not caught_file.is_file():
            return 7
        previous = frozenset(caught_file.read_text().splitlines())
        inventory = [mutant for mutant in inventory if mutant['name'] not in previous]
        print('INFO controlled iteration reads the supplied output directory', file=sys.stderr)
    if args.shard:
        numerator, denominator = (int(value) for value in args.shard.split('/'))
        inventory = inventory[numerator::denominator]
    if args.listing:
        if failure == ('shard-discovery' if args.shard else 'discovery'):
            return 7
        print(json.dumps(inventory))
        return 0
    if failure == 'runner':
        return 7
    if args.output is None:
        return 7
    if Path('marker.txt').read_text() != 'original':
        return 7
    Path('marker.txt').write_text('changed by SDK')
    output = args.output / 'mutants.out'
    (output / 'log').mkdir(parents=True, exist_ok=True)
    (output / 'log/baseline.log').write_text('controlled baseline')
    baseline = dict(scenario='Baseline', summary='Success', log_path='log/baseline.log',
                    phase_results=[dict(phase='Test', process_status='Success')])
    if failure == 'baseline':
        baseline['summary'] = 'Failure'
    caught = args.workspace == 'true' and failure != 'survivor'
    classified = tuple((mutant,
                        'Timeout' if failure == 'timeout' and index == 0
                        or reuse == 'mixed' and args.all_features and mutant['name'].endswith(': shared-timeout')
                        else 'MissedMutant' if not caught
                        or reuse == 'mixed' and args.all_features and mutant['name'].endswith(': shared-survivor')
                        or context and args.all_features and int(mutant['name'].rsplit(' ', 1)[1]) >= context_caught
                        else 'CaughtMutant') for index, mutant in enumerate(inventory))
    test_status: dict[str, object] = {'Timeout': 'Timeout', 'MissedMutant': 'Success', 'CaughtMutant': {'Failure': 101}}
    outcomes = [dict(scenario=dict(Mutant=mutant), summary=summary, log_path=f'log/{index}.log',
                     phase_results=[dict(phase='Build', process_status='Success'),
                                    dict(phase='Test', process_status=test_status[summary])])
                for index, (mutant, summary) in enumerate(classified)]
    for index in range(len(outcomes)):
        (output / f'log/{index}.log').write_text('controlled test result')
    report = dict(cargo_mutants_version='rust-fixture', end_time=None if failure == 'unfinished' else 'finished',
                  total_mutants=len(inventory) + int(failure == 'inconsistent'), outcomes=[baseline, *outcomes])
    if failure != 'missing-report':
        (output / 'outcomes.json').write_text(json.dumps(report))
    return 3 if any(summary == 'Timeout' for _, summary in classified) else 2 if any(
        summary == 'MissedMutant' for _, summary in classified) else 0


def cosmic(argv: list[str], failure: str) -> int:
    action = argv[0]
    if action == '--version':
        print('cosmic-ray, version ' + os.environ.get('MUTATION_FIXTURE_VERSION', 'python-fixture'))
        return 0
    if failure == action:
        return 7
    if action == 'init':
        Path(argv[2]).write_text(argv[1] + '\npending')
        return 0
    if action == 'dump':
        config_name, state = Path(argv[1]).read_text().splitlines()
        if state == 'baseline':
            if failure == 'baseline-export':
                return 7
            print(json.dumps([dict(job_id='baseline', mutations=[]),
                              json.loads(Path(argv[1]).with_suffix('.result').read_text())]))
            return 0
        settings = tomllib.loads(Path(config_name).read_text())['cosmic-ray']
        if failure == ('report-export' if state == 'complete' else 'inventory-export'):
            return 7
        if failure in ('empty', 'empty-baseline'):
            return 0
        for index in range(2):
            if failure == 'missing-mutation' and state == 'complete' and index == 1:
                continue
            item = dict(job_id=f'job-{index}', mutations=[dict(module_path=settings['module-path'],
                        operator_name='fixture/value', occurrence=index, start_pos=[1, 8], end_pos=[1, 9], operator_args={})])
            result = None
            if state == 'complete' and failure != 'incomplete':
                status = 'survived' if failure == 'survivor' else 'killed'
                output = 'MUTATION_RESULT ' + json.dumps(dict(kind='tests', run=1, failures=int(status == 'killed'), errors=0))
                if failure == 'runner-syntax':
                    output = Path(argv[1]).with_suffix('.output').read_text()
                if failure == 'timeout':
                    status, output = 'killed', 'timeout'
                result = dict(worker_outcome='exception' if failure == 'worker-error' else 'normal',
                              test_outcome=status, output=output, diff='controlled SDK mutation')
            print(json.dumps([item, result]))
        return 0
    settings = tomllib.loads(Path(argv[1]).read_text())['cosmic-ray']
    command = settings.get('test-command')
    module = settings.get('module-path')
    if not isinstance(command, str) or not isinstance(module, str) or not Path(module).is_file():
        return 7
    if action == 'baseline':
        Path(argv[argv.index('--session-file') + 1]).with_suffix('.timeout').write_text(str(settings['timeout']))
        if failure == 'empty-baseline':
            return 7
        baseline_path = Path(argv[argv.index('--session-file') + 1])
        if failure == 'baseline-zero-tests':
            baseline_result = dict(worker_outcome='normal', test_outcome='survived',
                                   output='MUTATION_RESULT {"kind":"tests","run":0,"failures":0,"errors":0}')
            baseline_exit = 0
        elif failure == 'baseline-incompetent':
            baseline_result = dict(worker_outcome='normal', test_outcome='incompetent', output='launcher unavailable')
            baseline_exit = 0
        else:
            tested = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=5, check=False)
            baseline_result = dict(worker_outcome='normal', test_outcome='survived' if tested.returncode == 0 else 'killed',
                                   output=tested.stdout)
            baseline_exit = tested.returncode
        baseline_path.write_text(argv[1] + '\nbaseline')
        baseline_path.with_suffix('.result').write_text(json.dumps(baseline_result))
        return baseline_exit
    if action == 'exec':
        Path(argv[2]).with_suffix('.timeout').write_text(str(settings['timeout']))
        if Path('marker.txt').read_text() != 'original':
            return 7
        Path('marker.txt').write_text('changed by SDK')
        if failure == 'runner-syntax':
            Path(module).write_text('def broken(:\n')
            tested = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=5, check=False)
            Path(argv[2]).with_suffix('.output').write_text(tested.stdout)
        Path(argv[2]).write_text(argv[1] + '\ncomplete')
        return 0
    return 7


if __name__ == '__main__':
    mode, *arguments = sys.argv[1:]
    failure = os.environ.get('MUTATION_FIXTURE_FAILURE', '')
    sys.exit(cargo(arguments, failure) if mode == 'cargo' else cosmic(arguments, failure))
