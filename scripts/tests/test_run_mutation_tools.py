# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from support import PYTHON_TOOL_VERSION, RUST_TOOL_VERSION, mutation_checkout, mutation_tools
from mutation_results import parse_report, score
from mutation_scope import Target


def invoke(root: Path, executable: Path, environment: dict[str, str], arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(executable), str(root / 'scripts/run_mutation.py'), *arguments], cwd=root,
                          env=environment, capture_output=True, text=True, timeout=10, check=False)


@unittest.skipUnless(os.name == 'posix', 'SDK doubles use POSIX launchers')
class MutationToolExecutionTests(unittest.TestCase):
    def test_cli_selects_owned_targets_and_runs_with_default_output_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            mutation_checkout(root)
            executable, environment = mutation_tools(root, Path(directory) / 'tools/bin')
            plan = Path(directory) / 'selection/plan.json'
            selected = invoke(root, executable, environment, ['select', '--full', '--plan', str(plan)])
            self.assertEqual(selected.returncode, 0, selected.stderr)
            targets = json.loads(plan.read_text())
            self.assertEqual(json.loads(selected.stdout), targets)
            self.assertEqual({value['group'] for value in targets if value['language'] == 'rust'}, {'sample', 'other'})
            self.assertEqual({value['group'] for value in targets if value['language'] == 'python'},
                             {'scripts/alpha.py', 'scripts/beta.py', 'scripts/mutation_results.py',
                              'scripts/mutation_scope.py', 'scripts/run_mutation.py', 'scripts/mutation_test_runner.py'})
            measured = invoke(root, executable, environment, ['run', '--plan', str(plan)])
            self.assertEqual(measured.returncode, 0, measured.stderr)
            checked = invoke(root, executable, environment, ['check', '--plan', str(plan)])
            self.assertEqual(checked.returncode, 0, checked.stderr)
            summaries = tuple(json.loads(line) for line in checked.stdout.splitlines())
            self.assertEqual({(value['group'], value['killed'], value['eligible']) for value in summaries},
                             {('sample', 3, 3), ('other', 1, 1)})
            self.assertTrue(all(value['tool_versions'] == [RUST_TOOL_VERSION] for value in summaries))
            self.assertEqual({json.loads(path.read_text())['report']['group']
                              for path in (root / 'mutation-results/rust').rglob('run.json')}, {'sample', 'other'})
            self.assertEqual((root / 'marker.txt').read_text(), 'original')
            identity = ('-c', 'user.name=Test', '-c', 'user.email=test@example.test')
            for command in (('add', '.'), (*identity, 'commit', '-qm', 'test: initialize SDK fixtures')):
                subprocess.run(['git', *command], cwd=root, env=environment, capture_output=True, check=True)
            (root / 'scripts/alpha.py').write_text('value = 1\n\n')
            for command in (('add', 'scripts/alpha.py'), (*identity, 'commit', '-qm', 'test: edit selected module')):
                subprocess.run(['git', *command], cwd=root, env=environment, capture_output=True, check=True)
            python_plan = Path(directory) / 'python.json'
            selected = invoke(root, executable, environment,
                              ['select', '--base', 'HEAD^', '--plan', str(python_plan)])
            self.assertEqual(selected.returncode, 0, selected.stderr)
            self.assertEqual(json.loads(selected.stdout), json.loads(python_plan.read_text()))
            self.assertEqual([(value['group'], value['files']) for value in json.loads(selected.stdout)],
                             [('scripts/alpha.py', ['scripts/alpha.py'])])
            arguments = ['--plan', str(python_plan), '--language', 'python']
            measured = invoke(root, executable, environment, ['run', *arguments])
            self.assertEqual(measured.returncode, 0, measured.stderr)
            checked = invoke(root, executable, environment, ['check', *arguments])
            self.assertEqual(checked.returncode, 0, checked.stderr)
            summary = json.loads(checked.stdout)
            self.assertEqual((summary['group'], summary['killed'], summary['eligible']), ('scripts/alpha.py', 2, 2))
            self.assertEqual(summary['tool_versions'], [PYTHON_TOOL_VERSION])
            self.assertEqual(len(tuple((root / 'mutation-results/python').rglob('run.json'))), 1)

    def test_completed_survivors_and_timeouts_fail_the_cli_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            mutation_checkout(root)
            executable, environment = mutation_tools(root, Path(directory) / 'tools/bin')
            for target, failure, killed, eligible, survivors, timeouts in (
                (Target('sample', 'rust', (), 'complete survivors'), 'survivor', 0, 3, 3, 0),
                (Target('scripts/alpha.py', 'python', ('scripts/alpha.py',), 'complete survivors'), 'survivor', 0, 2, 2, 0),
                (Target('sample', 'rust', (), 'complete timeout'), 'timeout', 2, 3, 0, 1),
            ):
                plan = Path(directory) / f'{target.language}-{failure}.json'
                plan.write_text(json.dumps([asdict(target)]))
                output = root / 'artifacts' / f'{target.language}-{failure}'
                arguments = ['--plan', str(plan), '--language', target.language, '--output', str(output)]
                measured = invoke(root, executable, environment | {'MUTATION_FIXTURE_FAILURE': failure}, ['run', *arguments])
                with self.subTest(language=target.language, failure=failure):
                    self.assertEqual(measured.returncode, 0, measured.stderr)
                    checked = invoke(root, executable, environment, ['check', *arguments])
                    self.assertEqual(checked.returncode, 1, checked.stderr)
                    published = json.loads(checked.stdout)
                    self.assertEqual((published['killed'], published['eligible'], published['invalid']), (killed, eligible, 0))
                    self.assertEqual(len(published['survivors']), survivors)
                    self.assertEqual(len(published['timeouts']), timeouts)
                    self.assertEqual(published['status'], 'failed')
                    self.assertFalse(published['passed'])
                    self.assertAlmostEqual(published['percentage'], 100 * killed / eligible)
                    version = RUST_TOOL_VERSION if target.language == 'rust' else PYTHON_TOOL_VERSION
                    self.assertEqual(published['tool_versions'], [version])

    def test_each_selected_target_receives_the_original_source_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            mutation_checkout(root)
            executable, environment = mutation_tools(root, Path(directory) / 'tools/bin')
            plan = Path(directory) / 'plan.json'
            targets = (Target('sample', 'rust', (), 'all sample files'),
                       Target('other', 'rust', ('crates/other/src/lib.rs',), 'one other file'),
                       Target('scripts/alpha.py', 'python', ('scripts/alpha.py',), 'other language'))
            plan.write_text(json.dumps([asdict(target) for target in targets]))
            output = root / 'artifacts'
            arguments = ['--plan', str(plan), '--language', 'rust', '--output', str(output)]
            result = invoke(root, executable, environment, ['run', *arguments])
            self.assertEqual(result.returncode, 0, result.stderr)
            reports = tuple(parse_report(json.loads(path.read_text())['report']) for path in output.rglob('run.json'))
            self.assertEqual({value.group for value in reports}, {'sample', 'other'})
            self.assertEqual({value.tool_version for value in reports}, {RUST_TOOL_VERSION})
            self.assertEqual(len({value.revision for value in reports}), 1)
            result = invoke(root, executable, environment, ['check', *arguments])
            self.assertEqual(result.returncode, 0, result.stderr)
            summaries = tuple(json.loads(line) for line in result.stdout.splitlines())
            self.assertEqual({(value['group'], value['killed'], value['eligible']) for value in summaries},
                             {('sample', 3, 3), ('other', 1, 1)})
            self.assertEqual((root / 'marker.txt').read_text(), 'original')

    def test_invalid_shards_and_wrong_tool_versions_are_refused_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            mutation_checkout(root)
            executable, environment = mutation_tools(root, Path(directory) / 'tools/bin')
            for target in (Target('sample', 'rust', (), 'controlled workspace'),
                           Target('scripts/alpha.py', 'python', ('scripts/alpha.py',), 'controlled module')):
                plan = Path(directory) / f'{target.language}.json'
                plan.write_text(json.dumps([asdict(target)]))
                for shard, shards in ((0, 1), (2, 1), (1, 0), (-1, 2)):
                    result = invoke(root, executable, environment, ['run', '--plan', str(plan), '--language', target.language,
                                    '--shard', str(shard), '--shards', str(shards),
                                    '--output', str(root / 'artifacts' / f'{target.language}-{shard}-{shards}')])
                    with self.subTest(language=target.language, shard=shard, shards=shards):
                        self.assertEqual(result.returncode, 1)
                        self.assertIn('invalid shard', result.stderr)
                other_version = PYTHON_TOOL_VERSION if target.language == 'rust' else RUST_TOOL_VERSION
                for version in ('aaa', 'zzz', other_version):
                    result = invoke(root, executable, environment | {'MUTATION_FIXTURE_VERSION': version},
                                    ['run', '--plan', str(plan), '--language', target.language,
                                     '--output', str(root / 'artifacts' / f'{target.language}-{version}')])
                    with self.subTest(language=target.language, version=version):
                        self.assertEqual(result.returncode, 1)
                        expected = RUST_TOOL_VERSION if target.language == 'rust' else PYTHON_TOOL_VERSION
                        self.assertIn(f'expected mutation tool {expected}, got {version}', result.stderr)
                        self.assertEqual((root / 'marker.txt').read_text(), 'original')

    def test_runner_mutations_use_an_immutable_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            mutation_checkout(root)
            executable, environment = mutation_tools(root, Path(directory) / 'tools/bin')
            module = 'scripts/mutation_test_runner.py'
            original = (root / module).read_bytes()
            plan = Path(directory) / 'plan.json'
            plan.write_text(json.dumps([asdict(Target(module, 'python', (module,), 'runner compilation'))]))
            output = root / 'artifacts'
            arguments = ['--plan', str(plan), '--language', 'python', '--output', str(output)]
            result = invoke(root, executable, environment | {'MUTATION_FIXTURE_FAILURE': 'runner-syntax'}, ['run', *arguments])
            self.assertEqual(result.returncode, 0, result.stderr)
            checked = invoke(root, executable, environment, ['check', *arguments])
            self.assertEqual(checked.returncode, 0, checked.stderr)
            summary = json.loads(checked.stdout)
            self.assertEqual((summary['killed'], summary['eligible'], summary['invalid']), (0, 0, 2))
            self.assertEqual(summary['status'], 'not_applicable')
            self.assertEqual((root / module).read_bytes(), original)

    def test_rust_tool_reports_cover_build_scripts_features_and_disposable_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            mutation_checkout(root)
            executable, environment = mutation_tools(root, Path(directory) / 'tools with spaces/bin')
            plan = Path(directory) / 'plan.json'
            plan.write_text(json.dumps([asdict(Target('sample', 'rust', (), 'controlled workspace'))]))
            manifest = (root / 'crates/sample/Cargo.toml').read_bytes()
            profiles = dict(portable='portable', default='default', layer2='layer2', layer3='layer3',
                            all='default+layer2+layer3')
            for profile, feature in profiles.items():
                output = root / 'artifacts' / profile
                arguments = ['--plan', str(plan), '--language', 'rust', '--output', str(output)]
                result = invoke(root, executable, environment, ['run', *arguments, '--profile', profile])
                with self.subTest(profile=profile):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    runs = tuple(output.rglob('run.json'))
                    self.assertEqual(len(runs), 1)
                    measured = parse_report(json.loads(runs[0].read_text())['report'])
                    self.assertEqual(measured.tool_version, RUST_TOOL_VERSION)
                    self.assertEqual(len(measured.expected), 3)
                    self.assertTrue(all(identity.endswith(f'fixture {feature}') for identity in measured.expected))
                    self.assertTrue(any('build.rs' in identity for identity in measured.expected))
                    self.assertEqual((score(measured).killed, score(measured).eligible), (3, 3))
                    checked = invoke(root, executable, environment, ['check', *arguments, '--profiles', profile])
                    self.assertEqual(checked.returncode, 0, checked.stderr)
                    self.assertEqual(json.loads(checked.stdout)['status'], 'passed')
                    self.assertEqual((root / 'marker.txt').read_text(), 'original')
                    self.assertEqual((root / 'crates/sample/Cargo.toml').read_bytes(), manifest)

    def test_python_tool_handles_an_interpreter_path_with_spaces(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            mutation_checkout(root)
            executable, environment = mutation_tools(root, Path(directory) / 'tools with spaces/bin')
            plan = Path(directory) / 'plan.json'
            target = Target('scripts/alpha.py', 'python', ('scripts/alpha.py',), 'controlled module')
            plan.write_text(json.dumps([asdict(target)]))
            output = root / 'artifacts'
            arguments = ['--plan', str(plan), '--language', 'python', '--output', str(output)]
            result = invoke(root, executable, environment, ['run', *arguments])
            self.assertEqual(result.returncode, 0, result.stderr)
            runs = tuple(output.rglob('run.json'))
            self.assertEqual(len(runs), 1)
            measured = parse_report(json.loads(runs[0].read_text())['report'])
            self.assertEqual(measured.tool_version, PYTHON_TOOL_VERSION)
            self.assertEqual((score(measured).killed, score(measured).eligible), (2, 2))
            checked = invoke(root, executable, environment, ['check', *arguments])
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertEqual(json.loads(checked.stdout)['status'], 'passed')
            self.assertEqual((root / 'marker.txt').read_text(), 'original')

    def test_external_failures_never_publish_a_completed_measurement(self) -> None:
        rust_failures = ('discovery', 'shard-discovery', 'runner', 'baseline', 'workspace-baseline', 'unfinished',
                         'missing-report', 'inconsistent', 'empty-baseline')
        python_failures = ('init', 'inventory-export', 'baseline', 'baseline-export', 'baseline-incompetent', 'exec', 'report-export',
                           'worker-error', 'incomplete', 'missing-mutation', 'empty-baseline')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            mutation_checkout(root)
            executable, environment = mutation_tools(root, Path(directory) / 'tools/bin')
            for language, failures, target in (
                ('rust', rust_failures, Target('sample', 'rust', (), 'controlled workspace')),
                ('python', python_failures, Target('scripts/alpha.py', 'python', ('scripts/alpha.py',), 'controlled module')),
            ):
                plan = Path(directory) / f'{language}.json'
                plan.write_text(json.dumps([asdict(target)]))
                for failure in failures:
                    output = root / 'artifacts' / language / failure
                    arguments = ['--plan', str(plan), '--language', language, '--output', str(output)]
                    result = invoke(root, executable, environment | {'MUTATION_FIXTURE_FAILURE': failure}, ['run', *arguments])
                    with self.subTest(language=language, failure=failure):
                        self.assertEqual(result.returncode, 1)
                        self.assertTrue(result.stderr.startswith('Mutation audit failed.'), result.stderr)
                        for path in output.rglob('run.json'):
                            self.assertNotIn('report', json.loads(path.read_text()))
                        checked = invoke(root, executable, environment, ['check', *arguments])
                        self.assertEqual(checked.returncode, 1)
                        self.assertEqual((root / 'marker.txt').read_text(), 'original')

    def test_scoped_shards_combine_once_and_omissions_fail_the_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            mutation_checkout(root)
            executable, environment = mutation_tools(root, Path(directory) / 'tools/bin')
            plan = Path(directory) / 'plan.json'
            target = Target('sample', 'rust', ('crates/sample/src/lib.rs', 'crates/sample/build.rs'), 'controlled files')
            plan.write_text(json.dumps([asdict(target)]))
            output = root / 'artifacts'
            for shard in (1, 2):
                result = invoke(root, executable, environment, ['run', '--plan', str(plan), '--language', 'rust',
                                '--shard', str(shard), '--shards', '2', '--output', str(output / str(shard))])
                self.assertEqual(result.returncode, 0, result.stderr)
            arguments = ['check', '--plan', str(plan), '--language', 'rust', '--shards', '2', '--output', str(output)]
            result = invoke(root, executable, environment, arguments)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual((summary['killed'], summary['eligible']), (2, 2))
            next((output / '2').rglob('run.json')).unlink()
            result = invoke(root, executable, environment, arguments)
            self.assertEqual(result.returncode, 1)
            self.assertIn('missing', result.stderr)

    def test_empty_discovery_runs_a_baseline_and_preserves_the_selection_reason(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            mutation_checkout(root)
            executable, environment = mutation_tools(root, Path(directory) / 'tools/bin')
            for target in (Target('sample', 'rust', (), 'no viable fixture mutations'),
                           Target('scripts/alpha.py', 'python', ('scripts/alpha.py',), 'no viable fixture mutations')):
                plan = Path(directory) / f'{target.language}.json'
                plan.write_text(json.dumps([asdict(target)]))
                output = root / 'artifacts' / target.language
                arguments = ['--plan', str(plan), '--language', target.language, '--output', str(output)]
                result = invoke(root, executable, environment | {'MUTATION_FIXTURE_FAILURE': 'empty'}, ['run', *arguments])
                with self.subTest(language=target.language):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    checked = invoke(root, executable, environment, ['check', *arguments])
                    self.assertEqual(checked.returncode, 0, checked.stderr)
                    summary = json.loads(checked.stdout)
                    self.assertEqual(summary['status'], 'not_applicable')
                    self.assertIsNone(summary['percentage'])
                    self.assertEqual(summary['reason'], target.reason)
