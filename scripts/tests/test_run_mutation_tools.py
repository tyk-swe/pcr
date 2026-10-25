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

from support import mutation_checkout, mutation_tools
from mutation_results import parse_report, score
from mutation_scope import Target


def invoke(root: Path, executable: Path, environment: dict[str, str], arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(executable), str(root / 'scripts/run_mutation.py'), *arguments], cwd=root,
                          env=environment, capture_output=True, text=True, timeout=10, check=False)


@unittest.skipUnless(os.name == 'posix', 'SDK doubles use POSIX launchers')
class MutationToolExecutionTests(unittest.TestCase):
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
                for version in ('aaa', 'zzz'):
                    result = invoke(root, executable, environment | {'MUTATION_FIXTURE_VERSION': version},
                                    ['run', '--plan', str(plan), '--language', target.language,
                                     '--output', str(root / 'artifacts' / f'{target.language}-{version}')])
                    with self.subTest(language=target.language, version=version):
                        self.assertEqual(result.returncode, 1)
                        self.assertIn(f'expected mutation tool version, got {version}', result.stderr)
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
            self.assertEqual((score(measured).killed, score(measured).eligible), (2, 2))
            checked = invoke(root, executable, environment, ['check', *arguments])
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertEqual(json.loads(checked.stdout)['status'], 'passed')
            self.assertEqual((root / 'marker.txt').read_text(), 'original')

    def test_external_failures_never_publish_a_completed_measurement(self) -> None:
        rust_failures = ('discovery', 'shard-discovery', 'runner', 'baseline', 'unfinished',
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
