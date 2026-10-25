# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from support import PYTHON_TOOL_VERSION, RUST_TOOL_VERSION, mutation_checkout, mutation_tools
from mutation_results import parse_report, score
from mutation_scope import Target
from mutation_reuse import parse_seed


def invoke(root: Path, executable: Path, environment: dict[str, str], arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(executable), str(root / 'scripts/run_mutation.py'), *arguments], cwd=root,
                          env=environment, capture_output=True, text=True, timeout=10, check=False)


def create_seed(root: Path, executable: Path, environment: dict[str, str], plan: Path, output: Path) -> Path:
    for shard in (1, 2):
        invoke(root, executable, environment, ['run', '--plan', str(plan), '--language', 'rust',
            '--profile', 'all', '--platform-label', 'ubuntu-24.04', '--shard', str(shard), '--shards', '2',
            '--output', str(output / str(shard))]).check_returncode()
    invoke(root, executable, environment, ['seed', '--plan', str(plan), '--language', 'rust',
        '--shards', '2', '--output', str(output)]).check_returncode()
    return output / 'seed'


def coverage_digest(value: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')).hexdigest()


def create_context(root: Path, executable: Path, environment: dict[str, str], plan: Path,
                   seed: Path, output: Path) -> Path:
    result = invoke(root, executable, environment, ['context', '--plan', str(plan), '--language', 'rust',
        '--profile', 'portable', '--platform-label', 'ubuntu-24.04', '--seed', str(seed), '--output', str(output)])
    result.check_returncode()
    return output / 'context.json'


@unittest.skipUnless(os.name == 'posix', 'SDK doubles use POSIX launchers')
class MutationToolExecutionTests(unittest.TestCase):
    def test_context_plans_run_every_group_with_recomputed_shards(self) -> None:
        for mode, shards, counts in (('scaled', 4, {'sample': (6, 60), 'other': (2, 3)}),
                                     ('all', 1, {'sample': (0, 3), 'other': (0, 1)})):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / 'checkout'
                mutation_checkout(root)
                executable, environment = mutation_tools(root, Path(directory) / 'tools/bin')
                environment = environment | ({'MUTATION_FIXTURE_REUSE': 'all'} if mode == 'all'
                                             else {'MUTATION_FIXTURE_CONTEXT': mode})
                plan = Path(directory) / 'plan.json'
                plan.write_text(json.dumps([asdict(Target(group, 'rust', (), 'controlled contexts'))
                                            for group in ('sample', 'other')]))
                output = root / 'artifacts'
                seed = create_seed(root, executable, environment, plan, output / 'seed-run')
                contexts = output / 'contexts'
                context = create_context(root, executable, environment, plan, seed, contexts / 'portable')
                self.assertEqual(json.loads(context.read_text())['shards'], shards)
                for shard in range(1, shards + 1):
                    folder = output / 'receiver' / str(shard) / 'run'
                    result = invoke(root, executable, environment, ['run', '--plan', str(plan), '--language', 'rust',
                        '--profile', 'portable', '--platform-label', 'ubuntu-24.04', '--shard', str(shard),
                        '--shards', str(shards), '--seed', str(seed), '--context-plan', str(context), '--output', str(folder)])
                    self.assertEqual(result.returncode, 0, result.stderr)
                    for path in folder.rglob('run.json'):
                        measured = parse_report(json.loads(path.read_text())['report'])
                        self.assertEqual(len(measured.expected), counts[measured.group][0])
                        self.assertTrue(all(outcome.status == 'killed' for outcome in measured.outcomes))
                arguments = ['check', '--plan', str(plan), '--language', 'rust', '--seed', str(seed),
                    '--contexts', str(contexts), '--output', str(output), '--platforms', 'ubuntu-24.04',
                    '--profiles', 'all', 'portable', '--shards', '2']
                checked = invoke(root, executable, environment, arguments)
                self.assertEqual(checked.returncode, 0, checked.stderr)
                summaries = [json.loads(line) for line in checked.stdout.splitlines()]
                self.assertEqual({summary['group'] for summary in summaries}, set(counts))
                for summary in summaries:
                    executed, reused = counts[summary['group']]
                    self.assertEqual((summary['killed'], summary['eligible']), (executed + reused, executed + reused))
                    self.assertEqual(next((item['executed'], item['reused']) for item in summary['execution_contexts']
                                          if item['profile'] == 'portable'), (executed, reused))
                if mode == 'all':
                    failed = invoke(root, executable, environment | {'MUTATION_FIXTURE_FAILURE': 'workspace-baseline'},
                        ['run', '--plan', str(plan), '--language', 'rust', '--profile', 'portable',
                         '--platform-label', 'ubuntu-24.04', '--shards', '1', '--seed', str(seed),
                         '--context-plan', str(context), '--output', str(output / 'failed')])
                    self.assertEqual(failed.returncode, 1)
                    self.assertIn('workspace baseline', failed.stderr)
                    continue
                receipt = next((output / 'receiver/4').rglob('run.json'))
                original = receipt.read_bytes()
                receipt.unlink()
                self.assertEqual(invoke(root, executable, environment, arguments).returncode, 1)
                receipt.write_bytes(original)
                original_context = context.read_bytes()
                context.unlink()
                self.assertEqual(invoke(root, executable, environment, arguments).returncode, 1)
                context.write_bytes(original_context)

    def test_context_run_rejects_changed_inventory_and_forged_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            mutation_checkout(root)
            executable, environment = mutation_tools(root, Path(directory) / 'tools/bin')
            environment = environment | {'MUTATION_FIXTURE_CONTEXT': 'scaled'}
            plan = Path(directory) / 'plan.json'
            plan.write_text(json.dumps([asdict(Target('sample', 'rust', (), 'controlled contexts'))]))
            output = root / 'artifacts'
            seed = create_seed(root, executable, environment, plan, output / 'seed-run')
            context = create_context(root, executable, environment, plan, seed, output / 'contexts/portable')
            original = context.read_bytes()
            command = ['run', '--plan', str(plan), '--language', 'rust', '--profile', 'portable',
                       '--platform-label', 'ubuntu-24.04', '--shards', '4', '--seed', str(seed),
                       '--context-plan', str(context), '--output', str(output / 'receiver/run')]
            changed = invoke(root, executable, environment | {'MUTATION_FIXTURE_CONTEXT': 'changed'}, command)
            self.assertEqual(changed.returncode, 1)
            for field in ('shards', 'inventory', 'source', 'scope', 'seed'):
                forged = json.loads(original)
                arguments = command.copy()
                if field == 'shards':
                    forged['shards'] = 1
                    arguments[arguments.index('--shards') + 1] = '1'
                elif field == 'inventory':
                    forged['groups'][0]['inventory'][-1] += ' forged'
                elif field == 'source':
                    forged['revision'] = '0' * 40 + ' tree ' + '0' * 64
                elif field == 'scope':
                    forged['groups'][0]['target']['files'] = ['crates/sample/src/lib.rs']
                else:
                    forged['groups'][0]['seed_digest'] = '0' * 64
                context.write_text(json.dumps(forged))
                with self.subTest(field=field):
                    self.assertEqual(invoke(root, executable, environment, arguments).returncode, 1)
                context.write_bytes(original)
            environment = environment | {'MUTATION_FIXTURE_CONTEXT': 'unreused'}
            other_seed = create_seed(root, executable, environment, plan, output / 'unreused-seed')
            other_context = create_context(root, executable, environment, plan, other_seed,
                                           output / 'unreused-contexts/portable')
            self.assertEqual(json.loads(other_context.read_text())['shards'], 64)

    def test_seed_receiver_executes_remaining_and_new_ids_with_direct_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            mutation_checkout(root)
            executable, environment = mutation_tools(root, Path(directory) / 'tools/bin')
            environment = environment | {'MUTATION_FIXTURE_REUSE': 'mixed'}
            target = Target('sample', 'rust', (), 'controlled reuse')
            plan = Path(directory) / 'plan.json'
            plan.write_text(json.dumps([asdict(target)]))
            killed = 'crates/sample/src/lib.rs:1:1: shared-kill'
            survivor = 'crates/sample/src/extra.rs:1:1: shared-survivor'
            timed_out = 'crates/sample/build.rs:1:1: shared-timeout'
            new = killed + ' receiver-only'
            trap = root / 'mutants.out/previously_caught.txt'
            trap.parent.mkdir()
            trap.write_text(new + '\n')
            output = root / 'artifacts'
            seed = create_seed(root, executable, environment, plan, output / 'seed-run')
            seed_text = (seed / 'sample.json').read_text()
            self.assertEqual({item['status'] for item in json.loads(seed_text)['report']['outcomes']},
                             {'killed', 'survived', 'timeout'})
            coverage: dict[str, object] = dict(inventory=[killed, survivor, timed_out, new],
                                               reused_ids=[killed], seed=seed_text)
            for shard, executed in ((1, (survivor, new)), (2, (timed_out,))):
                folder = output / 'receiver' / str(shard)
                result = invoke(root, executable, environment, ['run', '--plan', str(plan), '--language', 'rust',
                    '--profile', 'portable', '--platform-label', 'ubuntu-24.04', '--shard', str(shard), '--shards', '2',
                    '--seed', str(seed), '--output', str(folder)])
                self.assertEqual(result.returncode, 0, result.stderr)
                metadata = json.loads(next(folder.rglob('run.json')).read_text())
                actual = parse_report(metadata['report'])
                self.assertEqual(actual.expected, (survivor, timed_out, new))
                self.assertEqual(tuple(item.identity for item in actual.outcomes), executed)
                self.assertEqual({item.status for item in actual.outcomes}, {'killed'})
                self.assertEqual(metadata['coverage_digest'], coverage_digest(coverage))
                self.assertEqual(metadata['coverage'], coverage if shard == 1 else None)
            result = invoke(root, executable, environment, ['check', '--plan', str(plan), '--language', 'rust',
                '--seed', str(seed), '--output', str(output), '--platforms', 'ubuntu-24.04',
                '--profiles', 'all', 'portable', '--shards', '2'])
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual((summary['killed'], summary['eligible']), (4, 4))
            self.assertEqual(summary['status'], 'passed')
            self.assertEqual({item['profile']: (item['executed'], item['reused'])
                              for item in summary['execution_contexts']}, {'all': (3, 0), 'portable': (3, 1)})

    def test_receiver_refuses_stale_seeds_and_missing_coverage_or_shards(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            mutation_checkout(root)
            executable, environment = mutation_tools(root, Path(directory) / 'tools/bin')
            environment = environment | {'MUTATION_FIXTURE_REUSE': 'mixed'}
            plan = Path(directory) / 'plan.json'
            plan.write_text(json.dumps([asdict(Target('sample', 'rust', (), 'controlled reuse'))]))
            output = root / 'artifacts'
            seed = create_seed(root, executable, environment, plan, output / 'seed-run')
            for shard in (1, 2):
                invoke(root, executable, environment, ['run', '--plan', str(plan), '--language', 'rust',
                    '--profile', 'portable', '--platform-label', 'ubuntu-24.04', '--shard', str(shard), '--shards', '2',
                    '--seed', str(seed), '--output', str(output / 'receiver' / str(shard))]).check_returncode()
            command = ['check', '--plan', str(plan), '--language', 'rust', '--seed', str(seed), '--output', str(output),
                       '--platforms', 'ubuntu-24.04', '--profiles', 'all', 'portable', '--shards', '2']
            invoke(root, executable, environment, command).check_returncode()
            first = next((output / 'receiver/1').rglob('run.json'))
            second = next((output / 'receiver/2').rglob('run.json'))
            original, second_original = first.read_bytes(), second.read_bytes()
            for change in ('missing-coverage', 'all-coverage-absent', 'bad-digest', 'stale-embedded-seed',
                           'reused-nonkill', 'missing-executable'):
                metadata = json.loads(original)
                other = json.loads(second_original)
                if change == 'missing-coverage':
                    metadata['coverage'] = None
                elif change == 'all-coverage-absent':
                    for receipt in (metadata, other):
                        receipt.pop('coverage')
                        receipt.pop('coverage_digest')
                elif change == 'bad-digest':
                    metadata['coverage_digest'] = '0' * 64
                elif change == 'stale-embedded-seed':
                    stale = json.loads(metadata['coverage']['seed'])
                    stale['report']['revision'] = '0' * 40 + ' tree ' + '0' * 64
                    metadata['coverage']['seed'] = json.dumps(stale)
                elif change == 'reused-nonkill':
                    metadata['coverage']['reused_ids'].append(metadata['report']['expected'][0])
                else:
                    expected = metadata['report']['expected'][1:]
                    for receipt in (metadata, other):
                        receipt['report']['expected'] = expected
                        receipt['report']['outcomes'] = [outcome for outcome in receipt['report']['outcomes']
                                                         if outcome['identity'] in expected]
                if change in ('stale-embedded-seed', 'reused-nonkill', 'missing-executable'):
                    metadata['coverage_digest'] = coverage_digest(metadata['coverage'])
                    other['coverage_digest'] = metadata['coverage_digest']
                first.write_text(json.dumps(metadata))
                second.write_text(json.dumps(other))
                with self.subTest(change=change):
                    refused = invoke(root, executable, environment, command)
                    self.assertEqual(refused.returncode, 1)
                first.write_bytes(original)
                second.write_bytes(second_original)
            second.unlink()
            self.assertEqual(invoke(root, executable, environment, command).returncode, 1)
            second.write_bytes(second_original)
            canonical_first = next((output / 'seed-run/1').rglob('run.json'))
            canonical_second = next((output / 'seed-run/2').rglob('run.json'))
            first_seed, second_seed = canonical_first.read_bytes(), canonical_second.read_bytes()
            canonical_first.write_bytes(second_seed)
            canonical_second.write_bytes(first_seed)
            reversed_result = invoke(root, executable, environment, command)
            self.assertEqual(reversed_result.returncode, 0, reversed_result.stderr)
            canonical_first.write_bytes(first_seed)
            canonical_second.write_bytes(second_seed)
            for field, value in (('status', 'survived'), ('evidence', 'different execution evidence')):
                changed_seed = json.loads(first_seed)
                changed_seed['report']['outcomes'][0][field] = value
                canonical_first.write_text(json.dumps(changed_seed))
                with self.subTest(canonical=field):
                    self.assertEqual(invoke(root, executable, environment, command).returncode, 1)
                canonical_first.write_bytes(first_seed)
            canonical_first.unlink()
            canonical_second.unlink()
            self.assertEqual(invoke(root, executable, environment, command).returncode, 1)
            canonical_first.write_bytes(first_seed)
            canonical_second.write_bytes(second_seed)
            proof = seed / 'sample.json'
            valid = proof.read_text()
            for label, invalid in (('malformed', '{}'), ('stale', valid.replace(
                    json.loads(valid)['report']['revision'], '0' * 40 + ' tree ' + '0' * 64))):
                proof.write_text(invalid)
                refused = invoke(root, executable, environment, ['run', '--plan', str(plan), '--language', 'rust',
                    '--profile', 'portable', '--platform-label', 'ubuntu-24.04', '--seed', str(seed),
                    '--output', str(Path(directory) / label)])
                with self.subTest(seed=label):
                    self.assertEqual(refused.returncode, 1)
                proof.write_text(valid)

    def test_all_reused_receiver_still_requires_its_workspace_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            mutation_checkout(root)
            executable, environment = mutation_tools(root, Path(directory) / 'tools/bin')
            environment = environment | {'MUTATION_FIXTURE_REUSE': 'all'}
            plan = Path(directory) / 'plan.json'
            plan.write_text(json.dumps([asdict(Target('sample', 'rust', (), 'controlled reuse'))]))
            output = root / 'artifacts'
            seed = create_seed(root, executable, environment, plan, output / 'seed-run')
            for shard in (1, 2):
                folder = output / 'receiver' / str(shard)
                measured = invoke(root, executable, environment, ['run', '--plan', str(plan), '--language', 'rust',
                    '--profile', 'portable', '--platform-label', 'ubuntu-24.04', '--shard', str(shard), '--shards', '2',
                    '--seed', str(seed), '--output', str(folder)])
                self.assertEqual(measured.returncode, 0, measured.stderr)
                actual = parse_report(json.loads(next(folder.rglob('run.json')).read_text())['report'])
                self.assertEqual(actual.expected, ())
                self.assertEqual(actual.outcomes, ())
            checked = invoke(root, executable, environment, ['check', '--plan', str(plan), '--language', 'rust',
                '--seed', str(seed), '--output', str(output), '--platforms', 'ubuntu-24.04',
                '--profiles', 'all', 'portable', '--shards', '2'])
            self.assertEqual(checked.returncode, 0, checked.stderr)
            summary = json.loads(checked.stdout)
            self.assertEqual((summary['killed'], summary['eligible'], summary['invalid']), (3, 3, 0))
            self.assertEqual(summary['status'], 'passed')
            self.assertEqual({item['profile']: (item['executed'], item['reused'])
                              for item in summary['execution_contexts']}, {'all': (3, 0), 'portable': (0, 3)})
            failed = invoke(root, executable, environment | {'MUTATION_FIXTURE_FAILURE': 'workspace-baseline'},
                ['run', '--plan', str(plan), '--language', 'rust', '--profile', 'portable',
                 '--platform-label', 'ubuntu-24.04', '--seed', str(seed), '--output', str(output / 'failed')])
            self.assertEqual(failed.returncode, 1)
            self.assertIn('workspace baseline', failed.stderr)
            for path in (output / 'failed').rglob('run.json'):
                self.assertNotIn('report', json.loads(path.read_text()))

    def test_seed_command_publishes_only_complete_workspace_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            mutation_checkout(root)
            executable, environment = mutation_tools(root, Path(directory) / 'tools/bin')
            target = Target('sample', 'rust', (), 'controlled seed')
            plan = Path(directory) / 'plan.json'
            plan.write_text(json.dumps([asdict(target)]))
            output = root / 'artifacts'
            arguments = ['--plan', str(plan), '--language', 'rust', '--output', str(output)]
            ran = invoke(root, executable, environment, ['run', *arguments, '--platform-label', 'ubuntu-24.04'])
            self.assertEqual(ran.returncode, 0, ran.stderr)
            result = invoke(root, executable, environment, ['seed', *arguments])
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt_path = next(output.rglob('run.json'))
            receipt = json.loads(receipt_path.read_text())
            revision, digest = receipt['report']['revision'].split(' tree ')
            proof_path = output / 'seed/sample.json'
            seed = parse_seed(proof_path.read_bytes(), target=target, revision=revision,
                              source_digest=digest, tool_version=RUST_TOOL_VERSION)
            self.assertEqual({outcome.status for outcome in seed.report.outcomes}, {'killed'})
            self.assertEqual(len(seed.report.outcomes), 3)
            receipt['workspace_baseline'] = False
            receipt_path.write_text(json.dumps(receipt))
            result = invoke(root, executable, environment, ['seed', *arguments])
            self.assertEqual(result.returncode, 1)
            self.assertIn('workspace baseline', result.stderr)
            self.assertFalse(proof_path.exists())

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
                             'scripts/mutation_scope.py', 'scripts/run_mutation.py', 'scripts/mutation_test_runner.py',
                             'scripts/mutation_reuse.py', 'scripts/script_support.py'})
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
