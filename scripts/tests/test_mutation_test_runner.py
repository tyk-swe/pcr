# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from textwrap import indent
import unittest

from support import ROOT, mutation_checkout


def runner_checkout(root: Path) -> None:
    mutation_checkout(root)
    (root / 'scripts/mutation_test_runner.py').write_bytes((ROOT / 'scripts/mutation_test_runner.py').read_bytes())
    (root / 'scripts/tests/test_alpha.py').write_text(
        'import sys\nfrom pathlib import Path\nimport unittest\n'
        'sys.path.insert(0, str(Path(__file__).resolve().parents[1]))\nfrom alpha import value\n'
        'class ValueTests(unittest.TestCase):\n'
        '    def test_value(self) -> None:\n        self.assertEqual(value, 1)\n')
    (root / 'scripts/tests/test_beta.py').write_text(
        'import unittest\nclass OtherTests(unittest.TestCase):\n'
        '    def test_unrelated(self) -> None:\n        self.fail("unrelated module")\n')


def execute(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(root / 'scripts/mutation_test_runner.py'), '--module', 'scripts/alpha.py'],
                          cwd=root, env=os.environ | {'PYTHONDONTWRITEBYTECODE': '1'},
                          capture_output=True, text=True, timeout=5, check=False)


def evidence(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    markers = tuple(line.removeprefix('MUTATION_RESULT ') for line in result.stdout.splitlines()
                    if line.startswith('MUTATION_RESULT '))
    if len(markers) != 1:
        raise ValueError(f'missing runner evidence: {result.stdout} {result.stderr}')
    decoded: object = json.loads(markers[0])
    if not isinstance(decoded, dict):
        raise ValueError('runner evidence is not an object')
    return decoded


class MutationTestRunnerTests(unittest.TestCase):
    def test_module_loading_respects_the_requested_entrypoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_checkout(root)
            program = ('import runpy, sys\n'
                       'sys.path.insert(0, "scripts")\n'
                       'import mutation_test_runner\n'
                       'runpy.run_path("scripts/mutation_test_runner.py")\n'
                       'print("loaded")\n')
            result = subprocess.run([sys.executable, '-c', program], cwd=root, capture_output=True,
                                    text=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'loaded\n')
            program = ('import os, runpy, sys\n'
                       'sys.argv = ["scripts/mutation_test_runner.py", "--module", "scripts/alpha.py"]\n'
                       'runpy.run_path(sys.argv[0], run_name=os.environ["MUTATION_TEST_ENTRYPOINT"])\n')
            result = subprocess.run([sys.executable, '-c', program], cwd=root, capture_output=True,
                                    env=os.environ | {'MUTATION_TEST_ENTRYPOINT': '__main__'},
                                    text=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(evidence(result), dict(kind='tests', run=1, failures=0, errors=0))

    def test_selected_module_runs_its_owned_tests_without_unrelated_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_checkout(root)
            result = execute(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(evidence(result), dict(kind='tests', run=1, failures=0, errors=0))

    def test_every_mapped_suite_contributes_to_failure_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_checkout(root)
            config = root / '.config/mutation.toml'
            original = config.read_text()
            config.write_text(original.replace('["scripts/tests/test_alpha.py"]',
                '["scripts/tests/test_alpha.py", "scripts/tests/test_beta.py"]'))
            result = execute(root)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(evidence(result), dict(kind='tests', run=2, failures=1, errors=0))
            owners = ('scripts/tests/test_alpha.py',) * 300
            config.write_text(original.replace('["scripts/tests/test_alpha.py"]', json.dumps(owners)))
            result = execute(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(evidence(result), dict(kind='tests', run=len(owners), failures=0, errors=0))
            (root / 'scripts/tests/test_alpha.py').write_text(
                'from pathlib import Path\nimport unittest\n'
                'class LaterTests(unittest.TestCase):\n'
                '    def test_later(self) -> None:\n        Path("later-ran").write_text("ran")\n')
            config.write_text(original.replace('["scripts/tests/test_alpha.py"]',
                '["scripts/tests/test_beta.py", "scripts/tests/test_alpha.py"]'))
            result = execute(root)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(evidence(result), dict(kind='tests', run=1, failures=1, errors=0))
            self.assertFalse((root / 'later-ran').exists())

    def test_runtime_test_errors_are_distinct_from_syntax_invalid_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_checkout(root)
            (root / 'scripts/tests/test_alpha.py').write_text('import unittest\nclass Tests(unittest.TestCase):\n'
                '    def test_error(self) -> None:\n        raise RuntimeError("controlled error")\n')
            result = execute(root)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(evidence(result), dict(kind='tests', run=1, failures=0, errors=1))
            (root / 'scripts/alpha.py').write_text('def broken(:\n')
            result = execute(root)
            self.assertEqual(result.returncode, 1)
            diagnostic = evidence(result)
            self.assertEqual(diagnostic['kind'], 'syntax_error')
            self.assertTrue(diagnostic['message'])

    def test_storage_exhaustion_blocks_test_errors_and_subtests(self) -> None:
        codes = tuple((code, name) for code, name in errno.errorcode.items() if name in ('ENOSPC', 'EDQUOT'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_checkout(root)
            path = root / 'scripts/tests/test_alpha.py'
            for code, name in codes:
                failure = f'raise OSError({code}, "controlled storage exhaustion")\n'
                cause = ('try:\n    ' + failure
                         + 'except OSError as error:\n    raise SystemExit("project load failed") from error\n')
                detached_cause = ('error = SystemExit("project load failed")\n'
                                  f'error.__cause__ = OSError({code}, "controlled storage exhaustion")\nraise error\n')
                context = ('try:\n    ' + failure
                           + 'except OSError:\n    raise RuntimeError("project wrapper")\n')
                assertion = ('try:\n    ' + failure
                             + 'except OSError as error:\n    raise AssertionError("project assertion") from error\n')
                assertion_context = ('try:\n    ' + failure
                                     + 'except OSError:\n    raise AssertionError("project assertion")\n')
                prefix = 'import unittest\nclass Tests(unittest.TestCase):\n    def test_value(self) -> None:\n'
                sources = (
                    ('body', prefix + indent(failure, '        ')),
                    ('subtest', prefix + '        with self.subTest(stage="write"):\n' + indent(failure, '            ')),
                    ('setup', 'import unittest\nclass Tests(unittest.TestCase):\n    @classmethod\n'
                     '    def setUpClass(cls) -> None:\n' + indent(failure, '        ')
                     + '    def test_value(self) -> None:\n        self.fail("must not execute")\n'),
                    ('cause', prefix + indent(cause, '        ')),
                    ('detached_cause', prefix + indent(detached_cause, '        ')),
                    ('context', prefix + indent(context, '        ')),
                    ('assertion_cause', prefix + indent(assertion, '        ')),
                    ('subtest_assertion_context', prefix + '        with self.subTest(stage="write"):\n'
                     + indent(assertion_context, '            ')),
                    ('import', 'import unittest\n' + failure),
                    ('import_cause', 'import unittest\n' + cause),
                    ('import_context', 'import unittest\n' + context),
                    ('load_tests', 'import unittest\ndef load_tests(loader: unittest.TestLoader, tests: unittest.TestSuite,\n'
                     '               pattern: str | None) -> unittest.TestSuite:\n' + indent(failure, '    ')),
                )
                for phase, source in sources:
                    path.write_text(source)
                    result = execute(root)
                    with self.subTest(code=name, phase=phase):
                        self.assertEqual(result.returncode, 1)
                        observed = evidence(result)
                        self.assertEqual(observed['kind'], 'resource_error')
                        self.assertEqual(observed['code'], name)
                        self.assertIn('controlled storage exhaustion', str(observed['message']))
            for statement, failures, errors in (
                ('raise AssertionError("Disk quota exceeded")', 1, 0),
                ('with self.subTest(stage="assertion"):\n            self.fail("Disk quota exceeded")', 1, 0),
                ('raise RuntimeError("No space left on device")', 0, 1),
                (f'raise OSError({errno.EACCES}, "controlled refusal")', 0, 1),
                ('print("Disk quota exceeded\\nNo space left on device")\n        raise ValueError("project failure")', 0, 1),
                ('print("Disk quota exceeded\\nNo space left on device")', 0, 0),
                (f'try:\n            raise OSError({errno.EACCES}, "project refusal")\n'
                 '        except OSError as error:\n            raise RuntimeError("project wrapper") from error', 0, 1),
                ('error = RuntimeError("project cycle")\n        error.__cause__ = error\n        raise error', 0, 1),
            ):
                path.write_text('import unittest\nclass Tests(unittest.TestCase):\n'
                                '    def test_value(self) -> None:\n        ' + statement + '\n')
                result = execute(root)
                with self.subTest(statement=statement):
                    self.assertEqual(result.returncode, int(bool(failures or errors)))
                    self.assertEqual(evidence(result), dict(kind='tests', run=1, failures=failures, errors=errors))
            for source in (
                'raise ImportError("project import failed")\n',
                f'try:\n    raise OSError({errno.EACCES}, "project refusal")\n'
                'except OSError as error:\n    raise RuntimeError("project import wrapper") from error\n',
                'import unittest\ndef load_tests(loader: unittest.TestLoader, tests: unittest.TestSuite,\n'
                '               pattern: str | None) -> unittest.TestSuite:\n    raise ValueError("project load failure")\n',
            ):
                path.write_text(source)
                result = execute(root)
                with self.subTest(source=source):
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(evidence(result), dict(kind='tests', run=1, failures=0, errors=1))

    def test_declared_but_unexecuted_suite_is_a_runner_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_checkout(root)
            (root / 'scripts/tests/test_alpha.py').write_text(
                'import unittest\n'
                'class ValueTests(unittest.TestCase):\n'
                '    def test_value(self) -> None:\n        self.fail("declared test unexpectedly ran")\n'
                'class UnexecutedSuite(unittest.TestSuite):\n'
                '    def run(self, result: unittest.TestResult, debug: bool = False) -> unittest.TestResult:\n'
                '        return result\n'
                'def load_tests(loader: unittest.TestLoader, tests: unittest.TestSuite,\n'
                '               pattern: str | None) -> unittest.TestSuite:\n'
                '    return UnexecutedSuite(tests)\n')
            result = execute(root)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(evidence(result)['kind'], 'runner_error')

    def test_missing_invalid_and_empty_suites_are_runner_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_checkout(root)
            config = root / '.config/mutation.toml'
            original = config.read_text()
            for invalid in ('', '[python]\nmodules=[]\n',
                            original.replace('scripts/alpha.py', 'scripts/absent.py'),
                            original.replace('["scripts/tests/test_alpha.py"]', '[]'),
                            original.replace('["scripts/tests/test_alpha.py"]', '[1]'),
                            original.replace('["scripts/tests/test_alpha.py"]',
                                             '{"scripts/tests/test_alpha.py" = true}'),
                            original.replace('["scripts/tests/test_alpha.py"]',
                                             '["scripts/tests/test_alpha.py", 1]'),
                            original.replace('["scripts/tests/test_alpha.py"]',
                                             '["scripts/tests/test_alpha.py", ""]'),
                            original.replace('["scripts/tests/test_alpha.py"]',
                                             '["scripts/tests/test_alpha.py", "  "]'),
                            original.replace('["scripts/tests/test_alpha.py"]',
                                             '["scripts/tests/test_alpha.py", "scripts/tests/test_absent.py"]'),
                            original.replace('["scripts/tests/test_alpha.py"]',
                                             '["scripts/tests/test_alpha.py", "scripts/tests/empty.py"]')):
                config.write_text(invalid)
                result = execute(root)
                with self.subTest(invalid=invalid):
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(evidence(result)['kind'], 'runner_error')
            for owner in ('scripts/tests/../../outside/test_escape.py',
                          'scripts/aaa/test_escape.py', 'scripts/zzz/test_escape.py', 'scripts/tests/helper.py'):
                path = root / owner
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('import unittest\nclass EscapedTests(unittest.TestCase):\n'
                                '    def test_escape(self) -> None:\n        self.fail("unowned suite executed")\n')
                config.write_text(original.replace('["scripts/tests/test_alpha.py"]', json.dumps([owner])))
                result = execute(root)
                with self.subTest(owner=owner):
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(evidence(result)['kind'], 'runner_error')
            (root / 'scripts/tests/test_beta.py').write_text('value = 3\n')
            config.write_text(original.replace('["scripts/tests/test_alpha.py"]',
                '["scripts/tests/test_alpha.py", "scripts/tests/test_beta.py"]'))
            result = execute(root)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(evidence(result)['kind'], 'runner_error')
            config.write_text(original)
            (root / 'scripts/tests/test_alpha.py').write_text('value = 3\n')
            result = execute(root)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(evidence(result)['kind'], 'runner_error')
