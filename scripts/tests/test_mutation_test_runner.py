# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
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
                          cwd=root, capture_output=True, text=True, timeout=5, check=False)


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
            config.write_text(config.read_text().replace('["scripts/tests/test_alpha.py"]',
                '["scripts/tests/test_alpha.py", "scripts/tests/test_beta.py"]'))
            result = execute(root)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(evidence(result), dict(kind='tests', run=2, failures=1, errors=0))

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

    def test_missing_invalid_and_empty_suites_are_runner_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_checkout(root)
            config = root / '.config/mutation.toml'
            original = config.read_text()
            for invalid in ('', '[python]\nmodules=[]\n',
                            original.replace('scripts/alpha.py', 'scripts/absent.py'),
                            original.replace('["scripts/tests/test_alpha.py"]', '[]'),
                            original.replace('["scripts/tests/test_alpha.py"]', '[1]')):
                config.write_text(invalid)
                result = execute(root)
                with self.subTest(invalid=invalid):
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(evidence(result)['kind'], 'runner_error')
            config.write_text(original)
            (root / 'scripts/tests/test_alpha.py').write_text('value = 3\n')
            result = execute(root)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(evidence(result)['kind'], 'runner_error')
