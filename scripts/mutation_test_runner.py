from __future__ import annotations

import argparse
import errno
import glob
import json
from pathlib import Path
import sys
import tomllib
from types import ModuleType, TracebackType
from typing import TypeAlias
import unittest


TestError: TypeAlias = tuple[type[BaseException], BaseException, TracebackType] | tuple[None, None, None]


def resource_error(error: BaseException | None) -> tuple[str, str] | None:
    pending: tuple[BaseException, ...] = () if error is None else (error,)
    seen: frozenset[int] = frozenset()
    while pending:
        current, pending = pending[0], pending[1:]
        if id(current) in seen:
            continue
        seen = seen.union((id(current),))
        if isinstance(current, OSError) and current.errno is not None:
            code = errno.errorcode.get(current.errno)
            if code is not None and code in ('ENOSPC', 'EDQUOT'):
                return code, str(current)
        pending = tuple(nested for nested in (current.__cause__, current.__context__)
                        if nested is not None) + pending
    return None


def report_resource_error(failure: tuple[str, str]) -> int:
    code, message = failure
    print('MUTATION_RESULT ' + json.dumps(dict(kind='resource_error', code=code, message=message)))
    return 1


class MutationLoader(unittest.TestLoader):
    resource_failure: tuple[str, str] | None = None

    # CPython formats import exceptions after this hook, losing their native type.
    # https://github.com/python/cpython/blob/v3.13.0/Lib/unittest/loader.py, checked 2026-10-25.
    def _get_module_from_name(self, name: str) -> ModuleType:
        try:
            __import__(name)
            return sys.modules[name]
        except BaseException as error:
            self.resource_failure = self.resource_failure or resource_error(error)
            raise


class MutationResult(unittest.TextTestResult):
    resource_failure: tuple[str, str] | None = None

    def addError(self, test: unittest.TestCase, err: TestError) -> None:
        self.resource_failure = self.resource_failure or resource_error(err[1])
        super().addError(test, err)

    def addFailure(self, test: unittest.TestCase, err: TestError) -> None:
        self.resource_failure = self.resource_failure or resource_error(err[1])
        super().addFailure(test, err)

    def addSubTest(self, test: unittest.TestCase, subtest: unittest.TestCase, err: TestError | None) -> None:
        if err is not None:
            self.resource_failure = self.resource_failure or resource_error(err[1])
        super().addSubTest(test, subtest, err)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--module', required=True, type=Path)
    args = parser.parse_args()
    try:
        compile(args.module.read_bytes(), str(args.module), 'exec')
    except SyntaxError as error:
        print('MUTATION_RESULT ' + json.dumps({'kind': 'syntax_error', 'message': str(error)}))
        return 1
    try:
        with Path('.config/mutation.toml').open('rb') as source:
            configuration = tomllib.load(source)
        python = configuration.get('python')
        if not isinstance(python, dict) or not isinstance(python.get('modules'), dict):
            raise ValueError('missing Python test ownership')
        selected = python['modules'].get(args.module.as_posix())
        if not isinstance(selected, list) or not selected:
            raise ValueError('missing tests for selected production module')
        names = tuple(name for name in selected if isinstance(name, str) and name.strip())
        if len(names) != len(selected):
            raise ValueError('invalid Python test ownership')
        paths = tuple(Path(name) for name in names)
        if any(path.is_absolute() or '..' in path.parts or path.parts[:2] != ('scripts', 'tests')
               or not path.name.startswith('test_') or path.suffix != '.py' or not path.is_file()
               for path in paths):
            raise ValueError('selected Python test owner is not a repository test file')
        loader = MutationLoader()
        suites = tuple(loader.discover(str(path.parent), pattern=glob.escape(path.name))
                       for path in paths)
        if loader.resource_failure is not None:
            return report_resource_error(loader.resource_failure)
        if any(suite.countTestCases() == 0 for suite in suites):
            raise ValueError('selected Python test owner contains no tests')
        suite = unittest.TestSuite(suites)
    except (OSError, ValueError) as error:
        print('MUTATION_RESULT ' + json.dumps({'kind': 'runner_error', 'message': str(error)}))
        return 1
    result = unittest.TextTestRunner(
        stream=sys.stdout, verbosity=1, failfast=True,
        resultclass=MutationResult,  # type: ignore[arg-type]  # unittest passes its wrapped stream to the inherited constructor.
    ).run(suite)
    if isinstance(result, MutationResult) and result.resource_failure is not None:
        return report_resource_error(result.resource_failure)
    if result.testsRun == 0:
        print('MUTATION_RESULT ' + json.dumps({'kind': 'runner_error', 'message': 'selected tests did not execute'}))
        return 1
    print('MUTATION_RESULT ' + json.dumps({
        'kind': 'tests', 'run': result.testsRun,
        'failures': len(result.failures), 'errors': len(result.errors),
    }))
    return 0 if result.wasSuccessful() and result.testsRun else 1


if __name__ == '__main__':
    sys.exit(main())
