from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tomllib
import unittest


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
        suite = unittest.TestSuite(unittest.defaultTestLoader.discover(str(Path(name).parent), pattern=Path(name).name)
                                   for name in names)
    except (OSError, ValueError) as error:
        print('MUTATION_RESULT ' + json.dumps({'kind': 'runner_error', 'message': str(error)}))
        return 1
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=1).run(suite)
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
