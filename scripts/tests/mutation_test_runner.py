from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
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
    suite = unittest.defaultTestLoader.discover('scripts/tests')
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=1).run(suite)
    print('MUTATION_RESULT ' + json.dumps({
        'kind': 'tests', 'run': result.testsRun,
        'failures': len(result.failures), 'errors': len(result.errors),
    }))
    return 0 if result.wasSuccessful() and result.testsRun else 1


if __name__ == '__main__':
    sys.exit(main())
