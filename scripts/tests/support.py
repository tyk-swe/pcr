# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Load standalone tool scripts without executing their command-line entrypoints."""
import importlib.util
from pathlib import Path
import sys
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))


def load_script(name: str, relative: str | None = None) -> ModuleType:
    path = ROOT / (relative or f'scripts/{name}.py')
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path)
    if spec is None or spec.loader is None:
        raise ImportError(f'cannot load script {path}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
