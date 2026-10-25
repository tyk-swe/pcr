# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded JSON and atomic report publication for repository tools.

This module uses only the standard library so repository tools remain standalone.
It is not a decoder for the product's public output contracts.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any

MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_JSON_DEPTH = 64


def portable_basename(value: str) -> bool:
    """Whether a component is safe on Unix and Windows release filesystems."""
    devices = {'con', 'prn', 'aux', 'nul', 'conin$', 'conout$'}
    devices.update(f'{prefix}{digit}' for prefix in ('com', 'lpt')
                   for digit in '123456789¹²³')
    return (isinstance(value, str) and bool(value)
            and value not in ('.', '..')
            and not value.endswith((' ', '.'))
            and not any(character in value for character in '/\\:*?"<>|')
            and not any(ord(character) < 32 or ord(character) == 127 for character in value)
            and value.split('.')[0].rstrip(' ').casefold() not in devices)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key!r}')
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f'non-finite JSON constant: {value}')


def _validate_tree(value: Any) -> None:
    # Iterative traversal also covers additive fields instead of checking only
    # the handful of strings that a particular validator happens to consume.
    stack = [(iter((value,)), 0)]
    while stack:
        items, depth = stack[-1]
        try:
            item = next(items)
        except StopIteration:
            stack.pop()
            continue
        if depth > MAX_JSON_DEPTH:
            raise ValueError(f'JSON nesting exceeds {MAX_JSON_DEPTH}')
        if isinstance(item, str):
            item.encode('utf-8', errors='strict')
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError('non-finite JSON number')
        elif isinstance(item, dict):
            for key in item:
                if not isinstance(key, str):
                    raise ValueError('JSON object keys must be strings')
                key.encode('utf-8', errors='strict')
            stack.append((iter(item.values()), depth + 1))
        elif isinstance(item, list):
            stack.append((iter(item), depth + 1))


def strict_json(data: str | bytes, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    """Read one UTF-8 JSON value, rejecting ambiguity and non-JSON numbers."""
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError('JSON byte limit must be a positive integer')
    try:
        if isinstance(data, bytes):
            if len(data) > max_bytes:
                raise ValueError(f'JSON exceeds {max_bytes} bytes')
            # json.loads(bytes) also accepts UTF-16/32, unlike these contracts.
            data = data.decode('utf-8', errors='strict')
        elif isinstance(data, str):
            if len(data.encode('utf-8', errors='strict')) > max_bytes:
                raise ValueError(f'JSON exceeds {max_bytes} bytes')
        else:
            raise ValueError('JSON input must be text or bytes')
        value = json.loads(data, object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant)
        _validate_tree(value)
        return value
    except (UnicodeError, RecursionError) as error:
        raise ValueError(f'invalid UTF-8 JSON or excessive nesting: {error}') from error


def read_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    """Read at most the limit plus one byte; do not trust a prior file stat."""
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError('JSON byte limit must be a positive integer')
    path = Path(path)
    if not path.is_file():
        raise ValueError(f'JSON input is not a regular file: {path}')
    with path.open('rb') as source:
        data = source.read(max_bytes + 1)
    try:
        return strict_json(data, max_bytes=max_bytes)
    except ValueError as error:
        raise ValueError(f'{path}: {error}') from error


def write_json_atomic(path: Path, document: Any) -> None:
    """Replace a report only after a complete, flushed UTF-8 encoding exists.

    A failed serialization/write leaves the previous file intact. Callers that
    use success markers must remove a stale marker before starting a new run.
    """
    path = Path(path)
    _validate_tree(document)
    encoded = json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + '\n'
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = None
    try:
        existing = path.lstat()
        if stat.S_ISREG(existing.st_mode):
            mode = stat.S_IMODE(existing.st_mode)
    except FileNotFoundError:
        pass
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n',
                                         prefix=f'.{path.name}.', suffix='.tmp',
                                         dir=path.parent, delete=False) as output:
            temporary = Path(output.name)
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        if mode is not None:
            temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def distinct_paths(output: Path, *inputs: Path) -> None:
    """Prevent reports from overwriting their binary, inputs, or hard links."""
    output = Path(output)
    for source in inputs:
        source = Path(source)
        if output.resolve() == source.resolve():
            raise ValueError(f'output must differ from input: {source}')
        try:
            same = output.samefile(source)
        except FileNotFoundError:
            same = False
        if same:
            raise ValueError(f'output aliases input: {source}')


def prepare_report(output: Path, *inputs: Path) -> None:
    """Check aliases before removing a stale success report for a new attempt."""
    distinct_paths(output, *inputs)
    Path(output).unlink(missing_ok=True)


def valid_digest(value: object, width: int = 64) -> bool:
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{' + str(width) + r'}', value) is not None


def digest(path: Path | str) -> str:
    path = Path(path)
    if not path.is_file():
        raise ValueError(f'digest input is not a regular file: {path}')
    hasher = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(65536), b''):
            hasher.update(block)
    return hasher.hexdigest()
