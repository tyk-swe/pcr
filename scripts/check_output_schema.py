#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Check that the output schema, its runtime identifier, examples, release assets,
and real CLI stdout agree on one current output contract."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable, NamedTuple

from script_support import read_json, strict_json

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = 'crates/packetcraftr-core/src/security.rs'
RELEASE_ASSETS = 'scripts/release-assets.json'
RUNTIME_IDENTIFIER = re.compile(
    r'^pub const OUTPUT_SCHEMA: &str = "(packetcraftr\.output/v([1-9][0-9]*))";$', re.MULTILINE)
OUTPUT_SCHEMA_ASSET = re.compile(r'^schemas/(?:historical/)?packetcraftr\.output\.')
RUNTIME_TIMEOUT_SECONDS = 60
MAX_PROBLEMS_PER_DOCUMENT = 5


class CheckError(Exception):
    """The check could not run, as opposed to finding contract problems."""


class Identity(NamedTuple):
    identifier: str
    version: int

    @property
    def schema_path(self) -> str:
        return f'schemas/packetcraftr.output.v{self.version}.schema.json'

    @property
    def urn(self) -> str:
        return f'urn:packetcraftr:output:v{self.version}'


class RuntimeCommand(NamedTuple):
    args: tuple[str, ...]
    succeeds: bool


RUNTIME_COMMANDS = (
    RuntimeCommand(('--output', 'json', 'files', 'read', 'examples/captures/protocol-mqtt.pcap',
                    '--field', 'frame.number'), True),
    RuntimeCommand(('--output', 'ndjson', 'files', 'read', '--dissect',
                    'examples/captures/dns-response.pcap'), True),
    RuntimeCommand(('--output', 'json', 'packet', 'build', '--packet-file',
                    'examples/documents/packet-dns-response.json'), True),
    RuntimeCommand(('--output', 'json', 'packet', 'dissect',
                    '--hex', '4500001e0000000040118e98c0000201c63364029c409c41000a72b76869'), True),
    RuntimeCommand(('--output', 'json', 'analyze', 'dns', 'examples/captures/dns-response.pcap'), True),
    RuntimeCommand(('--output', 'ndjson', 'analyze', 'http', 'examples/captures/http-stream.pcap'), True),
    RuntimeCommand(('--output', 'json', 'analyze', 'stats', 'examples/captures/dns-response.pcap'), True),
    RuntimeCommand(('--output', 'json', 'analyze', 'scan-diff',
                    'examples/documents/output-scan-success.json',
                    'examples/documents/output-scan-qualified.json'), True),
    RuntimeCommand(('--output', 'json', 'reference', 'protocols'), True),
    RuntimeCommand(('--output', 'json', 'files', 'read', 'examples/captures/missing.pcap',
                    '--field', 'frame.number'), False),
)


def read_identity(contract_source: str) -> Identity:
    matches = RUNTIME_IDENTIFIER.findall(contract_source)
    if len(matches) != 1:
        raise CheckError(f'expected exactly one `pub const OUTPUT_SCHEMA` output identifier in {CONTRACT}')
    identifier, version = matches[0]
    return Identity(identifier, int(version))


def check_identity(schema: Any, identity: Identity) -> list[str]:
    problems = []
    if schema.get('$id') != identity.urn:
        problems.append(f'{identity.schema_path}: $id is {schema.get("$id")!r}, expected {identity.urn!r}')
    try:
        declared = schema['$defs']['baseEnvelope']['properties']['schema']['const']
    except (KeyError, TypeError):
        declared = None
    if declared != identity.identifier:
        problems.append(f'{identity.schema_path}: envelope schema const is {declared!r}, '
                        f'expected the runtime identifier {identity.identifier!r}')
    return problems


def check_release_assets(assets: Iterable[str], identity: Identity) -> list[str]:
    assets = list(assets)
    problems = [] if identity.schema_path in assets else [
        f'{RELEASE_ASSETS}: the current output schema {identity.schema_path} is not shipped']
    problems.extend(f'{RELEASE_ASSETS}: ships {asset}, which is not the current output schema'
                    for asset in assets
                    if OUTPUT_SCHEMA_ASSET.match(asset) and asset != identity.schema_path)
    return problems


def load_validator(schema: Any) -> Any:
    try:
        import jsonschema
    except ImportError as error:
        raise CheckError('full Draft 2020-12 validation requires the jsonschema package; '
                         'install python3-jsonschema or `pip install jsonschema`') from error
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except jsonschema.SchemaError as error:
        raise CheckError(f'the output schema is not a valid Draft 2020-12 schema: {error.message}') from error
    return jsonschema.Draft202012Validator(schema)


def document_problems(validator: Any, label: str, document: Any) -> list[str]:
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    return [f'{label}: /{"/".join(map(str, error.absolute_path))}: {error.message[:300]}'
            for error in errors[:MAX_PROBLEMS_PER_DOCUMENT]]


def parsed_records(label: str, text: str, ndjson: bool) -> tuple[list[tuple[str, Any]], list[str]]:
    chunks = ([(f'{label}:{number}', line) for number, line in enumerate(text.splitlines(), 1)]
              if ndjson else [(label, text)])
    records, problems = [], []
    for record_label, chunk in chunks:
        try:
            records.append((record_label, strict_json(chunk)))
        except ValueError as error:
            problems.append(f'{record_label}: not a JSON document: {error}')
    if not chunks:
        problems.append(f'{label}: no JSON document')
    return records, problems


def validated(validator: Any, label: str, text: str, ndjson: bool) -> list[str]:
    records, problems = parsed_records(label, text, ndjson)
    for record_label, record in records:
        problems.extend(document_problems(validator, record_label, record))
    return problems


def example_problems(root: Path, validator: Any) -> list[str]:
    documents = root / 'examples' / 'documents'
    paths = sorted([*documents.glob('output-*.json'), *documents.glob('output-*.ndjson')])
    problems = [] if paths else [f'{documents}: no output examples found']
    for path in paths:
        text = path.read_bytes().decode('utf-8')
        problems.extend(validated(validator, str(path.relative_to(root)), text,
                                  path.suffix == '.ndjson'))
    return problems


def runtime_problems(binary: Path, root: Path, validator: Any,
                     commands: Iterable[RuntimeCommand] = RUNTIME_COMMANDS) -> list[str]:
    problems = []
    for command in commands:
        label = f'packetcraftr {" ".join(command.args)}'
        try:
            completed = subprocess.run([str(binary), *command.args], cwd=root, capture_output=True,
                                       timeout=RUNTIME_TIMEOUT_SECONDS, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            problems.append(f'{label}: could not run: {error}')
            continue
        if (completed.returncode == 0) != command.succeeds:
            problems.append(f'{label}: unexpected exit status {completed.returncode}: '
                            f'{completed.stderr.decode("utf-8", "replace")[:300]}')
            continue
        try:
            stdout = completed.stdout.decode('utf-8')
        except UnicodeDecodeError as error:
            problems.append(f'{label}: stdout is not UTF-8: {error}')
            continue
        problems.extend(validated(validator, label, stdout, 'ndjson' in command.args))
    return problems


def check(root: Path, binary: Path | None = None) -> list[str]:
    identity = read_identity((root / CONTRACT).read_text(encoding='utf-8'))
    schema = read_json(root / identity.schema_path)
    problems = check_identity(schema, identity)
    problems.extend(check_release_assets(read_json(root / RELEASE_ASSETS)['source_assets'], identity))
    validator = load_validator(schema)
    problems.extend(example_problems(root, validator))
    if binary is not None:
        problems.extend(runtime_problems(binary, root, validator))
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--binary', type=Path,
                        help='also validate stdout of offline commands run with this CLI binary')
    args = parser.parse_args(argv)
    try:
        problems = check(args.root.resolve(), args.binary.resolve() if args.binary else None)
    except (CheckError, OSError, ValueError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 2
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print(f'{len(problems)} output contract problem(s)', file=sys.stderr)
        return 1
    print('output schema, runtime identifier, examples, release assets'
          + (', and runtime stdout' if args.binary else '') + ' agree')
    return 0


if __name__ == '__main__':
    sys.exit(main())
