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
REGISTRY = 'crates/packetcraftr-cli/src/output/contract.rs'
CLI_SRC = 'crates/packetcraftr-cli/src'
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


CODE_PATTERN = re.compile(r'^[a-z]+\.[a-z0-9_.]+$')
CODE_LITERAL = re.compile(r'"((?:[a-z][a-z0-9]*)\.[a-z0-9_.]+)"')


def published_codes(root: Path) -> set[str]:
    """Every machine-readable code the Rust sources can publish.

    Classification codes come from the typed `Code` enum; diagnostic and
    expert-finding codes are string literals at their construction sites.
    Output carrying a code outside this closed set is unpublished surface.
    """
    codes: set[str] = set()
    for path in (root / 'crates').rglob('*.rs'):
        codes.update(CODE_LITERAL.findall(path.read_text(encoding='utf-8', errors='replace')))
    return codes


def code_problems(label: str, record: Any, published: set[str]) -> list[str]:
    problems: list[str] = []

    def walk(node: Any, trail: str) -> None:
        if isinstance(node, dict):
            code = node.get('code')
            if isinstance(code, str) and CODE_PATTERN.match(code) and code not in published:
                problems.append(f'{label}: {trail}/code: unpublished code {code!r}')
            for key, value in node.items():
                walk(value, f'{trail}/{key}')
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f'{trail}/{index}')

    walk(record, '')
    return problems[:MAX_PROBLEMS_PER_DOCUMENT]


def validated(validator: Any, label: str, text: str, ndjson: bool,
              published: set[str] | None = None) -> list[str]:
    records, problems = parsed_records(label, text, ndjson)
    for record_label, record in records:
        problems.extend(document_problems(validator, record_label, record))
        if published is not None:
            problems.extend(code_problems(record_label, record, published))
    return problems


def example_problems(root: Path, validator: Any, published: set[str]) -> list[str]:
    documents = root / 'examples' / 'documents'
    paths = sorted([*documents.glob('output-*.json'), *documents.glob('output-*.ndjson')])
    problems = [] if paths else [f'{documents}: no output examples found']
    for path in paths:
        text = path.read_bytes().decode('utf-8')
        problems.extend(validated(validator, str(path.relative_to(root)), text,
                                  path.suffix == '.ndjson', published))
    return problems


def runtime_problems(binary: Path, root: Path, validator: Any, published: set[str],
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
        problems.extend(validated(validator, label, stdout, 'ndjson' in command.args, published))
    return problems




class PublishedRow(NamedTuple):
    definition: str
    command: str
    rust_types: tuple[str, ...]
    events: tuple[str, ...]
    example: str


ROW_PATTERN = re.compile(
    r'PublishedType \{\s*definition: "([^"]+)",\s*command: "([^"]+)",\s*'
    r'rust_types: &\[([^\]]*)\],\s*events: &\[([^\]]*)\],\s*example: "([^"]+)",\s*\}')


def read_registry(source: str) -> list[PublishedRow]:
    rows = []
    for definition, command, rust_types, events, example in ROW_PATTERN.findall(source):
        rows.append(PublishedRow(
            definition, command,
            tuple(re.findall(r'"([^"]+)"', rust_types)),
            tuple(re.findall(r'"([^"]+)"', events)),
            example))
    return rows


def _refs(node: Any) -> list[str]:
    if isinstance(node, dict):
        found = []
        for key, value in node.items():
            if key == '$ref':
                found.append(value.split('/')[-1])
            else:
                found += _refs(value)
        return found
    if isinstance(node, list):
        found = []
        for value in node:
            found += _refs(value)
        return found
    return []


def _consts(node: Any, key: str) -> list[str]:
    if isinstance(node, dict):
        found = []
        for name, value in node.items():
            if name == 'properties' and isinstance(value, dict):
                target = value.get(key)
                if isinstance(target, dict):
                    if 'const' in target:
                        found.append(target['const'])
                    found += target.get('enum', [])
            found += _consts(value, key)
        return sorted(set(found))
    if isinstance(node, list):
        found = []
        for value in node:
            found += _consts(value, key)
        return sorted(set(found))
    return []


def _production_sources(root: Path) -> list[Path]:
    base = root / CLI_SRC
    return [path for path in sorted(base.rglob('*.rs'))
            if 'tests' not in path.parts and path.name != 'tests.rs']


def _stream_record_types(root: Path) -> set[str]:
    types = set()
    for path in _production_sources(root):
        lines = path.read_text(encoding='utf-8').splitlines()
        for index, line in enumerate(lines):
            if 'fn event_name' not in line:
                continue
            for back in range(index - 1, max(-1, index - 8), -1):
                match = re.search(r'StreamRecord for\s+(&?\w+(?:::\w+)*(?:<[^>]*>)?)', lines[back])
                if match:
                    name = match.group(1).lstrip('&').split('<')[0]
                    relative = str(path.relative_to(root / CLI_SRC)).removesuffix('.rs')
                    types.add(f'crate::{relative.replace("/", "::")}::{name}'
                              if '::' not in name else f'crate::{name}')
                    break
    return types


def _type_defined(root: Path, rust_type: str, sources: dict[Path, str]) -> bool:
    parts = rust_type.split('::')
    if len(parts) < 3 or parts[0] != 'crate':
        return False
    name, module = parts[-1], parts[1:-1]
    base = root / CLI_SRC
    candidates = [base / ('/'.join(module) + '.rs')]
    candidates += sorted((base / '/'.join(module)).rglob('*.rs')) if (base / '/'.join(module)).is_dir() else []
    pattern = re.compile(rf'(?:struct|enum|type)\s+{re.escape(name)}\b')
    return any(pattern.search(sources.get(path, '')) for path in candidates)


def registry_problems(root: Path, schema: Any) -> list[str]:
    """The contract registry must agree with the schema, sources, and examples."""
    import jsonschema

    problems: list[str] = []
    rows = read_registry((root / REGISTRY).read_text(encoding='utf-8'))
    if not rows:
        return [f'{REGISTRY}: no PublishedType rows found']
    definitions = schema.get('$defs', {})
    sources = {path: path.read_text(encoding='utf-8') for path in _production_sources(root)}
    examples: dict[str, list[Any]] = {}

    def example_records(relative: str) -> list[Any]:
        if relative not in examples:
            path = root / relative
            if not path.is_file():
                examples[relative] = []
            else:
                text = path.read_text(encoding='utf-8')
                examples[relative] = [strict_json(line) for line in text.splitlines()
                                       if line.strip()] if relative.endswith('.ndjson') \
                    else [strict_json(text)]
        return examples[relative]

    claimed: dict[str, set[str]] = {}
    seen: set[tuple[str, str]] = set()
    registered_types: set[str] = set()
    for row in rows:
        label = f'{REGISTRY}: {row.definition}/{row.command}'
        if (row.definition, row.command) in seen:
            problems.append(f'{label}: duplicate registry row')
        seen.add((row.definition, row.command))
        registered_types.update(row.rust_types)
        definition = definitions.get(row.definition)
        if definition is None:
            problems.append(f'{label}: no such schema definition')
            continue
        claimed.setdefault(row.definition, set()).add(row.command)
        if row.command not in _consts(definition, 'command'):
            problems.append(f'{label}: command is not pinned by the definition')
        if list(row.events) != _consts(definition, 'event'):
            problems.append(f'{label}: events disagree with the definition')
        for rust_type in row.rust_types:
            if not _type_defined(root, rust_type, sources):
                problems.append(f'{label}: rust type {rust_type} is not defined')
        if not (root / row.example).is_file():
            problems.append(f'{label}: example {row.example} does not exist')
            continue
        validator = jsonschema.Draft202012Validator(
            {'$ref': f'#/$defs/{row.definition}', '$defs': definitions})
        if not any(validator.is_valid(record) for record in example_records(row.example)
                   if isinstance(record, dict) and record.get('status') == 'success'):
            problems.append(f'{label}: no record in {row.example} validates '
                            f'against {row.definition}')

    for root_name in ('aggregateSuccess', 'streamSuccess'):
        for name in _refs(definitions.get(root_name, {})):
            if name == 'baseEnvelope':
                continue
            expected = set(_consts(definitions.get(name, {}), 'command'))
            if claimed.get(name, set()) != expected:
                problems.append(f'{REGISTRY}: {name} claims '
                                f'{sorted(claimed.get(name, set()))}, schema pins {sorted(expected)}')
    for stream_type in sorted(_stream_record_types(root) - registered_types):
        problems.append(f'{REGISTRY}: stream record type {stream_type} is not registered')
    return problems


def check(root: Path, binary: Path | None = None) -> list[str]:
    identity = read_identity((root / CONTRACT).read_text(encoding='utf-8'))
    schema = read_json(root / identity.schema_path)
    problems = check_identity(schema, identity)
    problems.extend(check_release_assets(read_json(root / RELEASE_ASSETS)['source_assets'], identity))
    problems.extend(registry_problems(root, schema))
    validator = load_validator(schema)
    published = published_codes(root)
    problems.extend(example_problems(root, validator, published))
    if binary is not None:
        problems.extend(runtime_problems(binary, root, validator, published))
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
