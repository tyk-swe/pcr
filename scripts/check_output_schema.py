#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Check that the output schema, its runtime identifier, examples, release assets,
and real CLI stdout agree on one current output contract."""
from __future__ import annotations

import argparse
from io import StringIO
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable, Literal, NamedTuple

from release_assets import validate_manifest
from rust_source import blank_comments, blank_comments_and_strings, production_sources
from script_support import read_json, strict_json

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = 'crates/packetcraftr-cli/src/output/contract.rs'
RELEASE_ASSETS = 'scripts/release-assets.json'
REGISTRY = 'published registry (Spec::PUBLISHED rows under crates/packetcraftr-cli/src)'
CLI_SRC = 'crates/packetcraftr-cli/src'
RUNTIME_IDENTIFIER = re.compile(
    r'^pub const OUTPUT_SCHEMA: &str = "(packetcraftr\.output/v([1-9][0-9]*))";[ \t]*$', re.MULTILINE)
OUTPUT_SCHEMA_ASSET = re.compile(r'^schemas/(?:(?:historical/)?packetcraftr\.output\.|output/.+\.schema\.json$)')
COMMON_SCHEMA = 'schemas/output/common.v1.schema.json'
COMMON_URN = 'urn:packetcraftr:output:common:v1'
OUTPUT_SCHEMA_DIR = 'schemas/output'
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
    RuntimeCommand(('--output', 'json', 'analyze', 'http3', 'examples/captures/http3-demo.pcapng',
                    '--keylog', 'examples/captures/http3-demo.keys',
                    '--max-quic-stream-bytes', '32'), True),
    RuntimeCommand(('--output', 'ndjson', 'analyze', 'http3', 'examples/captures/http3-demo.pcapng',
                    '--keylog', 'examples/captures/http3-demo.keys', '--include-header-values'), True),
    RuntimeCommand(('--output', 'json', 'analyze', 'stats', 'examples/captures/dns-response.pcap'), True),
    RuntimeCommand(('--output', 'json', 'analyze', 'scan-diff',
                    'examples/documents/output-scan-success.json',
                    'examples/documents/output-scan-qualified.json'), True),
    RuntimeCommand(('--output', 'json', 'reference', 'protocols'), True),
    RuntimeCommand(('--output', 'json', 'files', 'read', 'examples/captures/missing.pcap',
                    '--field', 'frame.number'), False),
)


def read_identity(contract_source: str) -> Identity:
    matches = RUNTIME_IDENTIFIER.findall(blank_comments(contract_source))
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


def check_release_assets(assets: Iterable[str], identity: Identity,
                         required: Iterable[str] = ()) -> list[str]:
    assets = list(assets)
    required = [identity.schema_path, *required]
    problems = [f'{RELEASE_ASSETS}: the current output schema {asset} is not shipped'
                for asset in required if asset not in assets]
    problems.extend(f'{RELEASE_ASSETS}: ships {asset}, which is not part of the current output schema set'
                    for asset in assets
                    if OUTPUT_SCHEMA_ASSET.match(asset) and asset not in required)
    return problems


def load_jsonschema() -> Any:
    try:
        import jsonschema
    except ImportError as error:
        raise CheckError('full Draft 2020-12 validation requires the jsonschema package; '
                         'install python3-jsonschema or `pip install jsonschema`') from error
    return jsonschema


def load_validator(schema: Any) -> Any:
    jsonschema = load_jsonschema()
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except jsonschema.SchemaError as error:
        raise CheckError(f'the output schema is not a valid Draft 2020-12 schema: {error.message}') from error
    return jsonschema.Draft202012Validator(schema)


class RegistrySchema(NamedTuple):
    definitions: dict[str, Any]
    modes: dict[str, dict[str, set[str]]]


class SchemaSet(NamedTuple):
    envelope_schema: Any
    validator: Any
    registry: RegistrySchema
    required_assets: tuple[str, ...]


def _localize_common_refs(node: Any) -> Any:
    prefix = f'{COMMON_URN}#/$defs/'
    if isinstance(node, dict):
        return {
            key: (f'#/$defs/{value[len(prefix):]}'
                  if key == '$ref' and isinstance(value, str) and value.startswith(prefix)
                  else _localize_common_refs(value))
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [_localize_common_refs(value) for value in node]
    return node


def load_schema_set(root: Path, identity: Identity) -> SchemaSet:
    jsonschema = load_jsonschema()
    envelope_path = root / identity.schema_path
    common_path = root / COMMON_SCHEMA
    command_paths = sorted((root / OUTPUT_SCHEMA_DIR).glob('*.v1.schema.json'))
    command_paths = [path for path in command_paths if path.name != 'common.v1.schema.json']
    if not envelope_path.is_file():
        raise CheckError(f'{identity.schema_path}: schema file does not exist')
    if not common_path.is_file():
        raise CheckError(f'{COMMON_SCHEMA}: schema file does not exist')
    if not command_paths:
        raise CheckError(f'{OUTPUT_SCHEMA_DIR}: no command payload schemas found')

    envelope = read_json(envelope_path)
    common = read_json(common_path)
    commands: dict[str, Any] = {}
    documents: dict[str, Any] = {}
    for uri, schema, path in [(identity.urn, envelope, envelope_path),
                              (COMMON_URN, common, common_path)]:
        if not isinstance(schema, dict):
            raise CheckError(f'{path.relative_to(root)}: expected a JSON object')
        if schema.get('$id') != uri:
            raise CheckError(f'{path.relative_to(root)}: $id is {schema.get("$id")!r}, expected {uri!r}')
        documents[uri] = schema
    for path in command_paths:
        command = path.name.removesuffix('.v1.schema.json')
        schema = read_json(path)
        uri = f'urn:packetcraftr:output:{command}:v1'
        if not isinstance(schema, dict):
            raise CheckError(f'{path.relative_to(root)}: expected a JSON object')
        if schema.get('$id') != uri:
            raise CheckError(f'{path.relative_to(root)}: $id is {schema.get("$id")!r}, expected {uri!r}')
        commands[command] = schema
        documents[uri] = schema

    for uri, schema in documents.items():
        try:
            jsonschema.Draft202012Validator.check_schema(schema)
        except jsonschema.SchemaError as error:
            raise CheckError(f'{uri}: invalid Draft 2020-12 schema: {error.message}') from error
    merged_definitions = dict(_localize_common_refs(common.get('$defs', {})))
    for schema in commands.values():
        for name, definition in schema.get('$defs', {}).items():
            if name in merged_definitions:
                raise CheckError(f'schemas/output: duplicate definition {name!r}')
            merged_definitions[name] = _localize_common_refs(definition)
    modes: dict[str, dict[str, set[str]]] = {}
    shells = {f'{COMMON_URN}#/$defs/{mode}SuccessEnvelope': mode for mode in ('aggregate', 'stream')}
    for command, schema in commands.items():
        path = f'{OUTPUT_SCHEMA_DIR}/{command}.v1.schema.json'
        try:
            for variant in schema.get('allOf', [{}])[-1].get('oneOf', []):
                envelope_ref, payloads = variant['allOf']
                mode = shells[envelope_ref['$ref']]
                for payload in payloads['oneOf']:
                    ref = payload['$ref']
                    uri, separator, name = ref.partition('#/$defs/')
                    owner = common if uri == COMMON_URN else schema
                    if not separator or uri not in ('', COMMON_URN) or name not in owner.get('$defs', {}):
                        raise CheckError(f'{path}: unknown payload definition {ref!r}')
                    modes.setdefault(name, {}).setdefault(command, set()).add(mode)
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as error:
            raise CheckError(f'{path}: invalid success branch: {error}') from error

    def standalone(schema):
        localized = _localize_common_refs(schema)
        localized['$defs'] = merged_definitions
        return localized

    envelope_validator = jsonschema.Draft202012Validator(standalone(envelope))
    command_validators = {
        command: jsonschema.Draft202012Validator(standalone(schema))
        for command, schema in commands.items()
    }

    class Validator:
        def iter_errors(self, document: Any):
            errors = sorted(envelope_validator.iter_errors(document),
                            key=lambda error: list(error.absolute_path))
            if errors:
                return iter(errors)
            if not isinstance(document, dict) or document.get('status') != 'success':
                return iter(())
            command = document.get('command')
            expected = f'packetcraftr.output.{command}/v1' if isinstance(command, str) else None
            if document.get('payload_schema') != expected:
                return iter([jsonschema.ValidationError(
                    f'payload_schema {document.get("payload_schema")!r} does not match command {command!r}')])
            validator = command_validators.get(command)
            if validator is None:
                return iter([jsonschema.ValidationError(f'no command payload schema for {command!r}')])
            return iter(sorted(validator.iter_errors(document),
                               key=lambda error: list(error.absolute_path)))

    required = (COMMON_SCHEMA,
                *(f'{OUTPUT_SCHEMA_DIR}/{path.name}' for path in command_paths))
    return SchemaSet(envelope, Validator(), RegistrySchema(merged_definitions, modes), required)


def document_problems(validator: Any, label: str, document: Any) -> list[str]:
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    return [f'{label}: /{"/".join(map(str, error.absolute_path))}: {error.message[:300]}'
            for error in errors[:MAX_PROBLEMS_PER_DOCUMENT]]


def parsed_records(label: str, text: str, ndjson: bool) -> tuple[list[tuple[str, Any]], list[str]]:
    chunks = ([(f'{label}:{number}', line)
               for number, line in enumerate(StringIO(text, newline='\n'), 1)]
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
HTTP3_CODE_ENUM = re.compile(r'published_enum!\s*\{[^{}]*\benum Code from http3::Code\s*\{([^{}]*)\}')
ENUM_VALUE = re.compile(r'=>\s*"([a-z][a-z0-9_]*)"')


def published_codes(sources: Iterable[str]) -> set[str]:
    """Every machine-readable code the Rust sources can publish.

    Classification codes come from the typed `Code` enum; diagnostic and
    expert-finding codes are string literals at their construction sites.
    Output carrying a code outside this closed set is unpublished surface.
    """
    codes: set[str] = set()
    for text in sources:
        codes.update(CODE_LITERAL.findall(text))
        if declaration := HTTP3_CODE_ENUM.search(text):
            codes.update(ENUM_VALUE.findall(declaration[1]))
    return codes


def code_problems(label: str, record: Any, published: set[str]) -> list[str]:
    problems: list[str] = []
    http3 = isinstance(record, dict) and record.get('command') == 'http3'

    def walk(node: Any, trail: str, issue: bool = False) -> None:
        if isinstance(node, dict):
            code = node.get('code')
            if isinstance(code, str) and (issue or CODE_PATTERN.match(code)) and code not in published:
                problems.append(f'{label}: {trail}/code: unpublished code {code!r}')
            for key, value in node.items():
                walk(value, f'{trail}/{key}')
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f'{trail}/{index}', http3 and trail.endswith('/issues'))

    walk(record, '')
    return problems[:MAX_PROBLEMS_PER_DOCUMENT]


def validated(validator: Any, label: str, text: str, ndjson: bool,
              published: set[str] | None = None, *,
              expected_status: Literal['success', 'error'] | None = None) -> list[str]:
    records, problems = parsed_records(label, text, ndjson)
    for record_label, record in records:
        problems.extend(document_problems(validator, record_label, record))
        if published is not None:
            problems.extend(code_problems(record_label, record, published))
    if expected_status is not None and not problems and records:
        record_label, record = records[-1]
        if ndjson:
            for earlier_label, earlier in records[:-1]:
                if isinstance(earlier, dict) and earlier.get('event') in ('complete', 'error'):
                    return [f'{earlier_label}: terminal event before end of stream']
            if not isinstance(record, dict) or record.get('event') not in ('complete', 'error'):
                return [f'{record_label}: missing terminal event']
            command = record.get('command')
            for expected, (line_label, item) in enumerate(records):
                if (not isinstance(item, dict) or type(item.get('seq')) is not int
                        or item['seq'] != expected):
                    return [f'{line_label}: non-contiguous stream sequence, expected {expected}']
                if item.get('command') != command:
                    return [f'{line_label}: command changed within stream']
        status = record.get('status') if isinstance(record, dict) else None
        if status != expected_status:
            problems.append(f'{record_label}: expected {expected_status!r} envelope status, got {status!r}')
    return problems


def output_example_paths(root: Path) -> list[Path]:
    documents = root / 'examples' / 'documents'
    return sorted([*documents.glob('output-*.json'), *documents.glob('output-*.ndjson')])


def example_problems(root: Path, validator: Any, published: set[str]) -> list[str]:
    paths = output_example_paths(root)
    problems = [] if paths else [f'{root / "examples/documents"}: no output examples found']
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
        problems.extend(validated(validator, label, stdout, 'ndjson' in command.args, published,
                                  expected_status='success' if command.succeeds else 'error'))
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


def _consts(node: Any, key: str) -> list[str]:
    if isinstance(node, dict):
        found = []
        for name, value in node.items():
            if name == 'properties' and isinstance(value, dict):
                target = value.get(key)
                if isinstance(target, dict):
                    constants = [target['const']] if 'const' in target else []
                    for constant in (*constants, *target.get('enum', [])):
                        if not isinstance(constant, str):
                            raise CheckError(f'{key!r} values must be strings')
                        found.append(constant)
            found += _consts(value, key)
        return sorted(set(found))
    if isinstance(node, list):
        found = []
        for value in node:
            found += _consts(value, key)
        return sorted(set(found))
    return []


RUST_PATH = r'[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*'
TYPE_OR_SCOPE = re.compile(
    r'\bmod\s+([A-Za-z_]\w*)\s*\{|\b(?:struct|enum|type)\s+([A-Za-z_]\w*)'
    rf"|\bStreamRecord\s+for\s+(?:&\s*(?:'\w+\s+)?(?:mut\s+)?)?({RUST_PATH})|[{{}}]")


def _source_module(path: Path) -> str:
    parts = path.relative_to(CLI_SRC).with_suffix('').parts
    if parts == ('lib',) or parts[-1] == 'mod':
        parts = parts[:-1]
    return '::'.join(('crate', *parts))


def _record_path(owner: str, record: str) -> str:
    if record.startswith('crate::'):
        return record
    while record.startswith('super::'):
        owner = owner.rpartition('::')[0]
        record = record.removeprefix('super::')
    return f"{owner}::{record.removeprefix('self::')}"


def _source_types(sources: dict[Path, str]) -> tuple[set[str], set[str]]:
    declared = set()
    streams: set[str] = set()
    for path, source in sources.items():
        scopes: list[str | None] = [_source_module(path)]
        for token in TYPE_OR_SCOPE.finditer(blank_comments_and_strings(source)):
            module, name, record = token.groups()
            owner = scopes[-1]
            if name is not None:
                if owner is not None:
                    declared.add(f'{owner}::{name}')
            elif record is not None:
                if owner is not None:
                    streams.add(_record_path(owner, record))
            elif token[0] == '}':
                if len(scopes) > 1:
                    scopes.pop()
            else:
                scopes.append(f'{owner}::{module}' if owner is not None and module else None)
    return declared, streams


def registry_problems(root: Path, schema: RegistrySchema, jsonschema: Any, published: set[str],
                      sources: dict[Path, str]) -> list[str]:
    """The contract registry must agree with the schema, sources, and examples."""
    problems: list[str] = []
    sources = {path: text for path, text in sources.items() if path.is_relative_to(CLI_SRC)}
    declared, streams = _source_types(sources)
    rows = read_registry('\n'.join(sources.values()))
    if not rows:
        return [f'{REGISTRY}: no PublishedType rows found']
    definitions = schema.definitions
    examples: dict[str, list[Any]] = {}
    output_examples = set(output_example_paths(root))

    def example_records(relative: str) -> list[Any]:
        if relative not in examples:
            path = root / relative
            if not path.is_file():
                examples[relative] = []
            else:
                text = path.read_text(encoding='utf-8')
                records, parse_problems = parsed_records(relative, text, path.suffix == '.ndjson')
                examples[relative] = [record for _, record in records]
                if path not in output_examples:
                    problems.extend(parse_problems)
                    for label, record in records:
                        problems.extend(code_problems(label, record, published))
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
            if rust_type not in declared:
                problems.append(f'{label}: rust type {rust_type} is not defined')
            if 'output' not in rust_type.split('::'):
                problems.append(f'{label}: rust type {rust_type} is outside an output module')
        if not (root / row.example).is_file():
            problems.append(f'{label}: example {row.example} does not exist')
            continue
        modes = sorted(schema.modes.get(row.definition, {}).get(row.command, ()))
        if not modes:
            problems.append(f'{label}: no success branch for this command')
            continue
        validator = jsonschema.Draft202012Validator(
            {'$ref': f'#/$defs/{row.definition}', '$defs': definitions})
        if not any(isinstance(record, dict) and record.get('status') == 'success'
                   and record.get('command') == row.command and record.get('mode') in modes
                   and validator.is_valid(record) for record in example_records(row.example)):
            problems.append(f'{label}: {row.example} has no successful {"/".join(modes)} '
                            f'record for {row.command!r} matching {row.definition}')

    for name, by_command in sorted(schema.modes.items()):
        referenced = set(by_command)
        pinned = set(_consts(definitions.get(name, {}), 'command'))
        if referenced != pinned:
            problems.append(f'{REGISTRY}: {name} referenced by {sorted(referenced)}, schema pins {sorted(pinned)}')
        actual = claimed.get(name, set())
        if actual != referenced:
            problems.append(f'{REGISTRY}: {name} claims {sorted(actual)}, schema references {sorted(referenced)}')
    for stream_type in sorted(streams - registered_types):
        problems.append(f'{REGISTRY}: stream record type {stream_type} is not registered')
    return problems


def check(root: Path, binary: Path | None = None) -> list[str]:
    identity = read_identity((root / CONTRACT).read_text(encoding='utf-8'))
    schema_set = load_schema_set(root, identity)
    try:
        inventory = validate_manifest(read_json(root / RELEASE_ASSETS))
    except ValueError as error:
        raise CheckError(f'{RELEASE_ASSETS}: {error}') from error
    problems = check_identity(schema_set.envelope_schema, identity)
    problems.extend(check_release_assets(inventory.source_assets, identity, schema_set.required_assets))
    sources = production_sources(root)
    published = published_codes(sources.values())
    try:
        problems.extend(registry_problems(root, schema_set.registry, load_jsonschema(), published, sources))
    except CheckError as error:
        raise CheckError(f'{identity.schema_path}: {error}') from error
    problems.extend(example_problems(root, schema_set.validator, published))
    if binary is not None:
        problems.extend(runtime_problems(binary, root, schema_set.validator, published))
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
