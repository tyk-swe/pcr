# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from support import ROOT, load_script

checker = load_script('check_output_schema')

IDENTITY = checker.Identity('packetcraftr.output/v7', 7)
SCHEMA = {
    '$schema': 'https://json-schema.org/draft/2020-12/schema',
    '$id': 'urn:packetcraftr:output:v7',
    '$ref': '#/$defs/baseEnvelope',
    '$defs': {'baseEnvelope': {
        'type': 'object',
        'required': ['schema', 'status'],
        'properties': {'schema': {'const': 'packetcraftr.output/v7'},
                       'status': {'enum': ['success', 'error']}},
    }},
}
VALID = {'schema': 'packetcraftr.output/v7', 'status': 'success'}


def with_const(value):
    schema = json.loads(json.dumps(SCHEMA))
    schema['$defs']['baseEnvelope']['properties']['schema']['const'] = value
    return schema


class IdentityTests(unittest.TestCase):
    def test_identity_matches_runtime_constant(self):
        source = 'use x;\n/// doc\npub const OUTPUT_SCHEMA: &str = "packetcraftr.output/v19";\n'
        identity = checker.read_identity(source)
        self.assertEqual(identity, checker.Identity('packetcraftr.output/v19', 19))
        self.assertEqual(identity.schema_path, 'schemas/packetcraftr.output.v19.schema.json')
        self.assertEqual(identity.urn, 'urn:packetcraftr:output:v19')

    def test_invalid_runtime_constant_fails(self):
        for source in ('', 'pub const SCHEMA_V1: &str = "packetcraftr.output/v1";',
                       'pub const OUTPUT_SCHEMA: &str = "packetcraftr.output/v0";',
                       'pub const OUTPUT_SCHEMA: &str = "packetcraftr.packet/v1";'):
            with self.subTest(source=source), self.assertRaises(checker.CheckError):
                checker.read_identity(source)

    def test_agreeing_schema_identity_passes(self):
        self.assertEqual(checker.check_identity(SCHEMA, IDENTITY), [])

    def test_each_identity_disagreement_is_reported(self):
        cases = {
            '$id': dict(SCHEMA, **{'$id': 'urn:packetcraftr:output:v1'}),
            'const': with_const('packetcraftr.output/v1'),
            'missing const': dict(SCHEMA, **{'$defs': {}}),
        }
        for label, schema in cases.items():
            with self.subTest(label=label):
                problems = checker.check_identity(schema, IDENTITY)
                self.assertEqual(len(problems), 1, problems)


class ReleaseAssetTests(unittest.TestCase):
    CURRENT = 'schemas/packetcraftr.output.v7.schema.json'

    def test_current_schema_alone_passes(self):
        assets = ['LICENSE', self.CURRENT, 'schemas/packetcraftr.packet.v1.schema.json']
        self.assertEqual(checker.check_release_assets(assets, IDENTITY), [])

    def test_missing_current_schema_is_reported(self):
        problems = checker.check_release_assets(['LICENSE'], IDENTITY)
        self.assertEqual(len(problems), 1)
        self.assertIn(self.CURRENT, problems[0])

    def test_reports_obsolete_output_schemas(self):
        for extra in ('schemas/packetcraftr.output.v1.schema.json',
                      'schemas/historical/packetcraftr.output.v1-reset-4766fe78.schema.json'):
            with self.subTest(extra=extra):
                problems = checker.check_release_assets([self.CURRENT, extra], IDENTITY)
                self.assertEqual(len(problems), 1)
                self.assertIn(extra, problems[0])


class DocumentValidationTests(unittest.TestCase):
    def setUp(self):
        self.validator = checker.load_validator(SCHEMA)

    def test_validates_json_and_ndjson_examples(self):
        with tempfile.TemporaryDirectory() as directory:
            documents = Path(directory) / 'examples' / 'documents'
            documents.mkdir(parents=True)
            (documents / 'output-good.json').write_text(json.dumps(VALID))
            (documents / 'packet-ignored.json').write_text('{}')
            (documents / 'output-stream.ndjson').write_text(
                json.dumps(VALID) + '\n' + json.dumps(dict(VALID, status='bogus')) + '\n')
            problems = checker.example_problems(Path(directory), self.validator, set())
        self.assertEqual(len(problems), 1, problems)
        self.assertIn('output-stream.ndjson:2', problems[0])

    def test_unpublished_code_is_rejected(self):
        document = dict(VALID, error={'code': 'cli.invented', 'message': 'x', 'kind': 'usage'})
        problems = checker.code_problems('doc', document, {'cli.known'})
        self.assertEqual(len(problems), 1)
        self.assertIn('cli.invented', problems[0])
        self.assertEqual(checker.code_problems('doc', document, {'cli.invented'}), [])

    def test_wrong_identity_document_is_rejected(self):
        problems = checker.document_problems(
            self.validator, 'doc', dict(VALID, schema='packetcraftr.output/v1'))
        self.assertEqual(len(problems), 1)
        self.assertIn('doc', problems[0])

    def test_missing_jsonschema_reports_install_steps(self):
        with patch.dict(sys.modules, {'jsonschema': None}):
            with self.assertRaisesRegex(checker.CheckError, 'jsonschema'):
                checker.load_validator(SCHEMA)

    def test_missing_jsonschema_reports_install_steps_through_check(self):
        with patch.dict(sys.modules, {'jsonschema': None}):
            with self.assertRaisesRegex(checker.CheckError, 'jsonschema'):
                checker.check(ROOT)

    def test_published_codes_skip_test_sources(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            live = root / 'crates/mini/src/live.rs'
            live.parent.mkdir(parents=True)
            live.write_text(
                '// #[cfg(test)] appears only in this example\n'
                'const DOC: &str = r#"#[cfg(test)]"#;\n'
                'fn f() { let _ = "cli.live"; }\n'
                '#[cfg(test)]\nmod tests {\n'
                '    fn g() { assert!(1 < 2); let _ = "cli.inline_test"; }\n}\n'
                'fn after_tests() { let _ = "cli.after"; }\n'
            )
            tests = root / 'crates/mini/tests/check.rs'
            tests.parent.mkdir(parents=True)
            tests.write_text('fn g() { let _ = "cli.test_file"; }\n')
            self.assertEqual(checker.published_codes(root), {'cli.live', 'cli.after'})

    def test_invalid_schema_is_rejected(self):
        with self.assertRaises(checker.CheckError):
            checker.load_validator(dict(SCHEMA, type=7))


class RuntimeValidationTests(unittest.TestCase):
    COMMANDS = (
        checker.RuntimeCommand(('--output', 'json', 'aggregate'), succeeds=True),
        checker.RuntimeCommand(('--output', 'ndjson', 'stream'), succeeds=True),
        checker.RuntimeCommand(('--output', 'json', 'missing'), succeeds=False),
    )

    def fake_binary(self, directory, document, stdout=None):
        path = Path(directory) / 'fake-cli'
        body = stdout if stdout is not None else json.dumps(document) + '\n'
        path.write_text(
            f'#!{sys.executable}\nimport sys\n'
            f'sys.stdout.write({body!r})\n'
            "sys.exit(2 if 'missing' in sys.argv else 0)\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def problems(self, document=VALID, stdout=None):
        validator = checker.load_validator(SCHEMA)
        with tempfile.TemporaryDirectory() as directory:
            binary = self.fake_binary(directory, document, stdout)
            return checker.runtime_problems(binary, Path(directory), validator, set(), self.COMMANDS)

    def test_conforming_runtime_output_passes(self):
        self.assertEqual(self.problems(), [])

    def test_reports_invalid_output_per_command(self):
        problems = self.problems(dict(VALID, schema='packetcraftr.output/v1'))
        self.assertEqual(len(problems), len(self.COMMANDS), problems)

    def test_reports_empty_and_nonjson_output(self):
        for stdout in ('', 'not json\n'):
            with self.subTest(stdout=stdout):
                self.assertEqual(len(self.problems(stdout=stdout)), len(self.COMMANDS))

    def test_unexpected_exit_status_is_reported(self):
        commands = (checker.RuntimeCommand(('--output', 'json', 'missing'), succeeds=True),)
        validator = checker.load_validator(SCHEMA)
        with tempfile.TemporaryDirectory() as directory:
            binary = self.fake_binary(directory, VALID)
            problems = checker.runtime_problems(binary, Path(directory), validator, set(), commands)
        self.assertEqual(len(problems), 1)
        self.assertIn('exit', problems[0])


REGISTRY_SCHEMA = {
    '$defs': {
        'aggregateSuccess': {'allOf': [{'$ref': '#/$defs/buildSuccess'}]},
        'streamSuccess': {'allOf': [{'$ref': '#/$defs/buildStreamSuccess'}]},
        'buildSuccess': {
            'type': 'object',
            'properties': {'command': {'const': 'build'}, 'status': {'const': 'success'}},
            'required': ['command', 'status'],
        },
        'buildStreamSuccess': {
            'type': 'object',
            'properties': {
                'command': {'const': 'build'},
                'event': {'enum': ['packet', 'complete']},
                'status': {'const': 'success'},
            },
            'required': ['command', 'status'],
        },
    },
}

REGISTRY_SOURCE = '''
pub const PUBLISHED_TYPES: &[PublishedType] = &[
    PublishedType {
        definition: "buildSuccess",
        command: "build",
        rust_types: &["crate::output::build::Report"],
        events: &[],
        example: "examples/documents/output-build-success.json",
    },
    PublishedType {
        definition: "buildStreamSuccess",
        command: "build",
        rust_types: &["crate::output::build::PacketEvent", "crate::output::build::Complete"],
        events: &["complete", "packet"],
        example: "examples/documents/output-build-complete.json",
    },
];
'''


class RegistryTests(unittest.TestCase):
    def workspace(self, registry_source):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        files = {
            'crates/packetcraftr-cli/src/output/contract.rs': registry_source,
            'crates/packetcraftr-cli/src/output/build.rs':
                'pub struct Report {}\npub struct Complete {}\n'
                'pub struct PacketEvent {}\n'
                'impl StreamRecord for PacketEvent {\n'
                '    fn event_name(&self) -> &\'static str { "packet" }\n}\n'
                'impl StreamRecord for Complete {\n'
                '    fn event_name(&self) -> &\'static str { "complete" }\n}\n',
            'examples/documents/output-build-success.json':
                json.dumps({'command': 'build', 'status': 'success'}),
            'examples/documents/output-build-complete.json':
                json.dumps({'command': 'build', 'event': 'complete', 'status': 'success'}),
        }
        for relative, text in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return root

    def test_agreeing_registry_passes(self):
        root = self.workspace(REGISTRY_SOURCE)
        self.assertEqual(checker.registry_problems(root, REGISTRY_SCHEMA, checker.load_jsonschema()), [])

    def test_registry_ignores_comments_and_test_only_records(self):
        root = self.workspace(REGISTRY_SOURCE + '\n/*\n' + REGISTRY_SOURCE + '\n*/\n')
        output = root / checker.CLI_SRC / 'output/build.rs'
        source = output.read_text()
        output.write_text(source + '''
#[cfg(test)]
mod tests {
    pub struct TestRecord;
    impl StreamRecord for TestRecord {
        fn event_name(&self) -> &'static str { "test" }
    }
}
/*
impl StreamRecord for CommentedRecord {
    fn event_name(&self) -> &'static str { "commented" }
}
*/
''')
        self.assertEqual(checker.registry_problems(root, REGISTRY_SCHEMA, checker.load_jsonschema()), [])
        output.write_text(source.replace('pub struct Report {}', '/* pub struct Report {} */'))
        problems = checker.registry_problems(root, REGISTRY_SCHEMA, checker.load_jsonschema())
        self.assertEqual(len(problems), 1)
        self.assertIn('rust type crate::output::build::Report is not defined', problems[0])

    def test_reports_unused_schema_definitions(self):
        root = self.workspace(REGISTRY_SOURCE.replace('buildSuccess"', 'goneSuccess"'))
        problems = checker.registry_problems(root, REGISTRY_SCHEMA, checker.load_jsonschema())
        self.assertTrue(any('no such schema definition' in problem for problem in problems))
        self.assertTrue(any('buildSuccess claims' in problem for problem in problems))

    def test_unregistered_stream_type_is_reported(self):
        source = REGISTRY_SOURCE.replace('"crate::output::build::PacketEvent", ', '')
        root = self.workspace(source)
        problems = checker.registry_problems(root, REGISTRY_SCHEMA, checker.load_jsonschema())
        self.assertTrue(any('PacketEvent' in problem for problem in problems))

    def registered_at(self, module):
        relative = module.removeprefix('crate::').replace('::', '/')
        root = self.workspace(REGISTRY_SOURCE.replace('crate::output::build::Report',
                                                      f'{module}::Report'))
        path = root / checker.CLI_SRC / f'{relative}.rs'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('pub struct Report {}\n')
        return checker.registry_problems(root, REGISTRY_SCHEMA, checker.load_jsonschema())

    def test_published_type_in_a_command_output_module_passes(self):
        self.assertEqual(self.registered_at('crate::commands::packet::build::output'), [])

    def test_published_type_outside_an_output_module_is_reported(self):
        for module in ('crate::commands::packet::build', 'crate::staged_output'):
            with self.subTest(module=module):
                problems = self.registered_at(module)
                self.assertEqual(len(problems), 1)
                self.assertIn('outside an output module', problems[0])


class RepositoryTests(unittest.TestCase):
    def test_repository_outputs_match_current_schema(self):
        self.assertEqual(checker.check(ROOT), [])


if __name__ == '__main__':
    unittest.main()
