# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import json
from pathlib import Path
import tempfile
import unittest

from support import load_script

documents = load_script("check_documents")
REPO = Path(__file__).resolve().parents[2]

SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["schema"],
    "additionalProperties": False,
    "properties": {"schema": {"const": "packetcraftr.indicators/v1"}},
}


def workspace(files: dict[str, str]):
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name)
    historical = root / documents.HISTORICAL[0]
    historical.parent.mkdir(parents=True)
    historical.write_bytes((REPO / documents.HISTORICAL[0]).read_bytes())
    twins = {
        relative: '{"schema": "packetcraftr.indicators/v1"}'
        for pair in documents.TWIN_PAIRS
        for relative in pair
    }
    base = {
        "examples/consumers/forwarding.py": 'SCHEMA = "packetcraftr.output/v19"\n',
        "crates/packetcraftr-cli/src/output/contract.rs":
            'pub const OUTPUT_SCHEMA: &str = "packetcraftr.output/v19";\n',
        "schemas/packetcraftr.indicators.v1.schema.json": json.dumps(SCHEMA),
    }
    for relative, text in {**twins, **base, **files}.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return temporary, root


class CheckDocumentsTests(unittest.TestCase):
    def check(self, files: dict[str, str]):
        temporary, root = workspace(files)
        self.addCleanup(temporary.cleanup)
        return documents.check_documents(root)

    def test_missing_jsonschema_reports_install_steps(self):
        import sys
        from unittest.mock import patch

        with patch.dict(sys.modules, {"jsonschema": None}):
            with self.assertRaisesRegex(documents.CheckError, "jsonschema"):
                documents.check_documents(REPO)

    def test_real_documents_pass(self):
        self.assertEqual(documents.check_documents(REPO), [])

    def test_document_matching_its_schema_passes(self):
        problems = self.check({
            "examples/documents/indicators.json": '{"schema": "packetcraftr.indicators/v1"}',
        })
        self.assertEqual(problems, [])

    def test_document_breaking_its_schema_fails(self):
        problems = self.check({
            "examples/documents/indicators.json":
                '{"schema": "packetcraftr.indicators/v1", "extra": 1}',
        })
        self.assertTrue(any("indicators.json" in problem for problem in problems))

    def test_schema_is_required_even_when_other_documents_claim_the_schema(self):
        cases = {
            "examples/documents/second-indicators.json": "{}",
            "examples/documents/second-indicators.yaml": "schema: 1\n",
            "examples/documents/second-indicators.yml": "- not an object\n",
            "crates/packetcraftr/data/second-indicators.json": '{"schema": null}',
        }
        for path, source in cases.items():
            with self.subTest(path=path):
                self.assertEqual(
                    self.check({path: source}),
                    [f"{path}: expected a top-level 'schema' string"],
                )

    def test_invalid_schema_fails_even_when_document_omits_the_affected_property(self):
        schema_path = "schemas/packetcraftr.indicators.v1.schema.json"
        invalid_schema = SCHEMA | {
            "properties": SCHEMA["properties"] | {"count": {"type": "integeer"}},
        }
        with self.assertRaisesRegex(documents.CheckError, r"indicators\.v1\.schema\.json: invalid schema"):
            self.check({
                "examples/documents/indicators.json": '{"schema": "packetcraftr.indicators/v1"}',
                schema_path: json.dumps(invalid_schema),
            })

    def test_unclaimed_schema_fails(self):
        problems = self.check({
            "schemas/packetcraftr.packet.v1.schema.json": json.dumps(SCHEMA),
        })
        self.assertTrue(any("no document claims" in problem for problem in problems))

    def test_twin_drift_fails(self):
        problems = self.check({
            "examples/documents/indicators.json": '{"schema": "packetcraftr.indicators/v1"}',
            "examples/documents/service-probes.json": '{"schema": "packetcraftr.indicators/v1"}\n',
        })
        self.assertTrue(any("byte-identical" in problem for problem in problems))

    def test_duplicate_runtime_identifier_is_reported_at_its_source(self):
        contract = "crates/packetcraftr-cli/src/output/contract.rs"
        problems = self.check({
            "examples/documents/indicators.json": '{"schema": "packetcraftr.indicators/v1"}',
            contract: 'pub const OUTPUT_SCHEMA: &str = "packetcraftr.output/v19";\n'
                      'pub const OUTPUT_SCHEMA: &str = "packetcraftr.output/v20"; // next version\n',
        })
        self.assertEqual(len(problems), 1, problems)
        self.assertIn(contract, problems[0])
        self.assertIn("OUTPUT_SCHEMA", problems[0])

    def test_forwarding_schema_mismatch_is_reported_at_the_consumer(self):
        consumer = "examples/consumers/forwarding.py"
        problems = self.check({
            "examples/documents/indicators.json": '{"schema": "packetcraftr.indicators/v1"}',
            consumer: 'SCHEMA = "packetcraftr.output/v20"\n',
        })
        self.assertEqual(len(problems), 1, problems)
        self.assertIn(consumer, problems[0])
        self.assertIn("OUTPUT_SCHEMA", problems[0])

    def test_yaml_documents_are_validated_without_test_sources(self):
        for name in ("packet-raw.yaml", "new.yaml", "new.yml"):
            with self.subTest(name=name):
                path = f"examples/documents/{name}"
                source = "schema: packetcraftr.indicators/v1\n"
                self.assertEqual(self.check({path: source}), [])
                problems = self.check({path: source + "extra: 1\n"})
                self.assertTrue(any(name in problem and "extra" in problem for problem in problems))

    def test_invalid_yaml_reports_its_path(self):
        with self.assertRaisesRegex(documents.CheckError, "broken.yaml"):
            self.check({"examples/documents/broken.yaml": "schema: [\n"})

    def test_missing_yaml_parser_reports_install_steps(self):
        import sys
        from unittest.mock import patch

        with patch.dict(sys.modules, {"yaml": None}):
            with self.assertRaisesRegex(documents.CheckError, "PyYAML"):
                self.check({
                    "examples/documents/indicators.yaml": "schema: packetcraftr.indicators/v1\n",
                })

    def test_main_reports_missing_files_without_a_traceback(self):
        import contextlib
        import io
        import sys
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as empty:
            stderr = io.StringIO()
            with patch.object(sys, "argv", ["check_documents", "--root", empty]):
                with contextlib.redirect_stderr(stderr):
                    result = documents.main()
        self.assertEqual(result, 2)
        self.assertTrue(stderr.getvalue().startswith("error:"))
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_frozen_historical_schema_drift_fails(self):
        problems = self.check({
            "examples/documents/indicators.json": '{"schema": "packetcraftr.indicators/v1"}',
            documents.HISTORICAL[0]: "modified\n",
        })
        self.assertTrue(any("frozen schema changed" in problem for problem in problems))


if __name__ == "__main__":
    unittest.main()
