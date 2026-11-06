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
    twins = {relative: "{}" for pair in documents.TWIN_PAIRS for relative in pair}
    base = {
        documents.HISTORICAL_ADR:
            f"| {documents.HISTORICAL[0]} | {documents.HISTORICAL[1]} |\n",
        "examples/consumers/forwarding.py": 'SCHEMA = "packetcraftr.output/v19"\n',
        "crates/packetcraftr-core/src/security.rs":
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

    def test_unclaimed_schema_fails(self):
        problems = self.check({
            "examples/documents/other.json": "{}",
            "schemas/packetcraftr.packet.v1.schema.json": json.dumps(SCHEMA),
        })
        self.assertTrue(any("no document claims" in problem for problem in problems))

    def test_twin_drift_fails(self):
        problems = self.check({
            "examples/documents/indicators.json": '{"schema": "packetcraftr.indicators/v1"}',
            "examples/documents/service-probes.json": '{"changed": true}',
        })
        self.assertTrue(any("byte-identical" in problem for problem in problems))

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

    def test_adr_hash_drift_fails(self):
        problems = self.check({
            "examples/documents/indicators.json": '{"schema": "packetcraftr.indicators/v1"}',
            documents.HISTORICAL_ADR: "no provenance row here\n",
        })
        self.assertTrue(any("no row ties" in problem for problem in problems))


if __name__ == "__main__":
    unittest.main()
