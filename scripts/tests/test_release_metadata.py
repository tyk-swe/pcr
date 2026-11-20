# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "release_metadata.py"


def run(packages: list[dict[str, str]], tag: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temporary:
        metadata = Path(temporary) / "cargo-metadata.json"
        metadata.write_text(json.dumps({"packages": packages}), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--metadata", str(metadata), "--tag", tag],
            capture_output=True, text=True, check=False, timeout=30,
        )


def cli(version: str) -> dict[str, str]:
    return {"name": "packetcraftr-cli", "version": version}


class ReleaseMetadataTests(unittest.TestCase):
    def test_prerelease_classification_ignores_build_metadata(self):
        cases = (
            ("1.2.3", "false"),
            ("1.2.3+build.42", "false"),
            ("1.2.3+build-linux.42", "false"),
            ("1.2.3-beta.1", "true"),
            ("1.2.3-beta.1+build-linux.42", "true"),
        )
        for version, prerelease in cases:
            with self.subTest(version=version):
                result = run([{"name": "packetcraftr-core", "version": "9.9.9-rc.1"}, cli(version)],
                             f"v{version}")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, f"prerelease={prerelease}\nversion={version}\n")

    def test_mismatched_tag_fails_without_outputs(self):
        for tag in ("v1.2.4", "1.2.3", "v1.2.3-beta.1"):
            with self.subTest(tag=tag):
                result = run([cli("1.2.3")], tag)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertIn(tag, result.stderr)

    def test_ambiguous_released_package_fails_without_outputs(self):
        for packages in ([], [cli("1.2.3"), cli("1.2.3")]):
            with self.subTest(packages=packages):
                result = run(packages, "v1.2.3")
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
