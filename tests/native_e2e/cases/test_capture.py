# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Offline regression tests for capture NDJSON parsing."""

import subprocess
import unittest
from pathlib import Path

from . import capture


class CaptureRecordTests(unittest.TestCase):
    def test_records_reject_schema_invalid_record(self) -> None:
        completed = subprocess.CompletedProcess(
            (),
            0,
            '{"status":"success"}\n',
            "",
        )
        with self.assertRaisesRegex(AssertionError, "output did not validate"):
            capture._records(Path(__file__).resolve().parent.parent, completed)
