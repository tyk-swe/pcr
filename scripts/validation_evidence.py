# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared provenance for independent validation reports (not product output)."""
import hashlib
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent


def digest(path):
    with pathlib.Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def provenance(binary):
    return dict(commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
                binary_sha256=digest(binary),
                binary_version=subprocess.check_output([str(binary), '--version'], text=True, timeout=10).strip())
