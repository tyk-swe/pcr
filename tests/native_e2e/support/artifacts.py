# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Optional persistence for native-E2E failure evidence."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

ARTIFACT_DIRECTORY_ENVIRONMENT = "PCR_NATIVE_E2E_ARTIFACT_DIR"


def directory_from_environment() -> Path | None:
    value = os.environ.get(ARTIFACT_DIRECTORY_ENVIRONMENT)
    if value is None:
        return None
    if not value:
        raise ValueError(f"{ARTIFACT_DIRECTORY_ENVIRONMENT} must not be empty")

    directory = Path(value)
    if not directory.is_absolute():
        raise ValueError(
            f"{ARTIFACT_DIRECTORY_ENVIRONMENT} must be an absolute path"
        )
    return directory


def write_failure_files(
    directory: Path | None,
    files: Mapping[str, str],
) -> None:
    if directory is None:
        return

    directory.mkdir(parents=True, exist_ok=True)
    if not directory.is_dir():
        raise RuntimeError(
            f"native-E2E artifact path is not a directory: {directory}"
        )

    for name, contents in files.items():
        if Path(name).name != name:
            raise ValueError(f"native-E2E artifact name is not a file name: {name}")
        normalized = contents if contents.endswith("\n") else f"{contents}\n"
        (directory / name).write_text(normalized, encoding="utf-8")
