# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Stable context passed to native-E2E command-specific cases."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner
from .fixture_process import ResponderProcess
from .topology import Topology


@dataclass(frozen=True)
class CaseContext:
    packetcraftr_binary: Path
    native_e2e_root: Path
    runner: CommandRunner
    topology: Topology
    responder: ResponderProcess

    def packetcraftr_environment(self) -> dict[str, str]:
        """Environment additions for future command-specific child processes."""
        return {"PACKETCRAFTR_BIN": str(self.packetcraftr_binary)}
