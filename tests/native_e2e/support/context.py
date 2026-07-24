# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Stable definitions and execution context for command-specific native cases."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from .command import CommandFailure, CommandRunner
from .fixture_process import ResponderProcess
from .topology import Topology


@dataclass(frozen=True)
class NativeCase:
    name: str
    address_slot: int
    source_port: int
    destination_port: int
    tcp_port: int
    run: Callable[["CaseContext"], dict[str, object]]
    udp_mode: str | None = None
    response_port: int | None = None


@dataclass(frozen=True)
class CliInvocation:
    argv: tuple[str, ...]
    outcome: str
    stdout: str
    stderr: str
    elapsed_seconds: float

    def render(self) -> str:
        return "\n".join(
            (
                f"argv={self.argv!r}",
                f"outcome={self.outcome}",
                f"elapsed_seconds={self.elapsed_seconds:.6f}",
                "stdout:",
                self.stdout.rstrip() or "<empty>",
                "stderr:",
                self.stderr.rstrip() or "<empty>",
            )
        )


@dataclass(frozen=True)
class CaseContext:
    case: NativeCase
    packetcraftr_binary: Path
    native_e2e_root: Path
    temporary_directory: Path
    runner: CommandRunner
    topology: Topology
    responder: ResponderProcess | None
    invocations: list[CliInvocation]

    def packetcraftr_environment(self) -> dict[str, str]:
        """Environment additions for command-specific child processes."""
        return {"PACKETCRAFTR_BIN": str(self.packetcraftr_binary)}

    def run_packetcraftr(
        self,
        arguments: Sequence[str],
        *,
        timeout: float = 10.0,
    ) -> subprocess.CompletedProcess[str]:
        argv = (
            "ip",
            "netns",
            "exec",
            self.topology.names.client_namespace,
            str(self.packetcraftr_binary),
            *[str(argument) for argument in arguments],
        )
        started = time.monotonic()
        try:
            completed = self.runner.run(
                argv,
                privileged=True,
                check=False,
                timeout=timeout,
            )
        except CommandFailure as error:
            self.invocations.append(
                CliInvocation(
                    argv=tuple(error.argv),
                    outcome=error.outcome,
                    stdout=error.stdout,
                    stderr=error.stderr,
                    elapsed_seconds=time.monotonic() - started,
                )
            )
            raise
        self.invocations.append(
            CliInvocation(
                argv=tuple(self.runner.command(argv, privileged=True)),
                outcome=f"exit {completed.returncode}",
                stdout=completed.stdout,
                stderr=completed.stderr,
                elapsed_seconds=time.monotonic() - started,
            )
        )
        return completed

    def require_responder(self) -> ResponderProcess:
        if self.responder is None:
            raise RuntimeError(f"{self.case.name} has no independent UDP fixture")
        self.responder.ensure_running()
        return self.responder

    def format_invocations(self) -> str:
        if not self.invocations:
            return "<PacketcraftR was not invoked>"
        return "\n\n".join(
            f"--- PacketcraftR invocation {index} ---\n{invocation.render()}"
            for index, invocation in enumerate(self.invocations, start=1)
        )
