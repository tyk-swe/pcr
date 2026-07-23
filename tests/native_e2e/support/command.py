# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Bounded subprocess execution with a complete command audit trail."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from typing import IO, Mapping, Sequence


@dataclass
class CommandRecord:
    argv: tuple[str, ...]
    outcome: str

    def render(self, sequence: int) -> str:
        return f"[{sequence:03d}] $ {shlex.join(self.argv)} [{self.outcome}]"


class CommandFailure(RuntimeError):
    """A command failed or exceeded its bounded execution window."""

    def __init__(
        self,
        argv: Sequence[str],
        outcome: str,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        self.argv = tuple(argv)
        self.outcome = outcome
        self.stdout = stdout
        self.stderr = stderr
        detail = stderr.strip() or stdout.strip() or "no command output"
        super().__init__(
            f"{shlex.join(self.argv)} [{self.outcome}]: {detail}"
        )


class CommandRunner:
    """Runs commands directly or through the selected privilege boundary."""

    def __init__(self, privilege_prefix: Sequence[str], *, verbose: bool = False) -> None:
        self._privilege_prefix = tuple(privilege_prefix)
        self._verbose = verbose
        self.records: list[CommandRecord] = []

    @classmethod
    def from_environment(cls) -> "CommandRunner":
        mode = os.environ.get("PCR_NATIVE_E2E_PRIVILEGE_MODE", "direct")
        if mode == "direct":
            prefix: tuple[str, ...] = ()
        elif mode == "sudo":
            prefix = ("sudo", "--non-interactive", "--")
        else:
            raise ValueError(
                "PCR_NATIVE_E2E_PRIVILEGE_MODE must be 'direct' or 'sudo'"
            )
        verbose = os.environ.get("PCR_NATIVE_E2E_VERBOSE") == "1"
        return cls(prefix, verbose=verbose)

    def command(self, argv: Sequence[str], *, privileged: bool) -> tuple[str, ...]:
        command = tuple(str(argument) for argument in argv)
        if privileged:
            return (*self._privilege_prefix, *command)
        return command

    def run(
        self,
        argv: Sequence[str],
        *,
        privileged: bool = False,
        check: bool = True,
        timeout: float = 10.0,
        env: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = self.command(argv, privileged=privileged)
        if self._verbose:
            print(f"+ {shlex.join(command)}", file=sys.stderr, flush=True)
        try:
            completed = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                env=env,
            )
        except subprocess.TimeoutExpired as error:
            stdout = self._decode_timeout_output(error.stdout)
            stderr = self._decode_timeout_output(error.stderr)
            self.records.append(CommandRecord(command, f"timeout after {timeout:.1f}s"))
            raise CommandFailure(
                command,
                f"timeout after {timeout:.1f}s",
                stdout,
                stderr,
            ) from error
        except OSError as error:
            self.records.append(CommandRecord(command, f"exec error: {error}"))
            raise CommandFailure(command, "could not execute", stderr=str(error)) from error

        self.records.append(CommandRecord(command, f"exit {completed.returncode}"))
        if check and completed.returncode != 0:
            raise CommandFailure(
                command,
                f"exit {completed.returncode}",
                completed.stdout,
                completed.stderr,
            )
        return completed

    def start(
        self,
        argv: Sequence[str],
        *,
        privileged: bool = False,
        stdout: IO[str],
        stderr: IO[str],
        env: Mapping[str, str] | None = None,
    ) -> subprocess.Popen[str]:
        command = self.command(argv, privileged=privileged)
        if self._verbose:
            print(f"+ {shlex.join(command)} &", file=sys.stderr, flush=True)
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
                start_new_session=True,
            )
        except OSError as error:
            self.records.append(CommandRecord(command, f"exec error: {error}"))
            raise CommandFailure(command, "could not execute", stderr=str(error)) from error
        self.records.append(CommandRecord(command, f"started pid {process.pid}"))
        return process

    def note_process_exit(self, process: subprocess.Popen[str]) -> None:
        self.records.append(
            CommandRecord(
                (f"<background pid {process.pid}>",),
                f"exit {process.returncode}",
            )
        )

    def format_log(self) -> str:
        return "\n".join(
            record.render(sequence)
            for sequence, record in enumerate(self.records, start=1)
        )

    @staticmethod
    def _decode_timeout_output(value: bytes | str | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value
