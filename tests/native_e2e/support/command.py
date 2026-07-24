# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Bounded subprocess execution with a complete command audit trail."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
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
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
                start_new_session=True,
            )
        except OSError as error:
            self.records.append(CommandRecord(command, f"exec error: {error}"))
            raise CommandFailure(command, "could not execute", stderr=str(error)) from error

        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            cleanup_errors = self._terminate_process_group(process, privileged)
            stdout, stderr = self._collect_after_abort(process, error, cleanup_errors)
            outcome = f"timeout after {timeout:.1f}s"
            if cleanup_errors:
                outcome += "; " + "; ".join(cleanup_errors)
            self.records.append(CommandRecord(command, outcome))
            raise CommandFailure(
                command,
                outcome,
                stdout,
                stderr,
            ) from error
        except BaseException as error:
            cleanup_errors = self._terminate_process_group(process, privileged)
            self._close_capture_pipes(process)
            outcome = f"interrupted by {type(error).__name__}"
            if cleanup_errors:
                outcome += "; " + "; ".join(cleanup_errors)
            self.records.append(CommandRecord(command, outcome))
            raise

        completed = subprocess.CompletedProcess(
            command,
            process.returncode,
            stdout,
            stderr,
        )
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

    def _terminate_process_group(
        self,
        process: subprocess.Popen[str],
        privileged: bool,
    ) -> list[str]:
        """Terminate every descendant sharing the command's isolated process group."""
        errors: list[str] = []
        process_group = process.pid
        self._signal_process_group(process_group, "TERM", privileged, errors)
        try:
            process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            pass
        self._signal_process_group(process_group, "KILL", privileged, errors)
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            errors.append(
                f"process-group leader {process.pid} survived SIGKILL"
            )
        deadline = time.monotonic() + 2.0
        while (
            self._process_group_exists(process_group)
            and time.monotonic() < deadline
        ):
            time.sleep(0.02)
        if self._process_group_exists(process_group):
            errors.append(f"process group {process_group} survived SIGKILL")
        return errors

    def _signal_process_group(
        self,
        process_group: int,
        signal_name: str,
        privileged: bool,
        errors: list[str],
    ) -> None:
        command = self.command(
            ("kill", f"-{signal_name}", "--", f"-{process_group}"),
            privileged=privileged,
        )
        try:
            completed = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=2.0,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            errors.append(
                f"could not send SIG{signal_name} to process group "
                f"{process_group}: {error}"
            )
            return
        self.records.append(
            CommandRecord(command, f"exit {completed.returncode}")
        )
        if completed.returncode != 0 and self._process_group_exists(process_group):
            errors.append(
                f"could not send SIG{signal_name} to process group "
                f"{process_group}: "
                f"{completed.stderr.strip() or completed.stdout.strip()}"
            )

    @classmethod
    def _process_group_exists(cls, process_group: int) -> bool:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return True
        return cls._process_group_has_running_members(process_group)

    @classmethod
    def _process_group_has_running_members(cls, process_group: int) -> bool:
        for stat_path in Path("/proc").glob("[0-9]*/stat"):
            member = cls._process_stat(stat_path)
            if member is None:
                continue
            member_group, member_state = member
            if member_group == process_group and member_state not in ("X", "Z"):
                return True
        return False

    @staticmethod
    def _process_stat(stat_path: Path) -> tuple[int, str] | None:
        try:
            stat = stat_path.read_text(encoding="utf-8")
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            return None
        command_end = stat.rfind(")")
        if command_end == -1:
            return None
        fields = stat[command_end + 2 :].split()
        if len(fields) < 3:
            return None
        state = fields[0]
        try:
            process_group = int(fields[2])
        except ValueError:
            return None
        return process_group, state

    def _collect_after_abort(
        self,
        process: subprocess.Popen[str],
        timeout_error: subprocess.TimeoutExpired,
        errors: list[str],
    ) -> tuple[str, str]:
        stdout = self._decode_timeout_output(timeout_error.stdout)
        stderr = self._decode_timeout_output(timeout_error.stderr)
        try:
            final_stdout, final_stderr = process.communicate(timeout=2.0)
        except subprocess.TimeoutExpired as error:
            stdout = self._decode_timeout_output(error.stdout) or stdout
            stderr = self._decode_timeout_output(error.stderr) or stderr
            errors.append(
                "capture pipes remained open after process-group termination"
            )
            self._close_capture_pipes(process)
        else:
            stdout = final_stdout
            stderr = final_stderr
        return stdout, stderr

    @staticmethod
    def _close_capture_pipes(process: subprocess.Popen[str]) -> None:
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()

    @staticmethod
    def _decode_timeout_output(value: bytes | str | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value
