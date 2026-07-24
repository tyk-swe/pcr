# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Responder process ownership and explicit readiness signaling."""

from __future__ import annotations

import json
import os
import select
import socket
import subprocess
import time
from pathlib import Path
from typing import IO, Any

from .command import CommandFailure, CommandRunner
from .topology import Topology

UDP_PORT = 41_000
TCP_PORT = 41_001


class FixtureError(RuntimeError):
    """The independent responder did not start or stay healthy."""


class ResponderProcess:
    def __init__(
        self,
        runner: CommandRunner,
        topology: Topology,
        native_e2e_root: Path,
        temporary_directory: Path,
        *,
        udp_port: int = UDP_PORT,
        tcp_port: int = TCP_PORT,
        udp_mode: str = "echo",
        udp_response_port: int | None = None,
    ) -> None:
        if udp_mode not in {"echo", "sink", "wrong-port"}:
            raise ValueError(f"unsupported UDP fixture mode {udp_mode!r}")
        for label, port in (
            ("UDP", udp_port),
            ("TCP", tcp_port),
            ("UDP response", udp_response_port),
        ):
            if port is not None and not 1 <= port <= 65_535:
                raise ValueError(f"{label} fixture port must be within 1..=65535")
        if udp_mode == "wrong-port" and udp_response_port is None:
            raise ValueError("wrong-port UDP mode requires a response port")
        if udp_response_port == udp_port:
            raise ValueError("UDP response port must differ from the listener port")
        self.runner = runner
        self.topology = topology
        self.script = native_e2e_root / "fixtures" / "responders.py"
        self.temporary_directory = temporary_directory
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.udp_mode = udp_mode
        self.udp_response_port = udp_response_port
        self.stdout_path = temporary_directory / "responder.stdout"
        self.stderr_path = temporary_directory / "responder.stderr"
        self.readiness_path = temporary_directory / "ready.sock"
        self.event_path = temporary_directory / "events.sock"
        self.process: subprocess.Popen[str] | None = None
        self.fixture_pid: int | None = None
        self._stdout: IO[str] | None = None
        self._stderr: IO[str] | None = None
        self._event_listener: socket.socket | None = None
        self._event_token: str | None = None
        self._exit_recorded = False

    def start(self, timeout: float = 10.0) -> None:
        if self.process is not None:
            raise FixtureError("responder process was started more than once")
        for label, path in (
            ("readiness", self.readiness_path),
            ("event", self.event_path),
        ):
            if len(os.fsencode(path)) >= 100:
                raise FixtureError(f"{label} socket path is too long: {path}")

        token = os.urandom(16).hex()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.readiness_path))
        listener.listen(1)
        event_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        event_listener.bind(str(self.event_path))
        event_listener.listen(8)
        self._event_listener = event_listener
        self._event_token = token
        self._stdout = self.stdout_path.open("w", encoding="utf-8")
        self._stderr = self.stderr_path.open("w", encoding="utf-8")
        command = [
            "ip",
            "netns",
            "exec",
            self.topology.names.server_namespace,
            "python3",
            "-u",
            str(self.script),
            "--ipv4",
            self.topology.addresses.server_ipv4,
            "--ipv6",
            self.topology.addresses.server_ipv6,
            "--udp-port",
            str(self.udp_port),
            "--tcp-port",
            str(self.tcp_port),
            "--udp-mode",
            self.udp_mode,
            "--ready-socket",
            str(self.readiness_path),
            "--ready-token",
            token,
            "--event-socket",
            str(self.event_path),
            "--event-token",
            token,
        ]
        if self.udp_response_port is not None:
            command.extend(("--udp-response-port", str(self.udp_response_port)))
        try:
            self.process = self.runner.start(
                command,
                privileged=True,
                stdout=self._stdout,
                stderr=self._stderr,
            )
            ready = self._wait_ready(listener, timeout)
            self._validate_ready(ready, token)
        except BaseException:
            self._close_event_listener()
            raise
        finally:
            listener.close()
            self.readiness_path.unlink(missing_ok=True)

    def _wait_ready(
        self, listener: socket.socket, timeout: float
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            self.ensure_running()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FixtureError(
                    f"responder did not signal readiness within {timeout:.1f}s"
                )
            readable, _, _ = select.select(
                (listener,),
                (),
                (),
                min(remaining, 0.25),
            )
            if not readable:
                continue
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(max(0.1, deadline - time.monotonic()))
                chunks: list[bytes] = []
                received = 0
                while True:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > 65_536:
                        raise FixtureError("responder readiness message is too large")
                    chunks.append(chunk)
                    if b"\n" in chunk:
                        break
            try:
                value = json.loads(b"".join(chunks).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise FixtureError(
                    f"responder sent invalid readiness data: {error}"
                ) from error
            if not isinstance(value, dict):
                raise FixtureError("responder readiness data was not an object")
            return value

    def _validate_ready(self, ready: dict[str, Any], token: str) -> None:
        if ready.get("token") != token:
            raise FixtureError("responder readiness token did not match")
        pid = ready.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            raise FixtureError(f"responder reported invalid pid {pid!r}")
        expected = {
            (
                family,
                transport,
                address,
                port,
            )
            for family, address in (
                ("ipv4", self.topology.addresses.server_ipv4),
                ("ipv6", self.topology.addresses.server_ipv6),
            )
            for transport, port in (("udp", self.udp_port), ("tcp", self.tcp_port))
        }
        listeners = ready.get("listeners")
        if not isinstance(listeners, list):
            raise FixtureError("responder omitted its listener readiness set")
        actual = {
            (
                listener.get("family"),
                listener.get("transport"),
                listener.get("address"),
                listener.get("port"),
            )
            for listener in listeners
            if isinstance(listener, dict)
        }
        if actual != expected:
            raise FixtureError(
                f"responder listener set {actual!r} did not equal {expected!r}"
            )
        if ready.get("udp_mode") != self.udp_mode:
            raise FixtureError(
                f"responder reported UDP mode {ready.get('udp_mode')!r}, "
                f"expected {self.udp_mode!r}"
            )
        if ready.get("udp_response_port") != self.udp_response_port:
            raise FixtureError(
                "responder reported an unexpected UDP response port: "
                f"{ready.get('udp_response_port')!r}"
            )
        self.fixture_pid = pid
        self.ensure_running()

    def wait_event(
        self,
        event: str,
        family: str,
        *,
        timeout: float = 5.0,
    ) -> dict[str, Any]:
        listener = self._event_listener
        token = self._event_token
        if listener is None or token is None:
            raise FixtureError("responder event barrier is not active")
        value = self._wait_ready(listener, timeout)
        if value.get("token") != token:
            raise FixtureError("responder event token did not match")
        if value.get("event") != event or value.get("family") != family:
            raise FixtureError(
                f"responder event {(value.get('event'), value.get('family'))!r} "
                f"did not equal {(event, family)!r}"
            )
        self.ensure_running()
        return value

    def ensure_running(self) -> None:
        if self.process is None:
            raise FixtureError("responder process has not been started")
        status = self.process.poll()
        if status is not None:
            self._record_exit()
            stdout, stderr = self.logs()
            raise FixtureError(
                f"responder exited early with status {status}; "
                f"stdout={stdout!r}; stderr={stderr!r}"
            )

    def stop(self) -> list[str]:
        errors: list[str] = []
        process = self.process
        if process is None:
            self._close_logs()
            self._close_event_listener()
            return errors

        try:
            try:
                remaining = self._namespace_pids()
            except (CommandFailure, FixtureError) as error:
                errors.append(f"could not enumerate responder pids: {error}")
                remaining = ()
            targets = set(remaining)
            if self.fixture_pid is not None and process.poll() is None:
                targets.add(self.fixture_pid)
            if targets:
                self._signal_pids("TERM", tuple(sorted(targets)), errors)
                deadline = time.monotonic() + 3.0
                while time.monotonic() < deadline:
                    try:
                        remaining = self._namespace_pids()
                    except (CommandFailure, FixtureError) as error:
                        errors.append(
                            f"could not re-enumerate responder pids: {error}"
                        )
                        remaining = tuple(sorted(targets))
                        break
                    if not remaining:
                        break
                    time.sleep(0.05)
                if remaining:
                    self._signal_pids("KILL", remaining, errors)
            try:
                process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self._signal_pids("KILL", (process.pid,), errors)
                try:
                    process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    errors.append(
                        f"responder wrapper pid {process.pid} did not exit"
                    )
            if process.poll() is not None:
                self._record_exit()
            try:
                remaining = self._namespace_pids()
            except (CommandFailure, FixtureError) as error:
                errors.append(f"final responder pid check failed: {error}")
                remaining = ()
            if remaining:
                self._signal_pids("KILL", remaining, errors)
                try:
                    remaining = self._namespace_pids()
                except (CommandFailure, FixtureError) as error:
                    errors.append(
                        f"post-SIGKILL responder pid check failed: {error}"
                    )
                if remaining:
                    errors.append(
                        "responder namespace still contains pids "
                        + ", ".join(str(pid) for pid in remaining)
                    )
        except BaseException as error:
            errors.append(f"responder cleanup raised: {error}")
        finally:
            self._close_logs()
            self._close_event_listener()
        return errors

    def _namespace_pids(self) -> tuple[int, ...]:
        completed = self.runner.run(
            (
                "ip",
                "netns",
                "pids",
                self.topology.names.server_namespace,
            ),
            privileged=True,
            check=False,
            timeout=5.0,
        )
        if completed.returncode != 0:
            return ()
        pids: list[int] = []
        for value in completed.stdout.split():
            try:
                pids.append(int(value))
            except ValueError as error:
                raise FixtureError(
                    f"ip netns pids returned non-numeric value {value!r}"
                ) from error
        return tuple(pids)

    def _signal_pids(
        self, signal_name: str, pids: tuple[int, ...], errors: list[str]
    ) -> None:
        try:
            completed = self.runner.run(
                ("kill", f"-{signal_name}", *[str(pid) for pid in pids]),
                privileged=True,
                check=False,
                timeout=5.0,
            )
        except CommandFailure as error:
            errors.append(f"could not send SIG{signal_name} to {pids}: {error}")
            return
        if completed.returncode != 0:
            errors.append(
                f"could not send SIG{signal_name} to {pids}: "
                f"{completed.stderr.strip() or completed.stdout.strip()}"
            )

    def logs(self) -> tuple[str, str]:
        for stream in (self._stdout, self._stderr):
            if stream is not None and not stream.closed:
                stream.flush()
        return self._read_log(self.stdout_path), self._read_log(self.stderr_path)

    @staticmethod
    def _read_log(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return "<log was not created>"

    def _record_exit(self) -> None:
        if self.process is not None and not self._exit_recorded:
            self.runner.note_process_exit(self.process)
            self._exit_recorded = True

    def _close_logs(self) -> None:
        for stream in (self._stdout, self._stderr):
            if stream is not None and not stream.closed:
                stream.close()

    def _close_event_listener(self) -> None:
        if self._event_listener is not None:
            self._event_listener.close()
            self._event_listener = None
        self.event_path.unlink(missing_ok=True)
