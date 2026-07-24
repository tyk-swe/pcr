#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Strict Linux-native PacketcraftR E2E harness entry."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import tempfile
import traceback
from pathlib import Path
from types import FrameType

sys.dont_write_bytecode = True

NATIVE_E2E_ROOT = Path(__file__).resolve().parent
TESTS_ROOT = NATIVE_E2E_ROOT.parent
if str(TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(TESTS_ROOT))

from native_e2e.cases import exchange, route, send  # noqa: E402
from native_e2e.support import artifacts, diagnostics  # noqa: E402
from native_e2e.support.command import CommandRunner  # noqa: E402
from native_e2e.support.context import (  # noqa: E402
    CaseContext,
    NativeCase,
)
from native_e2e.support.fixture_process import (  # noqa: E402
    ResponderProcess,
)
from native_e2e.support.prerequisites import (  # noqa: E402
    PrerequisiteError,
    check_prerequisites,
)
from native_e2e.support.topology import (  # noqa: E402
    AddressPlan,
    Topology,
    TopologyNames,
)


class HarnessSignal(Exception):
    def __init__(self, signum: int) -> None:
        self.signum = signum
        super().__init__(f"received {signal.Signals(signum).name}")


class SignalGuard:
    def __init__(self) -> None:
        self.previous: dict[int, object] = {}

    def install(self) -> None:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            self.previous[signum] = signal.getsignal(signum)
            signal.signal(signum, self._raise)

    @staticmethod
    def _raise(signum: int, _frame: FrameType | None) -> None:
        raise HarnessSignal(signum)

    def ignore_during_cleanup(self) -> None:
        for signum in self.previous:
            signal.signal(signum, signal.SIG_IGN)

    def restore(self) -> None:
        for signum, handler in self.previous.items():
            signal.signal(signum, handler)


class CaseExecutionError(RuntimeError):
    def __init__(self, report: str, exit_code: int = 1) -> None:
        self.report = report
        self.exit_code = exit_code
        super().__init__(report)


def native_cases() -> tuple[NativeCase, ...]:
    cases = (*route.cases(), *send.cases(), *exchange.cases())
    names = [case.name for case in cases]
    slots = [case.address_slot for case in cases]
    ports = [
        port
        for case in cases
        for port in (
            case.source_port,
            case.destination_port,
            case.tcp_port,
            case.response_port,
        )
        if port is not None
    ]
    if len(set(names)) != len(names):
        raise RuntimeError(f"native-E2E case names are not unique: {names!r}")
    if len(set(slots)) != len(slots):
        raise RuntimeError(f"native-E2E address slots are not unique: {slots!r}")
    if len(set(ports)) != len(ports):
        raise RuntimeError(f"native-E2E ports are not unique: {ports!r}")
    return cases


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build and exercise isolated Linux namespace PacketcraftR paths. "
            "Missing prerequisites are errors, never skips."
        )
    )
    parser.add_argument(
        "--check-prerequisites",
        action="store_true",
        help="probe namespace/veth/forwarding/schema support without building or testing",
    )
    parser.add_argument(
        "--force-failure",
        choices=tuple(case.name for case in native_cases()),
        help="intentionally fail one case to audit diagnostics and cleanup",
    )
    parser.add_argument(
        "--skip-prerequisite-check",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def write_failure_artifacts(
    directory: Path | None,
    files: dict[str, str],
) -> None:
    try:
        artifacts.write_failure_files(directory, files)
    except BaseException as error:
        print(
            f"native-e2e failure artifact error: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
    else:
        if directory is not None:
            print(f"native-e2e failure artifacts: {directory}", file=sys.stderr)


def prerequisite_entry(
    runner: CommandRunner,
    artifact_directory: Path | None,
) -> int:
    signal_guard = SignalGuard()
    signal_guard.install()
    try:
        check_prerequisites(runner)
    except HarnessSignal as error:
        print(f"native-e2e prerequisite probe interrupted: {error}", file=sys.stderr)
        write_failure_artifacts(
            artifact_directory,
            {
                "prerequisite-error.txt": f"{type(error).__name__}: {error}",
                "commands.log": runner.format_log(),
            },
        )
        if runner.records:
            print("\nExact commands executed:", file=sys.stderr)
            print(runner.format_log(), file=sys.stderr)
        return 128 + error.signum
    except (PrerequisiteError, ValueError) as error:
        print(f"native-e2e prerequisite error: {error}", file=sys.stderr)
        write_failure_artifacts(
            artifact_directory,
            {
                "prerequisite-error.txt": f"{type(error).__name__}: {error}",
                "commands.log": runner.format_log(),
            },
        )
        if runner.records:
            print("\nExact commands executed:", file=sys.stderr)
            print(runner.format_log(), file=sys.stderr)
        return 2
    finally:
        signal_guard.restore()
    print("native-e2e prerequisites: PASS")
    return 0


def binary_from_environment() -> Path:
    value = os.environ.get("PACKETCRAFTR_BIN")
    if not value:
        raise RuntimeError(
            "PACKETCRAFTR_BIN is unset; use scripts/test-native-e2e so the "
            "binary is built exactly once"
        )
    binary = Path(value).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"PacketcraftR binary is not executable: {binary}")
    return binary


def run_case(
    runner: CommandRunner,
    binary: Path,
    case: NativeCase,
    force_failure: bool,
    artifact_directory: Path | None,
) -> dict[str, object]:
    names = TopologyNames.unique()
    topology = Topology(runner, names, AddressPlan.isolated(case.address_slot))
    temporary = tempfile.TemporaryDirectory(prefix=f"pcr-e2e-{names.run_id}-")
    temporary_path = Path(temporary.name)
    responder = (
        ResponderProcess(
            runner,
            topology,
            NATIVE_E2E_ROOT,
            temporary_path,
            udp_port=case.destination_port,
            tcp_port=case.tcp_port,
            udp_mode=case.udp_mode,
            udp_response_port=case.response_port,
        )
        if case.udp_mode is not None
        else None
    )
    context = CaseContext(
        case=case,
        packetcraftr_binary=binary,
        native_e2e_root=NATIVE_E2E_ROOT,
        temporary_directory=temporary_path,
        runner=runner,
        topology=topology,
        responder=responder,
        invocations=[],
    )
    signal_guard = SignalGuard()
    signal_guard.install()

    failure: BaseException | None = None
    failure_trace = ""
    before_cleanup = ""
    after_cleanup = ""
    cleanup_errors: list[str] = []
    responder_stdout = "<fixture not used>"
    responder_stderr = "<fixture not used>"
    result: dict[str, object] = {}

    print(f"\nCASE {case.name}")
    print(topology.describe())
    print(
        f"source_port={case.source_port} destination_port={case.destination_port} "
        f"tcp_fixture_port={case.tcp_port} response_port={case.response_port}",
        flush=True,
    )

    try:
        topology.setup()
        if responder is not None:
            responder.start()
        result = case.run(context)
        if force_failure:
            raise RuntimeError(f"intentional failure requested for {case.name}")
    except BaseException as error:
        failure = error
        failure_trace = "".join(
            traceback.format_exception(type(error), error, error.__traceback__)
        )
        try:
            before_cleanup = diagnostics.collect(runner, topology)
        except BaseException as diagnostic_error:
            before_cleanup = f"diagnostic collection failed: {diagnostic_error}"
    finally:
        signal_guard.ignore_during_cleanup()
        if responder is not None:
            try:
                cleanup_errors.extend(responder.stop())
            except BaseException as error:
                cleanup_errors.append(f"responder cleanup raised: {error}")
        try:
            cleanup_errors.extend(topology.cleanup())
        except BaseException as error:
            cleanup_errors.append(f"topology cleanup raised: {error}")
        if responder is not None:
            try:
                responder_stdout, responder_stderr = responder.logs()
            except BaseException as error:
                cleanup_errors.append(f"responder log collection raised: {error}")
        if cleanup_errors:
            try:
                after_cleanup = diagnostics.collect(runner, topology)
            except BaseException as diagnostic_error:
                after_cleanup = (
                    f"post-cleanup diagnostic collection failed: {diagnostic_error}"
                )
        try:
            temporary.cleanup()
        except BaseException as error:
            cleanup_errors.append(f"temporary cleanup raised: {error}")
        if temporary_path.exists():
            cleanup_errors.append(
                f"temporary directory leaked after cleanup: {temporary_path}"
            )
        signal_guard.restore()

    if cleanup_errors and failure is None:
        failure = RuntimeError("; ".join(cleanup_errors))
        failure_trace = f"{type(failure).__name__}: {failure}\n"

    if failure is not None:
        cleanup_report = "\n".join(f"- {error}" for error in cleanup_errors)
        write_failure_artifacts(
            artifact_directory,
            {
                "case.txt": case.name,
                "topology.txt": topology.describe(),
                "failure.txt": failure_trace.rstrip(),
                "cleanup-errors.txt": cleanup_report or "<none>",
                "topology-before-cleanup.txt": before_cleanup or "<not collected>",
                "topology-after-cleanup.txt": after_cleanup or "<not collected>",
                "responder-stdout.log": responder_stdout,
                "responder-stderr.log": responder_stderr,
                "packetcraftr-invocations.log": context.format_invocations(),
                "commands.log": runner.format_log(),
            },
        )
        sections = [
            f"NATIVE E2E CASE FAILURE: {case.name}",
            topology.describe(),
            f"Failure:\n{failure_trace.rstrip()}",
        ]
        if cleanup_errors:
            sections.append(
                "Cleanup errors:\n"
                + "\n".join(f"- {error}" for error in cleanup_errors)
            )
        sections.append(
            "PacketcraftR stdout/stderr/exit records:\n"
            + context.format_invocations()
        )
        if before_cleanup:
            sections.append(f"Diagnostics before cleanup:\n{before_cleanup}")
        if after_cleanup:
            sections.append(f"Diagnostics after cleanup:\n{after_cleanup}")
        sections.extend(
            (
                "Fixture stdout:\n" + (responder_stdout.rstrip() or "<empty>"),
                "Fixture stderr:\n" + (responder_stderr.rstrip() or "<empty>"),
            )
        )
        exit_code = (
            128 + failure.signum if isinstance(failure, HarnessSignal) else 1
        )
        raise CaseExecutionError("\n\n".join(sections), exit_code) from failure

    print(f"PASS {case.name}: {json.dumps(result, sort_keys=True)}", flush=True)
    return result


def run_harness(
    runner: CommandRunner,
    binary: Path,
    forced_failure: str | None,
    artifact_directory: Path | None,
) -> int:
    print(f"packetcraftr_binary={binary}", flush=True)
    results: list[dict[str, object]] = []
    try:
        for case in native_cases():
            results.append(
                run_case(
                    runner,
                    binary,
                    case,
                    force_failure=forced_failure == case.name,
                    artifact_directory=artifact_directory,
                )
            )
    except CaseExecutionError as error:
        print(f"\n{error.report}", file=sys.stderr)
        print("\nExact commands executed:", file=sys.stderr)
        print(runner.format_log(), file=sys.stderr)
        return error.exit_code

    print(
        f"\nnative-e2e PacketcraftR cases: PASS ({len(results)} isolated cases)"
    )
    print(
        "native-e2e cleanup: PASS "
        "(no namespaces, veth devices, fixture processes, or temporary files)"
    )
    return 0


def main() -> int:
    arguments = parse_arguments()
    try:
        runner = CommandRunner.from_environment()
        artifact_directory = artifacts.directory_from_environment()
    except ValueError as error:
        print(f"native-e2e prerequisite error: {error}", file=sys.stderr)
        return 2

    if arguments.check_prerequisites:
        return prerequisite_entry(runner, artifact_directory)
    if not arguments.skip_prerequisite_check:
        status = prerequisite_entry(runner, artifact_directory)
        if status != 0:
            return status
    try:
        binary = binary_from_environment()
    except RuntimeError as error:
        print(f"native-e2e setup error: {error}", file=sys.stderr)
        write_failure_artifacts(
            artifact_directory,
            {
                "setup-error.txt": f"{type(error).__name__}: {error}",
                "commands.log": runner.format_log(),
            },
        )
        return 2
    return run_harness(
        runner,
        binary,
        arguments.force_failure,
        artifact_directory,
    )


if __name__ == "__main__":
    raise SystemExit(main())
