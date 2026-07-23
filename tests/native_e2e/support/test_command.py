# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Regression tests for bounded native-E2E command ownership."""

from __future__ import annotations

import json
import os
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path

from .command import CommandFailure, CommandRunner
from .topology import AddressPlan, Topology, TopologyNames


DESCENDANT_SCRIPT = """
import json
import os
import subprocess
import sys

child = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(30)"],
)
print(json.dumps({"leader": os.getpid(), "child": child.pid}), flush=True)
child.wait()
"""

INTERRUPTED_DESCENDANT_SCRIPT = """
import json
import os
import subprocess
import sys

child = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(30)"],
)
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump({"leader": os.getpid(), "child": child.pid}, stream)
child.wait()
"""


class ProbeInterrupt(Exception):
    """Raised by the test signal handler while a command owns descendants."""


class CommandRunnerProcessTests(unittest.TestCase):
    def test_timeout_kills_prefixed_process_group_descendants(self) -> None:
        for prefix, privileged in (((), False), (("env",), True)):
            with self.subTest(prefix=prefix, privileged=privileged):
                self._assert_timeout_kills_tree(
                    CommandRunner(prefix),
                    privileged,
                )

    @unittest.skipUnless(
        os.environ.get("PCR_NATIVE_E2E_TEST_PRIVILEGED") == "1",
        "privileged process cleanup probe was not requested",
    )
    def test_timeout_kills_configured_privileged_descendants(self) -> None:
        self._assert_timeout_kills_tree(
            CommandRunner.from_environment(),
            privileged=True,
        )

    @unittest.skipUnless(
        os.environ.get("PCR_NATIVE_E2E_TEST_PRIVILEGED") == "1",
        "privileged namespace cleanup probe was not requested",
    )
    def test_topology_cleanup_drains_namespace_processes(self) -> None:
        runner = CommandRunner.from_environment()
        topology = Topology(
            runner,
            TopologyNames.unique(),
            AddressPlan.isolated(200),
        )
        process = None
        cleaned = False
        with tempfile.TemporaryDirectory(prefix="pcr-drain-test-") as directory:
            stdout_path = Path(directory) / "stdout"
            stderr_path = Path(directory) / "stderr"
            with stdout_path.open("w", encoding="utf-8") as stdout:
                with stderr_path.open("w", encoding="utf-8") as stderr:
                    try:
                        topology.setup()
                        process = runner.start(
                            (
                                "ip",
                                "netns",
                                "exec",
                                topology.names.client_namespace,
                                sys.executable,
                                "-c",
                                "import time; time.sleep(30)",
                            ),
                            privileged=True,
                            stdout=stdout,
                            stderr=stderr,
                        )
                        self._wait_for_namespace_process(runner, topology)
                        self.assertEqual(topology.cleanup(), [])
                        cleaned = True
                        process.wait(timeout=3.0)
                    finally:
                        if not cleaned:
                            topology.cleanup()
                        if process is not None and process.poll() is None:
                            runner.run(
                                ("kill", "-KILL", "--", f"-{process.pid}"),
                                privileged=True,
                                check=False,
                                timeout=2.0,
                            )
                            process.wait(timeout=2.0)

    @unittest.skipUnless(
        os.environ.get("PCR_NATIVE_E2E_TEST_PRIVILEGED") == "1",
        "privileged namespace timeout probe was not requested",
    )
    def test_timeout_kills_client_namespace_descendants(self) -> None:
        runner = CommandRunner.from_environment()
        topology = Topology(
            runner,
            TopologyNames.unique(),
            AddressPlan.isolated(199),
        )
        cleaned = False
        try:
            topology.setup()
            with self.assertRaises(CommandFailure) as raised:
                runner.run(
                    (
                        "ip",
                        "netns",
                        "exec",
                        topology.names.client_namespace,
                        sys.executable,
                        "-c",
                        DESCENDANT_SCRIPT,
                    ),
                    privileged=True,
                    timeout=1.0,
                )
            identity = json.loads(raised.exception.stdout.strip())
            pids = (identity["leader"], identity["child"])
            self._wait_for_exit(pids)
            self.assertEqual(
                self._namespace_pids(runner, topology),
                (),
            )
            self.assertEqual(topology.cleanup(), [])
            cleaned = True
        finally:
            if not cleaned:
                topology.cleanup()

    def test_interruption_kills_process_group_descendants(self) -> None:
        runner = CommandRunner(())
        pids: tuple[int, ...] = ()
        previous_handler = signal.getsignal(signal.SIGALRM)

        def interrupt(_signum: int, _frame: object) -> None:
            raise ProbeInterrupt

        with tempfile.TemporaryDirectory(prefix="pcr-command-test-") as directory:
            identity_path = Path(directory) / "identity.json"
            try:
                signal.signal(signal.SIGALRM, interrupt)
                signal.setitimer(signal.ITIMER_REAL, 1.0)
                with self.assertRaises(ProbeInterrupt):
                    runner.run(
                        (
                            sys.executable,
                            "-c",
                            INTERRUPTED_DESCENDANT_SCRIPT,
                            str(identity_path),
                        ),
                        timeout=10.0,
                    )
                identity = json.loads(identity_path.read_text(encoding="utf-8"))
                pids = (identity["leader"], identity["child"])
                self._wait_for_exit(pids)
                self.assertTrue(
                    runner.records[-1].outcome.startswith(
                        "interrupted by ProbeInterrupt"
                    ),
                    runner.records[-1].outcome,
                )
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0.0)
                signal.signal(signal.SIGALRM, previous_handler)
                if pids:
                    runner.run(
                        ("kill", "-KILL", "--", *[str(pid) for pid in pids]),
                        check=False,
                        timeout=2.0,
                    )

    def _assert_timeout_kills_tree(
        self,
        runner: CommandRunner,
        privileged: bool,
    ) -> None:
        pids: tuple[int, ...] = ()
        try:
            with self.assertRaises(CommandFailure) as raised:
                runner.run(
                    (sys.executable, "-c", DESCENDANT_SCRIPT),
                    privileged=privileged,
                    timeout=1.0,
                )
            failure = raised.exception
            self.assertTrue(
                failure.outcome.startswith("timeout after 1.0s"),
                failure.outcome,
            )
            identity = json.loads(failure.stdout.strip())
            pids = (identity["leader"], identity["child"])
            self.assertTrue(all(isinstance(pid, int) and pid > 0 for pid in pids))
            self._wait_for_exit(pids)
        finally:
            if pids:
                runner.run(
                    ("kill", "-KILL", "--", *[str(pid) for pid in pids]),
                    privileged=privileged,
                    check=False,
                    timeout=2.0,
                )

    def _wait_for_exit(self, pids: tuple[int, ...]) -> None:
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if not any(os.path.exists(f"/proc/{pid}") for pid in pids):
                return
            time.sleep(0.02)
        survivors = [pid for pid in pids if os.path.exists(f"/proc/{pid}")]
        self.fail(f"timed-out command descendants survived: {survivors}")

    def _wait_for_namespace_process(
        self,
        runner: CommandRunner,
        topology: Topology,
    ) -> None:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            completed = runner.run(
                (
                    "ip",
                    "netns",
                    "pids",
                    topology.names.client_namespace,
                ),
                privileged=True,
                check=False,
            )
            if completed.stdout.split():
                return
            time.sleep(0.02)
        self.fail("client namespace process never became observable")

    def _namespace_pids(
        self,
        runner: CommandRunner,
        topology: Topology,
    ) -> tuple[int, ...]:
        completed = runner.run(
            (
                "ip",
                "netns",
                "pids",
                topology.names.client_namespace,
            ),
            privileged=True,
            check=False,
        )
        return tuple(int(value) for value in completed.stdout.split())


if __name__ == "__main__":
    unittest.main()
