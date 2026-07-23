# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Failure-time namespace, route, neighbor, and forwarding diagnostics."""

from __future__ import annotations

from dataclasses import dataclass

from .command import CommandFailure, CommandRunner
from .topology import Topology


@dataclass(frozen=True)
class DiagnosticSection:
    title: str
    body: str


def collect(runner: CommandRunner, topology: Topology) -> str:
    sections: list[DiagnosticSection] = []
    _capture(
        sections,
        runner,
        "host: ip netns list",
        ("ip", "netns", "list"),
    )
    _capture(
        sections,
        runner,
        "host: detailed link state",
        ("ip", "-details", "-statistics", "link", "show"),
    )

    for namespace in topology.names.namespaces:
        prefix = ("ip", "netns", "exec", namespace)
        for title, command in (
            (
                "link state",
                ("ip", "-details", "-statistics", "link", "show"),
            ),
            ("IPv4 addresses", ("ip", "-4", "address", "show")),
            ("IPv6 addresses", ("ip", "-6", "address", "show")),
            (
                "IPv4 routes",
                ("ip", "-4", "route", "show", "table", "all"),
            ),
            (
                "IPv6 routes",
                ("ip", "-6", "route", "show", "table", "all"),
            ),
            ("IPv4 neighbors", ("ip", "-4", "neighbor", "show")),
            ("IPv6 neighbors", ("ip", "-6", "neighbor", "show")),
            (
                "forwarding state",
                (
                    "sysctl",
                    "net.ipv4.ip_forward",
                    "net.ipv6.conf.all.forwarding",
                ),
            ),
            ("namespace pids", ("ip", "netns", "pids", namespace)),
        ):
            argv = command if title == "namespace pids" else (*prefix, *command)
            _capture(
                sections,
                runner,
                f"{namespace}: {title}",
                argv,
            )

    return "\n\n".join(
        f"--- {section.title} ---\n{section.body}"
        for section in sections
    )


def _capture(
    sections: list[DiagnosticSection],
    runner: CommandRunner,
    title: str,
    argv: tuple[str, ...],
) -> None:
    try:
        completed = runner.run(
            argv,
            privileged=True,
            check=False,
            timeout=5.0,
        )
        output = completed.stdout.rstrip()
        stderr = completed.stderr.rstrip()
        parts = [f"exit={completed.returncode}"]
        parts.append(output if output else "<stdout empty>")
        if stderr:
            parts.append(f"stderr:\n{stderr}")
        sections.append(DiagnosticSection(title, "\n".join(parts)))
    except CommandFailure as error:
        sections.append(DiagnosticSection(title, f"diagnostic command failed: {error}"))
