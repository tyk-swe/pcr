# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Strict prerequisite and capability probes for the dedicated entry point."""

from __future__ import annotations

import json
import os
import platform
import secrets
import shutil
import sys

from .command import CommandFailure, CommandRunner
from .topology import _base36


class PrerequisiteError(RuntimeError):
    """The host cannot run the native namespace harness."""


def check_prerequisites(runner: CommandRunner) -> None:
    if platform.system() != "Linux":
        raise PrerequisiteError(
            f"Linux is required; detected {platform.system() or sys.platform}"
        )
    if sys.version_info < (3, 9):
        raise PrerequisiteError(
            "Python 3.9 or newer is required; "
            f"detected {platform.python_version()}"
        )
    for command in ("ip", "python3", "sysctl"):
        if shutil.which(command) is None:
            raise PrerequisiteError(
                f"required command '{command}' was not found in PATH"
            )
    if not os.path.exists("/proc/self/ns/net"):
        raise PrerequisiteError(
            "the Linux network-namespace handle /proc/self/ns/net is unavailable"
        )
    if not os.path.isdir("/proc/sys/net/ipv6"):
        raise PrerequisiteError("IPv6 kernel support is unavailable")

    _probe_namespace_and_veth(runner)


def _probe_namespace_and_veth(runner: CommandRunner) -> None:
    pid = os.getpid()
    suffix = secrets.token_hex(3)
    compact = f"{_base36(pid)[-6:]}{suffix}"
    namespace = f"pcr-preflight-{pid}-{suffix}"
    host_interface = f"f{compact}h"
    peer_interface = f"f{compact}n"
    failure: BaseException | None = None

    try:
        runner.run(("ip", "netns", "list"), privileged=True)
        runner.run(("ip", "netns", "add", namespace), privileged=True)
        runner.run(
            (
                "ip",
                "link",
                "add",
                host_interface,
                "type",
                "veth",
                "peer",
                "name",
                peer_interface,
            ),
            privileged=True,
        )
        runner.run(
            ("ip", "link", "set", "dev", peer_interface, "netns", namespace),
            privileged=True,
        )
        runner.run(
            ("ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up"),
            privileged=True,
        )
        runner.run(
            (
                "ip",
                "netns",
                "exec",
                namespace,
                "ip",
                "-6",
                "address",
                "add",
                "fd70:6372:ffff::1/128",
                "dev",
                "lo",
                "nodad",
            ),
            privileged=True,
        )
        for setting in (
            "net.ipv4.ip_forward=1",
            "net.ipv6.conf.all.forwarding=1",
        ):
            runner.run(
                (
                    "ip",
                    "netns",
                    "exec",
                    namespace,
                    "sysctl",
                    "-q",
                    "-w",
                    setting,
                ),
                privileged=True,
            )
    except BaseException as error:
        failure = error

    cleanup_errors: list[str] = []
    for argv in (
        ("ip", "link", "del", "dev", host_interface),
        ("ip", "netns", "del", namespace),
    ):
        try:
            completed = runner.run(
                argv,
                privileged=True,
                check=False,
                timeout=10.0,
            )
            if completed.returncode != 0 and _probe_resource_exists(
                runner, namespace, host_interface
            ):
                cleanup_errors.append(
                    f"{' '.join(argv)}: "
                    f"{completed.stderr.strip() or completed.stdout.strip()}"
                )
        except CommandFailure as error:
            cleanup_errors.append(str(error))

    try:
        cleanup_errors.extend(
            _probe_leaks(runner, namespace, host_interface, peer_interface)
        )
    except CommandFailure as error:
        cleanup_errors.append(f"preflight leak check failed: {error}")
    if cleanup_errors:
        detail = "; ".join(cleanup_errors)
        if failure is None:
            failure = RuntimeError(f"preflight cleanup failed: {detail}")
        else:
            failure = RuntimeError(f"{failure}; preflight cleanup failed: {detail}")

    if failure is not None:
        raise PrerequisiteError(
            "network namespaces and veth pairs could not be created safely. "
            "The harness needs CAP_NET_ADMIN plus permission to create named "
            "network namespaces (normally root/CAP_SYS_ADMIN with /run/netns "
            "mount access). Run `sudo -v` before scripts/test-native-e2e or "
            f"grant equivalent capabilities. Probe failure: {failure}"
        ) from failure


def _probe_resource_exists(
    runner: CommandRunner, namespace: str, host_interface: str
) -> bool:
    namespaces = runner.run(
        ("ip", "netns", "list"),
        privileged=True,
        check=False,
    )
    if any(
        line.split() and line.split()[0] == namespace
        for line in namespaces.stdout.splitlines()
    ):
        return True
    link = runner.run(
        ("ip", "link", "show", "dev", host_interface),
        privileged=True,
        check=False,
    )
    return link.returncode == 0


def _probe_leaks(
    runner: CommandRunner,
    namespace: str,
    host_interface: str,
    peer_interface: str,
) -> list[str]:
    errors: list[str] = []
    namespaces = runner.run(
        ("ip", "netns", "list"),
        privileged=True,
        check=False,
    )
    if any(
        line.split() and line.split()[0] == namespace
        for line in namespaces.stdout.splitlines()
    ):
        errors.append(f"preflight namespace leaked: {namespace}")

    links = runner.run(
        ("ip", "-j", "link", "show"),
        privileged=True,
        check=False,
    )
    try:
        names = {link["ifname"] for link in json.loads(links.stdout or "[]")}
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        errors.append(f"could not parse preflight host links: {error}")
        names = set()
    for interface in (host_interface, peer_interface):
        if interface in names:
            errors.append(f"preflight veth leaked: {interface}")
    return errors
