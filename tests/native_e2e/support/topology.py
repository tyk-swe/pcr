# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

"""Deterministic three-namespace Linux topology ownership."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import secrets
from dataclasses import dataclass
from typing import Any

from .command import CommandFailure, CommandRunner


def _base36(value: int) -> str:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    digits: list[str] = []
    while value:
        value, remainder = divmod(value, len(alphabet))
        digits.append(alphabet[remainder])
    return "".join(reversed(digits)) or "0"


@dataclass(frozen=True)
class TopologyNames:
    run_id: str
    client_namespace: str
    router_namespace: str
    server_namespace: str
    client_interface: str
    router_client_interface: str
    router_server_interface: str
    server_interface: str

    @classmethod
    def unique(cls) -> "TopologyNames":
        pid = os.getpid()
        hint = os.environ.get("PCR_NATIVE_E2E_RUN_ID")
        suffix = (
            hashlib.sha256(hint.encode("utf-8")).hexdigest()[:6]
            if hint is not None
            else secrets.token_hex(3)
        )
        run_id = f"{pid}-{suffix}"
        compact = f"{_base36(pid)[-6:]}{suffix}"
        names = cls(
            run_id=run_id,
            client_namespace=f"pcr-client-{run_id}",
            router_namespace=f"pcr-router-{run_id}",
            server_namespace=f"pcr-server-{run_id}",
            client_interface=f"p{compact}c",
            router_client_interface=f"p{compact}r0",
            router_server_interface=f"p{compact}r1",
            server_interface=f"p{compact}s",
        )
        interfaces = names.interfaces
        if len(set(interfaces)) != len(interfaces):
            raise RuntimeError("generated native-E2E interface names are not unique")
        if any(len(name) > 15 for name in interfaces):
            raise RuntimeError("generated native-E2E interface name exceeds Linux IFNAMSIZ")
        return names

    @property
    def namespaces(self) -> tuple[str, str, str]:
        return (
            self.client_namespace,
            self.router_namespace,
            self.server_namespace,
        )

    @property
    def interfaces(self) -> tuple[str, str, str, str]:
        return (
            self.client_interface,
            self.router_client_interface,
            self.router_server_interface,
            self.server_interface,
        )


@dataclass(frozen=True)
class AddressPlan:
    client_ipv4: str = "10.203.0.2"
    router_client_ipv4: str = "10.203.0.1"
    router_server_ipv4: str = "10.203.0.5"
    server_ipv4: str = "10.203.0.6"
    client_ipv4_network: str = "10.203.0.0/30"
    server_ipv4_network: str = "10.203.0.4/30"
    client_ipv6: str = "fd70:6372:1::2"
    router_client_ipv6: str = "fd70:6372:1::1"
    router_server_ipv6: str = "fd70:6372:2::1"
    server_ipv6: str = "fd70:6372:2::2"
    client_ipv6_network: str = "fd70:6372:1::/64"
    server_ipv6_network: str = "fd70:6372:2::/64"

    def validate(self) -> None:
        for address in (
            self.client_ipv4,
            self.router_client_ipv4,
            self.router_server_ipv4,
            self.server_ipv4,
        ):
            parsed = ipaddress.ip_address(address)
            if not isinstance(parsed, ipaddress.IPv4Address) or not parsed.is_private:
                raise RuntimeError(f"{address} is not a private IPv4 address")
        for address in (
            self.client_ipv6,
            self.router_client_ipv6,
            self.router_server_ipv6,
            self.server_ipv6,
        ):
            parsed = ipaddress.ip_address(address)
            if not isinstance(parsed, ipaddress.IPv6Address) or not parsed.is_private:
                raise RuntimeError(f"{address} is not an IPv6 ULA address")


class Topology:
    """Creates, validates, and removes one isolated namespace graph."""

    def __init__(
        self,
        runner: CommandRunner,
        names: TopologyNames,
        addresses: AddressPlan | None = None,
    ) -> None:
        self.runner = runner
        self.names = names
        self.addresses = addresses or AddressPlan()
        self.addresses.validate()

    def setup(self) -> None:
        names = self.names
        for namespace in names.namespaces:
            self._ip("netns", "add", namespace)

        self._ip(
            "link",
            "add",
            names.client_interface,
            "type",
            "veth",
            "peer",
            "name",
            names.router_client_interface,
        )
        self._ip(
            "link",
            "add",
            names.router_server_interface,
            "type",
            "veth",
            "peer",
            "name",
            names.server_interface,
        )
        for interface, namespace in (
            (names.client_interface, names.client_namespace),
            (names.router_client_interface, names.router_namespace),
            (names.router_server_interface, names.router_namespace),
            (names.server_interface, names.server_namespace),
        ):
            self._ip("link", "set", "dev", interface, "netns", namespace)

        for namespace in names.namespaces:
            self._netns(namespace, "ip", "link", "set", "dev", "lo", "up")
            for setting in (
                "net.ipv4.ip_forward=0",
                "net.ipv6.conf.all.forwarding=0",
                "net.ipv6.conf.all.accept_ra=0",
            ):
                self._netns(
                    namespace,
                    "sysctl",
                    "-q",
                    "-w",
                    setting,
                )

        self._configure_link(
            names.client_namespace,
            names.client_interface,
            f"{self.addresses.client_ipv4}/30",
            f"{self.addresses.client_ipv6}/64",
        )
        self._configure_link(
            names.router_namespace,
            names.router_client_interface,
            f"{self.addresses.router_client_ipv4}/30",
            f"{self.addresses.router_client_ipv6}/64",
        )
        self._configure_link(
            names.router_namespace,
            names.router_server_interface,
            f"{self.addresses.router_server_ipv4}/30",
            f"{self.addresses.router_server_ipv6}/64",
        )
        self._configure_link(
            names.server_namespace,
            names.server_interface,
            f"{self.addresses.server_ipv4}/30",
            f"{self.addresses.server_ipv6}/64",
        )

        self._netns(
            names.router_namespace,
            "sysctl",
            "-q",
            "-w",
            "net.ipv4.ip_forward=1",
        )
        self._netns(
            names.router_namespace,
            "sysctl",
            "-q",
            "-w",
            "net.ipv6.conf.all.forwarding=1",
        )

        self._netns(
            names.client_namespace,
            "ip",
            "-4",
            "route",
            "add",
            self.addresses.server_ipv4_network,
            "via",
            self.addresses.router_client_ipv4,
            "dev",
            names.client_interface,
        )
        self._netns(
            names.server_namespace,
            "ip",
            "-4",
            "route",
            "add",
            self.addresses.client_ipv4_network,
            "via",
            self.addresses.router_server_ipv4,
            "dev",
            names.server_interface,
        )
        self._netns(
            names.client_namespace,
            "ip",
            "-6",
            "route",
            "add",
            self.addresses.server_ipv6_network,
            "via",
            self.addresses.router_client_ipv6,
            "dev",
            names.client_interface,
        )
        self._netns(
            names.server_namespace,
            "ip",
            "-6",
            "route",
            "add",
            self.addresses.client_ipv6_network,
            "via",
            self.addresses.router_server_ipv6,
            "dev",
            names.server_interface,
        )
        self.validate()

    def _configure_link(
        self,
        namespace: str,
        interface: str,
        ipv4: str,
        ipv6: str,
    ) -> None:
        self._netns(namespace, "ip", "-4", "address", "add", ipv4, "dev", interface)
        self._netns(
            namespace,
            "ip",
            "-6",
            "address",
            "add",
            ipv6,
            "dev",
            interface,
            "nodad",
        )
        self._netns(
            namespace,
            "sysctl",
            "-q",
            "-w",
            f"net.ipv6.conf.{interface}.accept_ra=0",
        )
        self._netns(namespace, "ip", "link", "set", "dev", interface, "up")

    def validate(self) -> None:
        names = self.names
        addresses = self.addresses
        for namespace, interface, ipv4, ipv6 in (
            (
                names.client_namespace,
                names.client_interface,
                addresses.client_ipv4,
                addresses.client_ipv6,
            ),
            (
                names.router_namespace,
                names.router_client_interface,
                addresses.router_client_ipv4,
                addresses.router_client_ipv6,
            ),
            (
                names.router_namespace,
                names.router_server_interface,
                addresses.router_server_ipv4,
                addresses.router_server_ipv6,
            ),
            (
                names.server_namespace,
                names.server_interface,
                addresses.server_ipv4,
                addresses.server_ipv6,
            ),
        ):
            self._assert_link_up(namespace, interface)
            self._assert_address(namespace, interface, "-4", ipv4, 30)
            self._assert_address(namespace, interface, "-6", ipv6, 64)

        self._assert_route(
            names.client_namespace,
            "-4",
            addresses.server_ipv4_network,
            names.client_interface,
            addresses.router_client_ipv4,
        )
        self._assert_route(
            names.server_namespace,
            "-4",
            addresses.client_ipv4_network,
            names.server_interface,
            addresses.router_server_ipv4,
        )
        self._assert_route(
            names.client_namespace,
            "-6",
            addresses.server_ipv6_network,
            names.client_interface,
            addresses.router_client_ipv6,
        )
        self._assert_route(
            names.server_namespace,
            "-6",
            addresses.client_ipv6_network,
            names.server_interface,
            addresses.router_server_ipv6,
        )
        for namespace in names.namespaces:
            for family in ("-4", "-6"):
                routes = self._json_netns(
                    namespace, "ip", "-j", family, "route", "show", "default"
                )
                if routes:
                    raise RuntimeError(
                        f"{namespace} unexpectedly has a {family} default route: {routes}"
                    )
        self._assert_sysctl(names.router_namespace, "net.ipv4.ip_forward", "1")
        self._assert_sysctl(
            names.router_namespace, "net.ipv6.conf.all.forwarding", "1"
        )
        for namespace in (names.client_namespace, names.server_namespace):
            self._assert_sysctl(namespace, "net.ipv4.ip_forward", "0")
            self._assert_sysctl(
                namespace, "net.ipv6.conf.all.forwarding", "0"
            )

    def cleanup(self) -> list[str]:
        errors: list[str] = []
        for namespace in reversed(self.names.namespaces):
            try:
                completed = self._ip("netns", "del", namespace, check=False)
                if completed.returncode != 0 and self._namespace_exists(namespace):
                    errors.append(
                        f"could not delete namespace {namespace}: "
                        f"{completed.stderr.strip() or completed.stdout.strip()}"
                    )
            except CommandFailure as error:
                errors.append(
                    f"exception while deleting namespace {namespace}: {error}"
                )
        for interface in self.names.interfaces:
            try:
                completed = self._ip("link", "del", "dev", interface, check=False)
                if completed.returncode != 0 and self._host_interface_exists(interface):
                    errors.append(
                        f"could not delete host interface {interface}: "
                        f"{completed.stderr.strip() or completed.stdout.strip()}"
                    )
            except CommandFailure as error:
                errors.append(
                    f"exception while deleting host interface {interface}: {error}"
                )
        try:
            errors.extend(self.verify_absent())
        except CommandFailure as error:
            errors.append(f"post-cleanup leak check failed: {error}")
        return errors

    def verify_absent(self) -> list[str]:
        errors: list[str] = []
        listed = self._ip("netns", "list", check=False)
        existing_namespaces = {
            line.split()[0] for line in listed.stdout.splitlines() if line.split()
        }
        for namespace in self.names.namespaces:
            if namespace in existing_namespaces:
                errors.append(f"namespace leaked after cleanup: {namespace}")

        links = self._ip("-j", "link", "show", check=False)
        try:
            existing_interfaces = {
                item["ifname"] for item in json.loads(links.stdout or "[]")
            }
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            errors.append(f"could not parse host link state during leak check: {error}")
            existing_interfaces = set()
        for interface in self.names.interfaces:
            if interface in existing_interfaces:
                errors.append(f"veth interface leaked after cleanup: {interface}")
        return errors

    def describe(self) -> str:
        return "\n".join(
            (
                f"run_id={self.names.run_id}",
                f"client={self.names.client_namespace} "
                f"{self.names.client_interface} "
                f"{self.addresses.client_ipv4}/30 "
                f"{self.addresses.client_ipv6}/64",
                f"router={self.names.router_namespace} "
                f"{self.names.router_client_interface},"
                f"{self.names.router_server_interface}",
                f"server={self.names.server_namespace} "
                f"{self.names.server_interface} "
                f"{self.addresses.server_ipv4}/30 "
                f"{self.addresses.server_ipv6}/64",
            )
        )

    def _assert_link_up(self, namespace: str, interface: str) -> None:
        links = self._json_netns(
            namespace, "ip", "-j", "link", "show", "dev", interface
        )
        if len(links) != 1 or "UP" not in links[0].get("flags", []):
            raise RuntimeError(
                f"{namespace}/{interface} did not report the UP flag: {links}"
            )

    def _assert_address(
        self,
        namespace: str,
        interface: str,
        family: str,
        expected: str,
        prefix_length: int,
    ) -> None:
        links = self._json_netns(
            namespace,
            "ip",
            "-j",
            family,
            "address",
            "show",
            "dev",
            interface,
        )
        addresses = [
            (item.get("local"), item.get("prefixlen"))
            for link in links
            for item in link.get("addr_info", [])
        ]
        if (expected, prefix_length) not in addresses:
            raise RuntimeError(
                f"{namespace}/{interface} lacks {expected}/{prefix_length}: {addresses}"
            )

    def _assert_route(
        self,
        namespace: str,
        family: str,
        destination: str,
        interface: str,
        gateway: str,
    ) -> None:
        routes = self._json_netns(
            namespace,
            "ip",
            "-j",
            family,
            "route",
            "show",
            destination,
        )
        if not any(
            route.get("dst") == destination
            and route.get("dev") == interface
            and route.get("gateway") == gateway
            for route in routes
        ):
            raise RuntimeError(
                f"{namespace} lacks route {destination} via {gateway} "
                f"dev {interface}: {routes}"
            )

    def _assert_sysctl(self, namespace: str, key: str, expected: str) -> None:
        completed = self._netns(namespace, "sysctl", "-n", key)
        actual = completed.stdout.strip()
        if actual != expected:
            raise RuntimeError(f"{namespace} {key}={actual!r}, expected {expected!r}")

    def _json_netns(self, namespace: str, *argv: str) -> list[dict[str, Any]]:
        completed = self._netns(namespace, *argv)
        try:
            value = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"invalid JSON from {' '.join(argv)} in {namespace}: {error}"
            ) from error
        if not isinstance(value, list):
            raise RuntimeError(
                f"expected a JSON list from {' '.join(argv)} in {namespace}"
            )
        return value

    def _namespace_exists(self, namespace: str) -> bool:
        listed = self._ip("netns", "list", check=False)
        return any(
            line.split() and line.split()[0] == namespace
            for line in listed.stdout.splitlines()
        )

    def _host_interface_exists(self, interface: str) -> bool:
        return (
            self._ip("link", "show", "dev", interface, check=False).returncode == 0
        )

    def _ip(
        self, *argv: str, check: bool = True
    ) -> Any:
        return self.runner.run(
            ("ip", *argv),
            privileged=True,
            check=check,
            timeout=10.0,
        )

    def _netns(
        self,
        namespace: str,
        *argv: str,
        check: bool = True,
    ) -> Any:
        return self.runner.run(
            ("ip", "netns", "exec", namespace, *argv),
            privileged=True,
            check=check,
            timeout=10.0,
        )
