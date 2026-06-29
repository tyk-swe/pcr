// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, Context, Result};
use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::IpNetwork;

use crate::util::error::operation_failed;

/// Attempts to determine the source IP address that the OS would use to reach the given destination.
///
/// This is done by creating a UDP socket and connecting it to the destination. No packets are sent.
/// The `port` argument is used for the connection but does not need to be open on the remote host.
pub fn discover_source_ip(destination: IpAddr, port: u16) -> Result<IpAddr> {
    discover_impl(destination, port)
}

pub fn discover_source_ipv4(destination: Ipv4Addr, port: u16) -> Result<Ipv4Addr> {
    match discover_impl(IpAddr::V4(destination), port)? {
        IpAddr::V4(addr) => Ok(addr),
        other => Err(anyhow!(
            "source IP discovery returned {} for IPv4 destination {}",
            other,
            destination
        )),
    }
}

pub fn discover_source_ipv6(destination: Ipv6Addr, port: u16) -> Result<Ipv6Addr> {
    match discover_impl(IpAddr::V6(destination), port)? {
        IpAddr::V6(addr) => Ok(addr),
        other => Err(anyhow!(
            "source IP discovery returned {} for IPv6 destination {}",
            other,
            destination
        )),
    }
}

pub fn resolve_interface_or_ip_override(
    interface: Option<&str>,
    target: IpAddr,
) -> Result<Option<IpAddr>> {
    let Some(spec) = interface.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    if let Ok(addr) = spec.parse::<IpAddr>() {
        if is_matching_ip_family(addr, target) {
            return Ok(Some(addr));
        }
        return Err(anyhow!(
            "interface override {} does not match target address family",
            addr
        ));
    }

    let iface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == spec)
        .ok_or_else(|| anyhow!("interface {spec} not found"))?;

    let family = if target.is_ipv4() { "IPv4" } else { "IPv6" };
    let candidate = match target {
        IpAddr::V4(_) => iface.ips.iter().find_map(|network| match network {
            IpNetwork::V4(v4) => Some(IpAddr::V4(v4.ip())),
            _ => None,
        }),
        IpAddr::V6(destination) => {
            select_interface_ipv6_source_for_destination(&iface, destination).map(IpAddr::V6)
        }
    };

    candidate
        .map(Some)
        .ok_or_else(|| anyhow!("interface {spec} does not have a {family} address"))
}

pub fn source_override_ipv4(source_override: Option<IpAddr>) -> Result<Option<Ipv4Addr>> {
    source_override
        .map(|ip| match ip {
            IpAddr::V4(v4) => Ok(v4),
            IpAddr::V6(_) => Err(anyhow!(
                "IPv6 interface override cannot be used for IPv4 target"
            )),
        })
        .transpose()
}

pub fn source_override_ipv6(source_override: Option<IpAddr>) -> Result<Option<Ipv6Addr>> {
    source_override
        .map(|ip| match ip {
            IpAddr::V6(v6) => Ok(v6),
            IpAddr::V4(_) => Err(anyhow!(
                "IPv4 interface override cannot be used for IPv6 target"
            )),
        })
        .transpose()
}

fn is_matching_ip_family(candidate: IpAddr, target: IpAddr) -> bool {
    (candidate.is_ipv4() && target.is_ipv4()) || (candidate.is_ipv6() && target.is_ipv6())
}

pub(crate) fn select_ipv6_source_for_destination<I>(
    addresses: I,
    destination: Ipv6Addr,
) -> Option<Ipv6Addr>
where
    I: IntoIterator<Item = Ipv6Addr>,
{
    let wants_link_local = destination.is_unicast_link_local();
    let mut fallback = None;

    for address in addresses {
        if address.is_unspecified() {
            continue;
        }
        if fallback.is_none() {
            fallback = Some(address);
        }

        let same_scope = if wants_link_local {
            address.is_unicast_link_local()
        } else {
            !address.is_unicast_link_local()
        };
        if same_scope {
            return Some(address);
        }
    }

    fallback
}

pub(crate) fn select_interface_ipv6_source_for_destination(
    interface: &NetworkInterface,
    destination: Ipv6Addr,
) -> Option<Ipv6Addr> {
    select_ipv6_source_for_destination(
        interface.ips.iter().filter_map(|network| match network {
            IpNetwork::V6(v6) => Some(v6.ip()),
            _ => None,
        }),
        destination,
    )
}

fn discover_impl(destination: IpAddr, port: u16) -> Result<IpAddr> {
    let (bind_ip, family) = match destination {
        IpAddr::V4(_) => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), "IPv4"),
        IpAddr::V6(_) => (IpAddr::V6(Ipv6Addr::UNSPECIFIED), "IPv6"),
    };

    let bind_addr = (bind_ip, 0);
    let socket = std::net::UdpSocket::bind(bind_addr).with_context(|| {
        operation_failed(
            &format!("bind socket for {} source discovery", family),
            format!("addr={bind_addr:?}"),
        )
    })?;

    socket.connect((destination, port)).with_context(|| {
        operation_failed(
            &format!("determine {} source address", family),
            format!("destination={} port={}", destination, port),
        )
    })?;

    let local_addr = socket.local_addr()?;
    match (destination, local_addr) {
        (IpAddr::V4(_), SocketAddr::V4(addr)) => Ok(IpAddr::V4(*addr.ip())),
        (IpAddr::V6(_), SocketAddr::V6(addr)) => Ok(IpAddr::V6(*addr.ip())),
        (IpAddr::V4(_), _) => Err(anyhow!(
            "unexpected local address family for IPv4 source discovery"
        )),
        (IpAddr::V6(_), _) => Err(anyhow!(
            "unexpected local address family for IPv6 source discovery"
        )),
    }
}
