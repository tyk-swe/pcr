// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::IpNetwork;

use super::error::InterfaceError;
use super::types::{DestinationSelectionReason, InterfaceSelectionReason, SourceSelectionReason};
use crate::engine::spec::{PacketSpec, TargetAddress, TransportSpec};
use crate::network::interface;
use crate::util::net::resolve_target_ip;
use crate::util::source_ip::select_interface_ipv6_source_for_destination;

type Result<T> = std::result::Result<T, InterfaceError>;

pub(crate) struct SelectedInterface {
    pub(crate) interface: NetworkInterface,
    pub(crate) reason: InterfaceSelectionReason,
}

pub(crate) fn select_interface_with_reason(spec: &PacketSpec) -> Result<SelectedInterface> {
    if let Some(name) = spec.target.interface.as_ref() {
        let selection = interface::find_interface_selection(Some(name))
            .map_err(|source| InterfaceError::InterfaceLookup { source })?;
        return Ok(SelectedInterface {
            interface: selection.interface,
            reason: map_interface_selection_reason(selection.reason),
        });
    }

    // Determine destination IP for routing query
    let destination_ip = spec.ip.as_ref().and_then(|ip| ip.destination).or_else(|| {
        spec.target.address.as_ref().and_then(|addr| match addr {
            TargetAddress::Ip(ip) | TargetAddress::ResolvedHost { ip, .. } => Some(*ip),
            TargetAddress::Host(host) => {
                // Resolve hostname to IP
                let prefer_ipv6 = desired_ipv6(spec);
                resolve_target_ip(host, prefer_ipv6).ok()
            }
        })
    });

    // Use routing table if destination IP is known
    if let Some(dest) = destination_ip {
        let selection = interface::find_interface_for_destination_selection(dest)
            .map_err(|source| InterfaceError::InterfaceLookup { source })?;
        return Ok(SelectedInterface {
            interface: selection.interface,
            reason: map_interface_selection_reason(selection.reason),
        });
    }

    // Fallback to heuristic selection
    let interfaces = datalink::interfaces();
    Ok(SelectedInterface {
        interface: select_interface_from_list(spec, interfaces)?,
        reason: InterfaceSelectionReason::Heuristic,
    })
}

fn map_interface_selection_reason(
    reason: interface::InterfaceSelectionReason,
) -> InterfaceSelectionReason {
    match reason {
        interface::InterfaceSelectionReason::ExplicitInterface => {
            InterfaceSelectionReason::ExplicitInterface
        }
        interface::InterfaceSelectionReason::RouteTable => InterfaceSelectionReason::RouteTable,
        interface::InterfaceSelectionReason::Heuristic => InterfaceSelectionReason::Heuristic,
    }
}

fn select_interface_from_list(
    spec: &PacketSpec,
    interfaces: Vec<NetworkInterface>,
) -> Result<NetworkInterface> {
    let prefer_ipv6 = desired_ipv6(spec);
    let require_mac = interface_requires_mac(spec);

    interfaces
        .into_iter()
        .filter(|iface| iface.is_up() && !iface.is_loopback())
        .filter(|iface| !require_mac || iface.mac.is_some())
        .find(|iface| match prefer_ipv6 {
            Some(true) => interface_ipv6(iface).is_some(),
            Some(false) => interface_ipv4(iface).is_some(),
            None => interface_ipv4(iface).is_some() || interface_ipv6(iface).is_some(),
        })
        .ok_or(InterfaceError::InterfaceSelection)
}

/// Check if interface MAC is required (L2 overrides or L2 transmission).
fn interface_requires_mac(spec: &PacketSpec) -> bool {
    let layer2_overrides = spec.layer2.source.is_some()
        || spec.layer2.destination.is_some()
        || spec.layer2.ethertype.is_some();
    let wants_layer2 = !spec.transmit.is_layer3();
    layer2_overrides || wants_layer2
}

pub(crate) fn interface_ipv4(interface: &NetworkInterface) -> Option<Ipv4Addr> {
    interface.ips.iter().find_map(|ip| match ip {
        IpNetwork::V4(v4) => Some(v4.ip()),
        _ => None,
    })
}

pub(crate) fn interface_ipv6(interface: &NetworkInterface) -> Option<Ipv6Addr> {
    interface.ips.iter().find_map(|ip| match ip {
        IpNetwork::V6(v6) => Some(v6.ip()),
        _ => None,
    })
}

pub(crate) fn desired_ipv6(spec: &PacketSpec) -> Option<bool> {
    if let Some(ip) = spec.ip.as_ref().and_then(|ip| ip.destination) {
        return Some(matches!(ip, IpAddr::V6(_)));
    }
    if let Some(addr) = spec
        .target
        .address
        .as_ref()
        .and_then(TargetAddress::resolved_ip)
    {
        return Some(matches!(addr, IpAddr::V6(_)));
    }
    spec.ip.as_ref().and_then(|ip| ip.prefer_ipv6).or_else(|| {
        spec.ip
            .as_ref()
            .and_then(|ip| ip.source)
            .map(|ip| matches!(ip, IpAddr::V6(_)))
    })
}

pub(crate) struct IpAddressSelection {
    pub(crate) source_ip: IpAddr,
    pub(crate) source_reason: SourceSelectionReason,
    pub(crate) destination_ip: IpAddr,
    pub(crate) destination_reason: DestinationSelectionReason,
}

pub(crate) fn resolve_ip_addresses_with_selection(
    spec: &PacketSpec,
    interface: &NetworkInterface,
) -> Result<IpAddressSelection> {
    let ip_spec = spec.ip.as_ref();
    let prefer_ipv6 = ip_spec
        .and_then(|ip| ip.prefer_ipv6)
        .or_else(|| {
            ip_spec
                .and_then(|ip| ip.destination)
                .map(|addr| matches!(addr, IpAddr::V6(_)))
        })
        .or_else(|| {
            ip_spec
                .and_then(|ip| ip.source)
                .map(|addr| matches!(addr, IpAddr::V6(_)))
        })
        .or(match &spec.transport {
            TransportSpec::Icmpv6(_) => Some(true),
            TransportSpec::Icmp(_) => Some(false),
            _ => None,
        });

    let (destination_ip, destination_reason) =
        if let Some(ip) = ip_spec.and_then(|ip| ip.destination) {
            (ip, DestinationSelectionReason::TargetLiteral)
        } else if let Some(address) = spec.target.address.as_ref() {
            match address {
                TargetAddress::Ip(ip) => (*ip, DestinationSelectionReason::TargetLiteral),
                TargetAddress::ResolvedHost { ip, .. } => {
                    (*ip, DestinationSelectionReason::HostnameResolution)
                }
                TargetAddress::Host(host) => {
                    let ip = resolve_target_ip(host, prefer_ipv6).map_err(|source| {
                        InterfaceError::HostnameResolution {
                            host: host.clone(),
                            source,
                        }
                    })?;
                    (ip, DestinationSelectionReason::HostnameResolution)
                }
            }
        } else {
            return Err(InterfaceError::DestinationRequired);
        };

    let (source_ip, source_reason) = match ip_spec.and_then(|ip| ip.source) {
        Some(addr) => (addr, SourceSelectionReason::ExplicitSourceIp),
        None => match destination_ip {
            IpAddr::V4(_) => (
                interface_ipv4(interface)
                    .filter(|addr| !addr.is_unspecified())
                    .map(IpAddr::V4)
                    .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                SourceSelectionReason::InterfaceAddress,
            ),
            IpAddr::V6(destination) => {
                let selected = select_interface_ipv6_source_for_destination(interface, destination)
                    .filter(|addr| !addr.is_unspecified())
                    .map(IpAddr::V6)
                    .unwrap_or_else(|| IpAddr::V6(Ipv6Addr::UNSPECIFIED));
                (selected, SourceSelectionReason::Ipv6ScopeMatch)
            }
        },
    };

    Ok(IpAddressSelection {
        source_ip,
        source_reason,
        destination_ip,
        destination_reason,
    })
}
