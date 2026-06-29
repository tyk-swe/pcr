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

#[cfg(test)]
pub(crate) fn resolve_ip_addresses(
    spec: &PacketSpec,
    interface: &NetworkInterface,
) -> Result<(IpAddr, IpAddr)> {
    let selection = resolve_ip_addresses_with_selection(spec, interface)?;
    Ok((selection.source_ip, selection.destination_ip))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::request::DestinationRequest;
    use crate::engine::spec::{
        DestinationSpec, Ipv6Spec, Layer2Spec, ListenerSpec, LoggingSpec, PayloadSource,
        PayloadSpec, TransmissionSpec,
    };
    use libc::IFF_UP;
    use pnet::datalink::MacAddr;
    use pnet::ipnetwork::IpNetwork;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn base_spec() -> PacketSpec {
        PacketSpec {
            target: DestinationSpec::default(),
            layer2: Layer2Spec::default(),
            ip: None,
            ipv6: Ipv6Spec::default(),
            transport: TransportSpec::default(),
            payload: PayloadSpec {
                source: PayloadSource::Empty,
            },
            transmit: TransmissionSpec::default(),
            listener: ListenerSpec::default(),
            rules_file: None,
            logging: LoggingSpec::default(),
        }
    }

    fn interface_with(name: &str, mac: Option<MacAddr>, addr: Ipv4Addr) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            description: String::new(),
            index: 0,
            mac,
            ips: vec![IpNetwork::new(IpAddr::V4(addr), 24).expect("ipv4 network")],
            flags: IFF_UP as u32,
        }
    }

    fn interface_with_ipv6(addrs: &[Ipv6Addr]) -> NetworkInterface {
        NetworkInterface {
            name: "v6".to_string(),
            description: String::new(),
            index: 0,
            mac: Some(MacAddr::new(0, 0, 0, 0, 0, 1)),
            ips: addrs
                .iter()
                .copied()
                .map(|addr| IpNetwork::new(IpAddr::V6(addr), 64).expect("ipv6 network"))
                .collect(),
            flags: IFF_UP as u32,
        }
    }

    #[test]
    fn layer3_selection_allows_interfaces_without_mac() {
        let mut spec = base_spec();
        spec.transmit.force_layer3 = true;

        let selected = select_interface_from_list(
            &spec,
            vec![interface_with("lo", None, Ipv4Addr::new(127, 0, 0, 1))],
        )
        .expect("interface selection");

        assert_eq!(selected.name, "lo");
        assert!(selected.mac.is_none());
    }

    #[test]
    fn layer2_selection_requires_mac() {
        let spec = base_spec();
        let result = select_interface_from_list(
            &spec,
            vec![interface_with(
                "no-mac",
                None,
                Ipv4Addr::new(192, 168, 0, 2),
            )],
        );

        assert!(
            result.is_err(),
            "expected selection to fail without MAC for layer2 transmission"
        );
    }

    #[test]
    fn force_layer3_selection_allows_interfaces_without_mac() {
        let mut spec = base_spec();
        spec.transmit.force_layer3 = true;

        let selected = select_interface_from_list(
            &spec,
            vec![interface_with("tun0", None, Ipv4Addr::new(10, 0, 0, 1))],
        )
        .expect("interface selection");

        assert_eq!(selected.name, "tun0");
        assert!(selected.mac.is_none());
    }

    #[test]
    fn desired_ipv6_respects_source_ip() {
        let mut spec = base_spec();
        let ip = crate::engine::spec::IpSpec {
            source: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            ..Default::default()
        };
        spec.ip = Some(ip);

        // Should return Some(false) for IPv4 source
        assert_eq!(desired_ipv6(&spec), Some(false));

        let mut spec_v6 = base_spec();
        let ip_v6 = crate::engine::spec::IpSpec {
            source: Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            ..Default::default()
        };
        spec_v6.ip = Some(ip_v6);

        // Should return Some(true) for IPv6 source
        assert_eq!(desired_ipv6(&spec_v6), Some(true));
    }

    #[test]
    fn resolve_ip_addresses_prefers_link_local_source_for_link_local_destination() {
        let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let destination = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 10);
        let iface = interface_with_ipv6(&[global, link_local]);
        let mut spec = base_spec();
        spec.target.address = Some(TargetAddress::Ip(IpAddr::V6(destination)));

        let (source, destination_out) =
            resolve_ip_addresses(&spec, &iface).expect("resolve addresses");

        assert_eq!(source, IpAddr::V6(link_local));
        assert_eq!(destination_out, IpAddr::V6(destination));
    }

    #[test]
    fn resolve_ip_addresses_reports_explicit_source_reason() {
        let source = Ipv4Addr::new(192, 0, 2, 10);
        let destination = Ipv4Addr::new(198, 51, 100, 10);
        let iface = interface_with("v4", None, source);
        let mut spec = base_spec();
        spec.target.address = Some(TargetAddress::Ip(IpAddr::V4(destination)));
        spec.ip = Some(crate::engine::spec::IpSpec {
            source: Some(IpAddr::V4(source)),
            ..Default::default()
        });

        let selection =
            resolve_ip_addresses_with_selection(&spec, &iface).expect("resolve addresses");

        assert_eq!(selection.source_ip, IpAddr::V4(source));
        assert_eq!(
            selection.source_reason,
            SourceSelectionReason::ExplicitSourceIp
        );
        assert_eq!(selection.destination_ip, IpAddr::V4(destination));
        assert_eq!(
            selection.destination_reason,
            DestinationSelectionReason::TargetLiteral
        );
    }

    #[test]
    fn resolve_ip_addresses_reports_interface_source_reason() {
        let source = Ipv4Addr::new(192, 0, 2, 10);
        let destination = Ipv4Addr::new(198, 51, 100, 10);
        let iface = interface_with("v4", None, source);
        let mut spec = base_spec();
        spec.target.address = Some(TargetAddress::Ip(IpAddr::V4(destination)));

        let selection =
            resolve_ip_addresses_with_selection(&spec, &iface).expect("resolve addresses");

        assert_eq!(selection.source_ip, IpAddr::V4(source));
        assert_eq!(
            selection.source_reason,
            SourceSelectionReason::InterfaceAddress
        );
    }

    #[test]
    fn resolve_ip_addresses_reports_hostname_destination_reason() {
        let source = Ipv4Addr::new(127, 0, 0, 1);
        let iface = interface_with("lo", None, source);
        let mut spec = base_spec();
        spec.target.address = Some(TargetAddress::Host("localhost".to_string()));
        spec.ip = Some(crate::engine::spec::IpSpec {
            prefer_ipv6: Some(false),
            ..Default::default()
        });

        let selection =
            resolve_ip_addresses_with_selection(&spec, &iface).expect("resolve localhost");

        assert_eq!(
            selection.destination_reason,
            DestinationSelectionReason::HostnameResolution
        );
    }

    #[test]
    fn resolve_ip_addresses_reports_resolved_hostname_destination_reason() {
        let source = Ipv4Addr::new(192, 0, 2, 10);
        let destination = Ipv4Addr::new(198, 51, 100, 10);
        let iface = interface_with("v4", None, source);
        let mut spec = base_spec();
        spec.target = DestinationSpec::from_request(&DestinationRequest {
            destination: Some("example.test".to_string()),
            resolved_destination: Some(IpAddr::V4(destination)),
            ..Default::default()
        })
        .expect("destination spec");

        let selection =
            resolve_ip_addresses_with_selection(&spec, &iface).expect("resolve addresses");

        assert_eq!(selection.destination_ip, IpAddr::V4(destination));
        assert_eq!(
            selection.destination_reason,
            DestinationSelectionReason::HostnameResolution
        );
    }

    #[test]
    fn resolve_ip_addresses_reports_ipv6_scope_match_reason() {
        let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let destination = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 10);
        let iface = interface_with_ipv6(&[global, link_local]);
        let mut spec = base_spec();
        spec.target.address = Some(TargetAddress::Ip(IpAddr::V6(destination)));

        let selection =
            resolve_ip_addresses_with_selection(&spec, &iface).expect("resolve addresses");

        assert_eq!(selection.source_ip, IpAddr::V6(link_local));
        assert_eq!(
            selection.source_reason,
            SourceSelectionReason::Ipv6ScopeMatch
        );
    }

    #[test]
    fn resolve_ip_addresses_prefers_non_link_local_source_for_global_destination() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 10);
        let iface = interface_with_ipv6(&[Ipv6Addr::UNSPECIFIED, link_local, global]);
        let mut spec = base_spec();
        spec.target.address = Some(TargetAddress::Ip(IpAddr::V6(destination)));

        let (source, destination_out) =
            resolve_ip_addresses(&spec, &iface).expect("resolve addresses");

        assert_eq!(source, IpAddr::V6(global));
        assert_eq!(destination_out, IpAddr::V6(destination));
    }

    #[test]
    fn layer2_override_requires_mac_even_with_layer3_flag() {
        let mut spec = base_spec();
        spec.transmit.force_layer3 = true;
        spec.layer2.source = Some(MacAddr::new(0, 0, 0, 0, 0, 1));

        let result = select_interface_from_list(
            &spec,
            vec![interface_with(
                "no-mac",
                None,
                Ipv4Addr::new(192, 168, 0, 2),
            )],
        );

        assert!(
            result.is_err(),
            "expected layer2 overrides to require an interface with a MAC"
        );
    }
}
