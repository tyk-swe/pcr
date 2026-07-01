// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::IpNetwork;

use super::error::InterfaceError;
use super::types::{DestinationSelectionReason, InterfaceSelectionReason, SourceSelectionReason};
use crate::domain::spec::{PacketSpec, TargetAddress, TransportSpec};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::net::MacAddress;
    use crate::domain::request::{
        DestinationRequest, IpRequest, Layer2Request, PacketRequest, TransmissionRequest,
    };
    use pnet::datalink::MacAddr;

    fn interface(ips: &[&str]) -> NetworkInterface {
        NetworkInterface {
            name: "eth-test".to_string(),
            description: String::new(),
            index: 1,
            mac: Some(MacAddr::new(0x02, 0, 0, 0, 0, 1)),
            ips: ips.iter().map(|value| value.parse().unwrap()).collect(),
            flags: 0,
        }
    }

    #[test]
    fn interface_ip_helpers_extract_first_address_for_each_family() {
        let interface = interface(&["192.0.2.5/24", "2001:db8::5/64"]);

        assert_eq!(
            interface_ipv4(&interface),
            Some(Ipv4Addr::new(192, 0, 2, 5))
        );
        assert_eq!(
            interface_ipv6(&interface),
            Some("2001:db8::5".parse().unwrap())
        );
    }

    #[test]
    fn desired_ipv6_prefers_explicit_destination_family() {
        let spec = PacketSpec::from_request(&PacketRequest {
            ip: IpRequest {
                destination_ip: Some("2001:db8::10".to_string()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();

        assert_eq!(desired_ipv6(&spec), Some(true));
    }

    #[test]
    fn desired_ipv6_uses_resolved_target_address() {
        let spec = PacketSpec::from_request(&PacketRequest {
            destination: DestinationRequest {
                destination: Some("example.test".to_string()),
                resolved_destination: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();

        assert_eq!(desired_ipv6(&spec), Some(false));
    }

    #[test]
    fn desired_ipv6_uses_source_address_when_destination_is_unknown() {
        let spec = PacketSpec::from_request(&PacketRequest {
            ip: IpRequest {
                source_ip: Some("2001:db8::5".to_string()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();

        assert_eq!(desired_ipv6(&spec), Some(true));
    }

    #[test]
    fn interface_requires_mac_for_layer2_transmission_or_layer2_overrides() {
        let default_spec = PacketSpec::default();
        let layer3_spec = PacketSpec::from_request(&PacketRequest {
            transmit: TransmissionRequest {
                force_layer3: Some(true),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        let mut layer2_override = layer3_spec.clone();
        layer2_override.layer2.destination = Some(MacAddress::new([1, 2, 3, 4, 5, 6]));

        assert!(interface_requires_mac(&default_spec));
        assert!(!interface_requires_mac(&layer3_spec));
        assert!(interface_requires_mac(&layer2_override));
    }

    #[test]
    fn layer2_request_fixture_can_express_mac_override_without_hostname_resolution() {
        let spec = PacketSpec::from_request(&PacketRequest {
            layer2: Layer2Request {
                destination_mac: Some("01:02:03:04:05:06".to_string()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();

        assert_eq!(
            spec.layer2.destination.map(|mac| mac.to_string()),
            Some("01:02:03:04:05:06".to_string())
        );
    }

    #[test]
    fn resolve_ip_addresses_prefers_explicit_source_and_destination() {
        let spec = PacketSpec::from_request(&PacketRequest {
            ip: IpRequest {
                source_ip: Some("192.0.2.9".to_string()),
                destination_ip: Some("198.51.100.10".to_string()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();

        let selected =
            resolve_ip_addresses_with_selection(&spec, &interface(&["192.0.2.5/24"])).unwrap();

        assert_eq!(selected.source_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
        assert_eq!(
            selected.source_reason,
            SourceSelectionReason::ExplicitSourceIp
        );
        assert_eq!(
            selected.destination_ip,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))
        );
        assert_eq!(
            selected.destination_reason,
            DestinationSelectionReason::TargetLiteral
        );
    }

    #[test]
    fn resolve_ip_addresses_marks_resolved_host_and_interface_source() {
        let spec = PacketSpec::from_request(&PacketRequest {
            destination: DestinationRequest {
                destination: Some("example.test".to_string()),
                resolved_destination: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();

        let selected =
            resolve_ip_addresses_with_selection(&spec, &interface(&["192.0.2.5/24"])).unwrap();

        assert_eq!(selected.source_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)));
        assert_eq!(
            selected.source_reason,
            SourceSelectionReason::InterfaceAddress
        );
        assert_eq!(
            selected.destination_reason,
            DestinationSelectionReason::HostnameResolution
        );
    }

    #[test]
    fn resolve_ip_addresses_uses_ipv6_scope_match_for_source() {
        let spec = PacketSpec::from_request(&PacketRequest {
            destination: DestinationRequest {
                destination_ip: Some("fe80::abcd".to_string()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();

        let selected = resolve_ip_addresses_with_selection(
            &spec,
            &interface(&["2001:db8::5/64", "fe80::5/64"]),
        )
        .unwrap();

        assert_eq!(selected.source_ip, IpAddr::V6("fe80::5".parse().unwrap()));
        assert_eq!(
            selected.source_reason,
            SourceSelectionReason::Ipv6ScopeMatch
        );
    }

    #[test]
    fn resolve_ip_addresses_requires_destination() {
        let err = match resolve_ip_addresses_with_selection(&PacketSpec::default(), &interface(&[]))
        {
            Ok(_) => panic!("expected destination-required error"),
            Err(err) => err,
        };

        assert!(matches!(err, InterfaceError::DestinationRequired));
    }
}
