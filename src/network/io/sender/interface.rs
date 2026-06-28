use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::IpNetwork;

use super::error::InterfaceError;
use crate::engine::spec::{PacketSpec, TargetAddress, TransportSpec};
use crate::network::interface;
use crate::util::net::resolve_target_ip;

type Result<T> = std::result::Result<T, InterfaceError>;

pub(crate) fn select_interface(spec: &PacketSpec) -> Result<NetworkInterface> {
    if let Some(name) = spec.target.interface.as_ref() {
        return interface::resolve_interface_by_name(name)
            .map_err(|source| InterfaceError::InterfaceLookup { source });
    }

    // Determine destination IP for routing query
    let destination_ip = spec.ip.as_ref().and_then(|ip| ip.destination).or_else(|| {
        spec.target.address.as_ref().and_then(|addr| match addr {
            TargetAddress::Ip(ip) => Some(*ip),
            TargetAddress::Host(host) => {
                // Resolve hostname to IP
                let prefer_ipv6 = desired_ipv6(spec);
                resolve_target_ip(host, prefer_ipv6).ok()
            }
        })
    });

    // Use routing table if destination IP is known
    if let Some(dest) = destination_ip {
        return interface::find_interface_for_destination(dest)
            .map_err(|source| InterfaceError::InterfaceLookup { source });
    }

    // Fallback to heuristic selection
    let interfaces = datalink::interfaces();
    select_interface_from_list(spec, interfaces)
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
    if let Some(TargetAddress::Ip(addr)) = spec.target.address.as_ref() {
        return Some(matches!(addr, IpAddr::V6(_)));
    }
    spec.ip.as_ref().and_then(|ip| ip.prefer_ipv6).or_else(|| {
        spec.ip
            .as_ref()
            .and_then(|ip| ip.source)
            .map(|ip| matches!(ip, IpAddr::V6(_)))
    })
}

pub(crate) fn resolve_ip_addresses(
    spec: &PacketSpec,
    interface: &NetworkInterface,
) -> Result<(IpAddr, IpAddr)> {
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

    let destination_ip = if let Some(ip) = ip_spec.and_then(|ip| ip.destination) {
        ip
    } else if let Some(address) = spec.target.address.as_ref() {
        match address {
            TargetAddress::Ip(ip) => *ip,
            TargetAddress::Host(host) => {
                resolve_target_ip(host, prefer_ipv6).map_err(|source| {
                    InterfaceError::HostnameResolution {
                        host: host.clone(),
                        source,
                    }
                })?
            }
        }
    } else {
        return Err(InterfaceError::DestinationRequired);
    };

    let source_ip = match ip_spec.and_then(|ip| ip.source) {
        Some(addr) => addr,
        None => match destination_ip {
            IpAddr::V4(_) => interface_ipv4(interface)
                .filter(|addr| !addr.is_unspecified())
                .map(IpAddr::V4)
                .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            IpAddr::V6(_) => interface_ipv6(interface)
                .filter(|addr| !addr.is_unspecified())
                .map(IpAddr::V6)
                .unwrap_or_else(|| IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        },
    };

    Ok((source_ip, destination_ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::spec::{
        DestinationSpec, Ipv6Spec, Layer2Spec, ListenerSpec, LoggingSpec, PayloadSource,
        PayloadSpec, TransmissionSpec,
    };
    use libc::IFF_UP;
    use pnet::datalink::MacAddr;
    use pnet::ipnetwork::IpNetwork;
    use std::net::{IpAddr, Ipv4Addr};

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
