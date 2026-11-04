// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};

use crate::interface::validation::validate_native_interface;
use crate::{
    interface::{self, Id as InterfaceId},
    route::{self, Decision, Scope, SelectionReason},
};

pub(crate) struct NativeRouteSnapshot {
    pub interface: interface::Info,
    pub local_addresses: Vec<IpAddr>,
    pub selected_source: Option<IpAddr>,
    pub next_hop: Option<IpAddr>,
    pub route_mtu: Option<u32>,
    pub selection_reason: SelectionReason,
}

pub(crate) fn finish_route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
    snapshot: NativeRouteSnapshot,
) -> Result<Decision, route::Error> {
    validate_native_interface(&snapshot.interface)?;
    if let Some(hint) = interface_hint {
        validate_interface_hint(hint, &snapshot.interface.id)?;
    }
    if snapshot
        .next_hop
        .is_some_and(|next_hop| next_hop.is_ipv4() != destination.is_ipv4())
    {
        return Err(route::Error::InvalidResponse {
            message: "next-hop family differs from destination family".to_owned(),
        });
    }
    let selected_source = preferred_source
        .or(snapshot.selected_source)
        .or_else(|| fallback_source(&snapshot.interface.addresses, destination))
        .ok_or_else(|| route::Error::InvalidResponse {
            message: format!(
                "interface {} has no source address for {destination}",
                snapshot.interface.id.name
            ),
        })?;
    if selected_source.is_ipv4() != destination.is_ipv4() {
        return Err(route::Error::InvalidResponse {
            message: "selected source family differs from destination family".to_owned(),
        });
    }
    let assigned_to_output = snapshot
        .interface
        .addresses
        .iter()
        .any(|assigned| assigned.address == selected_source);
    let assigned_locally = snapshot.selection_reason == SelectionReason::Local
        && snapshot.local_addresses.contains(&selected_source);
    if !assigned_to_output && !assigned_locally {
        return Err(if let Some(preferred_source) = preferred_source {
            route::Error::SourceUnavailable {
                preferred_source,
                interface: snapshot.interface.id.name.clone(),
            }
        } else {
            route::Error::InvalidResponse {
                message: format!(
                    "selected source {selected_source} is not assigned to interface {}",
                    snapshot.interface.id.name
                ),
            }
        });
    }
    let mtu = usable_mtu(&snapshot.interface, snapshot.route_mtu)?;
    let selection_reason = match snapshot.selection_reason {
        SelectionReason::Local | SelectionReason::InterfaceOnly => snapshot.selection_reason,
        SelectionReason::Broadcast if snapshot.next_hop.is_none() => SelectionReason::Broadcast,
        _ if snapshot.next_hop.is_some() => SelectionReason::Gateway,
        _ if is_interface_broadcast(destination, &snapshot.interface) => SelectionReason::Broadcast,
        _ => SelectionReason::OnLink,
    };

    Ok(Decision {
        interface: snapshot.interface.id,
        source_mac: snapshot.interface.mac_address,
        selected_source: Some(selected_source),
        preferred_source,
        next_hop: snapshot.next_hop,
        selection_reason,
        destination_scope: classify_destination(destination),
        mtu,
        capability: snapshot.interface.capability,
        link_type: snapshot.interface.link_type,
    })
}

fn is_interface_broadcast(destination: IpAddr, interface: &interface::Info) -> bool {
    let IpAddr::V4(destination) = destination else {
        return false;
    };
    if destination == std::net::Ipv4Addr::BROADCAST {
        return true;
    }
    interface.flags.broadcast
        && interface.addresses.iter().any(|assigned| {
            let IpAddr::V4(address) = assigned.address else {
                return false;
            };
            // /31 and /32 have no directed broadcast address.
            if assigned.prefix_length > 30 {
                return false;
            }
            let host_mask = u32::MAX >> assigned.prefix_length;
            Ipv4Addr::from(u32::from(address) | host_mask) == destination
        })
}

pub(crate) fn interface_decision(interface: interface::Info) -> Result<Decision, route::Error> {
    validate_native_interface(&interface)?;
    let mtu = usable_mtu(&interface, None)?;
    Ok(Decision {
        interface: interface.id,
        source_mac: interface.mac_address,
        selected_source: None,
        preferred_source: None,
        next_hop: None,
        selection_reason: SelectionReason::InterfaceOnly,
        destination_scope: Scope::Unspecified,
        mtu,
        capability: interface.capability,
        link_type: interface.link_type,
    })
}

fn usable_mtu(interface: &interface::Info, route_mtu: Option<u32>) -> Result<u32, route::Error> {
    [route_mtu, interface.mtu]
        .into_iter()
        .flatten()
        .filter(|mtu| *mtu != 0)
        .min()
        .ok_or_else(|| route::Error::InvalidResponse {
            message: format!("interface {} reported no usable MTU", interface.id.name),
        })
}

fn classify_destination(address: IpAddr) -> Scope {
    if address.is_unspecified() {
        return Scope::Unspecified;
    }
    if address.is_multicast() {
        return Scope::Multicast;
    }
    if address.is_loopback() {
        return Scope::Host;
    }
    match address {
        IpAddr::V4(address) if address.is_link_local() => Scope::Link,
        IpAddr::V6(address) if address.is_unicast_link_local() => Scope::Link,
        IpAddr::V4(address) if address.is_private() => Scope::Private,
        IpAddr::V6(address) if address.is_unique_local() => Scope::Private,
        _ => Scope::Global,
    }
}

fn validate_interface_hint(
    requested: &InterfaceId,
    actual: &InterfaceId,
) -> Result<(), route::Error> {
    if requested == actual {
        return Ok(());
    }
    Err(route::Error::InterfaceMismatch {
        requested: requested.name.clone(),
        requested_index: requested.index,
        actual: actual.name.clone(),
        actual_index: actual.index,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SourceAddressRank {
    scope_match: bool,
    prefix_match: bool,
    matched_prefix_length: u8,
}

fn fallback_source(addresses: &[interface::Address], destination: IpAddr) -> Option<IpAddr> {
    let destination_scope = address_scope(destination);
    addresses
        .iter()
        .filter(|assigned| {
            assigned.address.is_ipv4() == destination.is_ipv4()
                && !assigned.address.is_unspecified()
                && !assigned.address.is_multicast()
        })
        .map(|assigned| {
            let prefix_match =
                prefix_matches(assigned.address, destination, assigned.prefix_length);
            let rank = SourceAddressRank {
                scope_match: address_scope(assigned.address) == destination_scope,
                prefix_match,
                matched_prefix_length: if prefix_match {
                    assigned.prefix_length
                } else {
                    0
                },
            };
            (assigned.address, rank)
        })
        .reduce(|best, candidate| {
            if candidate.1 > best.1 {
                candidate
            } else {
                best
            }
        })
        .map(|(address, _)| address)
}

fn prefix_matches(source: IpAddr, destination: IpAddr, prefix_length: u8) -> bool {
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) if prefix_length <= 32 => {
            prefix_length == 0
                || (u32::from(source) >> (32 - prefix_length))
                    == (u32::from(destination) >> (32 - prefix_length))
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) if prefix_length <= 128 => {
            prefix_length == 0
                || (u128::from(source) >> (128 - prefix_length))
                    == (u128::from(destination) >> (128 - prefix_length))
        }
        _ => false,
    }
}

fn address_scope(address: IpAddr) -> Scope {
    match classify_destination(address) {
        Scope::Multicast | Scope::Unspecified => Scope::Global,
        scope => scope,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(ip: &str, prefix_length: u8) -> interface::Address {
        interface::Address {
            address: ip.parse().unwrap(),
            prefix_length,
        }
    }

    fn interface(mtu: Option<u32>) -> interface::Info {
        interface::Info {
            id: InterfaceId {
                name: "test0".to_owned(),
                index: 1,
            },
            description: None,
            mac_address: None,
            addresses: vec![address("192.0.2.1", 24)],
            flags: interface::Flags::default(),
            mtu,
            capability: crate::link::Capability::Layer3,
            link_type: packetcraftr_core::frame::LinkType::RAW,
        }
    }

    #[test]
    fn scope_precedes_prefix_specificity() {
        let destination = "8.8.8.8".parse().unwrap();
        let global = "9.1.1.1".parse().unwrap();
        let addresses = [
            interface::Address {
                address: "10.0.0.1".parse().unwrap(),
                prefix_length: 0,
            },
            interface::Address {
                address: global,
                prefix_length: 24,
            },
        ];
        assert_eq!(fallback_source(&addresses, destination), Some(global));
    }

    #[test]
    fn matching_prefix_specificity_precedes_address_order() {
        for (destination, broad, specific, nonmatching) in [
            (
                "10.0.1.10",
                address("10.0.0.1", 16),
                address("10.0.1.1", 24),
                address("10.0.2.1", 32),
            ),
            (
                "2001:db8:1::10",
                address("2001:db8::1", 32),
                address("2001:db8:1::1", 64),
                address("2001:db8:2::1", 128),
            ),
        ] {
            let destination = destination.parse().unwrap();
            for addresses in [
                [broad, specific, nonmatching],
                [nonmatching, specific, broad],
            ] {
                assert_eq!(
                    fallback_source(&addresses, destination),
                    Some(specific.address)
                );
            }
        }
    }

    #[test]
    fn equally_ranked_sources_keep_the_first_address() {
        for (destination, first, second) in [
            (
                "10.0.1.10",
                address("10.0.1.1", 24),
                address("10.0.1.2", 24),
            ),
            (
                "2001:db8::10",
                address("2001:db8::1", 64),
                address("2001:db8::2", 64),
            ),
        ] {
            let destination = destination.parse().unwrap();
            for addresses in [[first, second], [second, first]] {
                assert_eq!(
                    fallback_source(&addresses, destination),
                    Some(addresses[0].address)
                );
            }
        }
    }

    #[test]
    fn fallback_skips_unspecified_multicast_and_wrong_family_sources() {
        let destination = "192.0.2.10".parse().unwrap();
        let addresses = [
            address("0.0.0.0", 0),
            address("224.0.0.1", 0),
            address("2001:db8::1", 0),
            address("198.51.100.1", 24),
        ];
        assert_eq!(
            fallback_source(&addresses, destination),
            Some(addresses[3].address)
        );
        assert_eq!(fallback_source(&addresses[..3], destination), None);
    }

    #[test]
    fn route_mtu_uses_the_smallest_positive_route_or_interface_value() {
        for (route_mtu, interface_mtu, expected) in [
            (None, None, None),
            (Some(0), Some(0), None),
            (None, Some(0), None),
            (Some(0), None, None),
            (Some(1200), None, Some(1200)),
            (None, Some(1400), Some(1400)),
            (Some(0), Some(1400), Some(1400)),
            (Some(1200), Some(0), Some(1200)),
            (Some(1200), Some(1400), Some(1200)),
            (Some(1600), Some(1400), Some(1400)),
        ] {
            let result = finish_route(
                "192.0.2.10".parse().unwrap(),
                None,
                None,
                NativeRouteSnapshot {
                    interface: interface(interface_mtu),
                    local_addresses: Vec::new(),
                    selected_source: None,
                    next_hop: None,
                    route_mtu,
                    selection_reason: SelectionReason::OnLink,
                },
            );
            match expected {
                Some(mtu) => assert_eq!(result.unwrap().mtu, mtu),
                None => assert!(
                    matches!(result, Err(route::Error::InvalidResponse { message })
                    if message == "interface test0 reported no usable MTU")
                ),
            }
        }
    }

    #[test]
    fn interface_only_route_requires_a_positive_interface_mtu() {
        assert_eq!(interface_decision(interface(Some(1400))).unwrap().mtu, 1400);
        for mtu in [None, Some(0)] {
            assert!(matches!(interface_decision(interface(mtu)),
                Err(route::Error::InvalidResponse { message })
                    if message == "interface test0 reported no usable MTU"));
        }
    }

    #[test]
    fn interface_only_route_rejects_incomplete_identity() {
        for id in [
            InterfaceId {
                name: String::new(),
                index: 1,
            },
            InterfaceId {
                name: "test0".into(),
                index: 0,
            },
        ] {
            let info = interface::Info {
                id,
                ..interface(Some(1500))
            };
            assert!(
                matches!(interface_decision(info), Err(route::Error::InvalidResponse { message })
                if message == "operating system returned an incomplete interface identity")
            );
        }
    }
}
