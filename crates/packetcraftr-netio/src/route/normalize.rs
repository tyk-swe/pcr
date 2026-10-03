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
    let route_mtu = snapshot.route_mtu.filter(|mtu| *mtu != 0);
    let interface_mtu = snapshot.interface.mtu.filter(|mtu| *mtu != 0);
    let mtu = match (route_mtu, interface_mtu) {
        (Some(route), Some(interface)) => route.min(interface),
        (Some(mtu), None) | (None, Some(mtu)) => mtu,
        (None, None) => {
            return Err(route::Error::InvalidResponse {
                message: format!(
                    "interface {} reported no usable MTU",
                    snapshot.interface.id.name
                ),
            });
        }
    };
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
    let mtu =
        interface
            .mtu
            .filter(|mtu| *mtu != 0)
            .ok_or_else(|| route::Error::InvalidResponse {
                message: format!("interface {} reported no usable MTU", interface.id.name),
            })?;
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
    prefix_match: bool,
    matched_prefix_length: u8,
    scope_match: bool,
}

fn fallback_source(addresses: &[interface::Address], destination: IpAddr) -> Option<IpAddr> {
    let mut best: Option<(IpAddr, SourceAddressRank)> = None;
    for assigned in addresses {
        let address = assigned.address;
        if address.is_ipv4() != destination.is_ipv4()
            || address.is_unspecified()
            || address.is_multicast()
        {
            continue;
        }
        let prefix_match = prefix_matches(address, destination, assigned.prefix_length);
        let rank = SourceAddressRank {
            prefix_match,
            matched_prefix_length: if prefix_match {
                assigned.prefix_length
            } else {
                0
            },
            scope_match: address_scope(address) == address_scope(destination),
        };
        if best.as_ref().is_none_or(|(_, current)| rank > *current) {
            best = Some((address, rank));
        }
    }
    best.map(|(address, _)| address)
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
    use std::net::Ipv6Addr;

    use packetcraftr_core::packet::MacAddress;

    use super::*;
    use crate::{
        interface::{self, Id as InterfaceId},
        test_support::{assigned, interface_info, v4},
    };

    fn interface() -> interface::Info {
        interface::Info {
            description: Some("fixture interface".to_owned()),
            mac_address: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
            addresses: vec![
                assigned(v4(10, 0, 0, 2), 8),
                assigned(v4(10, 2, 3, 4), 24),
                assigned(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
            ],
            flags: interface::Flags {
                up: true,
                multicast: true,
                ..interface::Flags::default()
            },
            ..interface_info("fixture0", 7)
        }
    }

    fn snapshot() -> NativeRouteSnapshot {
        let interface = interface();
        NativeRouteSnapshot {
            local_addresses: interface
                .addresses
                .iter()
                .map(|assigned| assigned.address)
                .collect(),
            interface,
            selected_source: None,
            next_hop: Some(v4(10, 2, 3, 1)),
            route_mtu: Some(1_400),
            selection_reason: SelectionReason::OnLink,
        }
    }

    #[test]
    fn finish_route_rejects_a_local_source_not_owned_by_any_interface() {
        let local_address = v4(192, 0, 2, 8);
        let mut local = snapshot();
        local.selected_source = Some(local_address);
        local.next_hop = None;
        local.selection_reason = SelectionReason::Local;

        assert!(matches!(
            finish_route(local_address, None, None, local),
            Err(route::Error::InvalidResponse { .. })
        ));
    }

    #[test]
    fn finish_route_rejects_inconsistent_native_snapshot_fields() {
        let destination = v4(10, 2, 3, 99);
        let wrong_interface = InterfaceId {
            name: "other0".to_owned(),
            index: 8,
        };
        assert!(matches!(
            finish_route(destination, Some(&wrong_interface), None, snapshot()),
            Err(route::Error::InterfaceMismatch { .. })
        ));

        let mut invalid = snapshot();
        invalid.next_hop = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert!(matches!(
            finish_route(destination, None, None, invalid),
            Err(route::Error::InvalidResponse { .. })
        ));

        let mut invalid = snapshot();
        invalid.selected_source = Some(v4(192, 0, 2, 8));
        assert!(matches!(
            finish_route(destination, None, None, invalid),
            Err(route::Error::InvalidResponse { .. })
        ));
        assert!(matches!(
            finish_route(destination, None, Some(v4(192, 0, 2, 8)), snapshot()),
            Err(route::Error::SourceUnavailable { .. })
        ));

        let mut invalid = snapshot();
        invalid.route_mtu = Some(0);
        invalid.interface.mtu = None;
        assert!(matches!(
            finish_route(destination, None, None, invalid),
            Err(route::Error::InvalidResponse { .. })
        ));
    }
}
