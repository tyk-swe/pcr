// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Validates and normalizes an operating-system route snapshot into a
//! [`Decision`]. Shared by every native route backend; no FFI lives here.

use std::net::{IpAddr, Ipv4Addr};

use super::interface_validation::validate_native_interface;
use crate::{
    interface::{self, Id as InterfaceId},
    route::{Decision, Scope, SelectionReason, SystemError},
};

pub(crate) struct NativeRouteSnapshot {
    pub interface: interface::Info,
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
) -> Result<Decision, SystemError> {
    validate_native_interface(&snapshot.interface)?;
    if let Some(hint) = interface_hint {
        validate_interface_hint(hint, &snapshot.interface.id)?;
    }
    validate_preferred_source_family(destination, preferred_source)?;
    if snapshot
        .next_hop
        .is_some_and(|next_hop| next_hop.is_ipv4() != destination.is_ipv4())
    {
        return Err(SystemError::InvalidResponse {
            message: "next-hop family differs from destination family".to_owned(),
        });
    }
    let selected_source = preferred_source
        .or(snapshot.selected_source)
        .or_else(|| fallback_source(&snapshot.interface.addresses, destination))
        .ok_or_else(|| SystemError::InvalidResponse {
            message: format!(
                "interface {} has no source address for {destination}",
                snapshot.interface.id.name
            ),
        })?;
    if selected_source.is_ipv4() != destination.is_ipv4() {
        return Err(SystemError::InvalidResponse {
            message: "selected source family differs from destination family".to_owned(),
        });
    }
    if !snapshot
        .interface
        .addresses
        .iter()
        .any(|assigned| assigned.address == selected_source)
    {
        return Err(if let Some(preferred_source) = preferred_source {
            SystemError::SourceUnavailable {
                preferred_source,
                interface: snapshot.interface.id.name.clone(),
            }
        } else {
            SystemError::InvalidResponse {
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
            return Err(SystemError::InvalidResponse {
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

#[expect(
    clippy::arithmetic_side_effects,
    reason = "prefix_length above 30 is rejected above, so host bits stay within u32::BITS"
)]
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
            if assigned.prefix_length > 30 {
                return false;
            }
            let host_bits = u32::BITS - u32::from(assigned.prefix_length);
            let host_mask = u32::MAX >> (u32::BITS - host_bits);
            Ipv4Addr::from(u32::from(address) | host_mask) == destination
        })
}

pub(crate) fn interface_decision(interface: interface::Info) -> Result<Decision, SystemError> {
    validate_native_interface(&interface)?;
    let mtu =
        interface
            .mtu
            .filter(|mtu| *mtu != 0)
            .ok_or_else(|| SystemError::InvalidResponse {
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn find_interface(
    interfaces: &[interface::Info],
    requested: &InterfaceId,
) -> Result<interface::Info, SystemError> {
    if let Some(interface) = interfaces
        .iter()
        .find(|interface| interface.id == *requested)
    {
        return Ok(interface.clone());
    }
    if let Some(actual) = interfaces.iter().find(|interface| {
        interface.id.name == requested.name || interface.id.index == requested.index
    }) {
        return Err(SystemError::InterfaceMismatch {
            requested: requested.name.clone(),
            requested_index: requested.index,
            actual: actual.id.name.clone(),
            actual_index: actual.id.index,
        });
    }
    Err(SystemError::InterfaceNotFound {
        name: requested.name.clone(),
        index: requested.index,
    })
}

pub(crate) fn classify_destination(address: IpAddr) -> Scope {
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

/// An interface a native route query may be pinned to.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) trait InterfaceCandidate: Clone {
    fn interface(&self) -> &interface::Info;
    /// Whether both candidates name the same operating-system interface.
    fn is_same(&self, other: &Self) -> bool;
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl InterfaceCandidate for interface::Info {
    fn interface(&self) -> &interface::Info {
        self
    }

    fn is_same(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

/// Pins the query to the interface owning `preferred_source`, refusing a
/// `requested` interface that does not own it. Without a preferred source the
/// request passes through unchanged.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn constrain_by_preferred_source<T: InterfaceCandidate>(
    available: &[T],
    interface_hint: Option<&InterfaceId>,
    requested: Option<T>,
    preferred_source: Option<IpAddr>,
) -> Result<Option<T>, SystemError> {
    let Some(source) = preferred_source else {
        return Ok(requested);
    };
    let source_interface = available
        .iter()
        .find(|candidate| {
            candidate
                .interface()
                .addresses
                .iter()
                .any(|assigned| assigned.address == source)
        })
        .cloned()
        .ok_or_else(|| SystemError::SourceUnavailable {
            preferred_source: source,
            interface: interface_hint
                .map_or_else(|| "any interface".to_owned(), |hint| hint.name.clone()),
        })?;
    match requested {
        Some(requested) if !requested.is_same(&source_interface) => {
            Err(SystemError::SourceUnavailable {
                preferred_source: source,
                interface: requested.interface().id.name.clone(),
            })
        }
        Some(requested) => Ok(Some(requested)),
        None => Ok(Some(source_interface)),
    }
}

pub(crate) fn validate_preferred_source_family(
    destination: IpAddr,
    preferred_source: Option<IpAddr>,
) -> Result<(), SystemError> {
    if let Some(source) = preferred_source
        && source.is_ipv4() != destination.is_ipv4()
    {
        return Err(SystemError::SourceFamilyMismatch {
            preferred_source: source,
            destination,
        });
    }
    Ok(())
}

fn validate_interface_hint(
    requested: &InterfaceId,
    actual: &InterfaceId,
) -> Result<(), SystemError> {
    if requested == actual {
        return Ok(());
    }
    Err(SystemError::InterfaceMismatch {
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

#[expect(
    clippy::arithmetic_side_effects,
    reason = "the match guards bound prefix_length to 32 and 128, so neither subtraction underflows"
)]
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

fn address_scope(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(address) if address.is_loopback() => 1,
        IpAddr::V6(address) if address.is_loopback() => 1,
        IpAddr::V4(address) if address.is_link_local() => 2,
        IpAddr::V6(address) if address.is_unicast_link_local() => 2,
        IpAddr::V4(address) if address.is_private() => 3,
        IpAddr::V6(address) if address.is_unique_local() => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use std::net::{Ipv4Addr, Ipv6Addr};

    use packetcraftr_core::frame::LinkType;

    use super::*;
    use crate::{
        interface::{self, Id as InterfaceId},
        link::{Capability, MacAddress},
    };

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn interface() -> interface::Info {
        interface::Info {
            id: InterfaceId {
                name: "fixture0".to_owned(),
                index: 7,
            },
            description: Some("fixture interface".to_owned()),
            mac_address: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
            addresses: vec![
                interface::Address {
                    address: v4(10, 0, 0, 2),
                    prefix_length: 8,
                },
                interface::Address {
                    address: v4(10, 2, 3, 4),
                    prefix_length: 24,
                },
                interface::Address {
                    address: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    prefix_length: 128,
                },
            ],
            flags: interface::Flags {
                up: true,
                multicast: true,
                ..interface::Flags::default()
            },
            mtu: Some(1_500),
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        }
    }

    fn snapshot() -> NativeRouteSnapshot {
        NativeRouteSnapshot {
            interface: interface(),
            selected_source: None,
            next_hop: Some(v4(10, 2, 3, 1)),
            route_mtu: Some(1_400),
            selection_reason: SelectionReason::OnLink,
        }
    }

    #[test]
    fn destination_scope_classification_covers_both_address_families() {
        let cases = [
            (v4(0, 0, 0, 0), Scope::Unspecified),
            (IpAddr::V6(Ipv6Addr::UNSPECIFIED), Scope::Unspecified),
            (v4(224, 0, 0, 1), Scope::Multicast),
            (
                "ff02::1".parse::<IpAddr>().expect("IPv6 multicast"),
                Scope::Multicast,
            ),
            (v4(127, 0, 0, 1), Scope::Host),
            (IpAddr::V6(Ipv6Addr::LOCALHOST), Scope::Host),
            (v4(169, 254, 1, 2), Scope::Link),
            (
                "fe80::1".parse::<IpAddr>().expect("IPv6 link local"),
                Scope::Link,
            ),
            (v4(10, 0, 0, 1), Scope::Private),
            (
                "fd00::1".parse::<IpAddr>().expect("IPv6 unique local"),
                Scope::Private,
            ),
            (v4(198, 51, 100, 1), Scope::Global),
            (
                "2001:db8::1".parse::<IpAddr>().expect("IPv6 global"),
                Scope::Global,
            ),
        ];

        for (address, expected) in cases {
            assert_eq!(classify_destination(address), expected, "{address}");
        }
    }

    #[test]
    fn finish_route_selects_the_longest_matching_source_and_normalizes_snapshot() {
        let destination = v4(10, 2, 3, 99);

        let decision = finish_route(destination, None, None, snapshot()).expect("valid snapshot");

        assert_eq!(decision.selected_source, Some(v4(10, 2, 3, 4)));
        assert_eq!(decision.next_hop, Some(v4(10, 2, 3, 1)));
        assert_eq!(decision.selection_reason, SelectionReason::Gateway);
        assert_eq!(decision.destination_scope, Scope::Private);
        assert_eq!(decision.mtu, 1_400);
        assert_eq!(decision.interface, interface().id);
    }

    #[test]
    fn finish_route_preserves_and_infers_ipv4_broadcast_routes_without_overriding_gateways() {
        let destination = v4(10, 2, 3, 255);

        let mut native_broadcast = snapshot();
        native_broadcast.next_hop = None;
        native_broadcast.selection_reason = SelectionReason::Broadcast;
        let preserved = finish_route(destination, None, None, native_broadcast)
            .expect("native broadcast route is valid");
        assert_eq!(preserved.selection_reason, SelectionReason::Broadcast);

        let mut inferred_broadcast = snapshot();
        inferred_broadcast.next_hop = None;
        inferred_broadcast.interface.flags.broadcast = true;
        let inferred = finish_route(destination, None, None, inferred_broadcast)
            .expect("interface-prefix broadcast is valid");
        assert_eq!(inferred.selection_reason, SelectionReason::Broadcast);

        let mut gateway = snapshot();
        gateway.selection_reason = SelectionReason::Broadcast;
        let gateway =
            finish_route(destination, None, None, gateway).expect("gateway route remains valid");
        assert_eq!(gateway.selection_reason, SelectionReason::Gateway);
        assert!(gateway.next_hop.is_some());
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
            Err(SystemError::InterfaceMismatch { .. })
        ));
        assert!(matches!(
            finish_route(
                destination,
                None,
                Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                snapshot()
            ),
            Err(SystemError::SourceFamilyMismatch { .. })
        ));

        let mut invalid = snapshot();
        invalid.next_hop = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert!(matches!(
            finish_route(destination, None, None, invalid),
            Err(SystemError::InvalidResponse { .. })
        ));

        let mut invalid = snapshot();
        invalid.selected_source = Some(v4(192, 0, 2, 8));
        assert!(matches!(
            finish_route(destination, None, None, invalid),
            Err(SystemError::InvalidResponse { .. })
        ));
        assert!(matches!(
            finish_route(destination, None, Some(v4(192, 0, 2, 8)), snapshot()),
            Err(SystemError::SourceUnavailable { .. })
        ));

        let mut invalid = snapshot();
        invalid.route_mtu = Some(0);
        invalid.interface.mtu = None;
        assert!(matches!(
            finish_route(destination, None, None, invalid),
            Err(SystemError::InvalidResponse { .. })
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn interface_lookup_requires_the_complete_stable_identity() {
        let available = interface();
        assert_eq!(
            find_interface(std::slice::from_ref(&available), &available.id)
                .expect("exact identity"),
            available
        );

        for requested in [
            InterfaceId {
                name: "fixture0".to_owned(),
                index: 8,
            },
            InterfaceId {
                name: "other0".to_owned(),
                index: 7,
            },
        ] {
            assert!(matches!(
                find_interface(std::slice::from_ref(&available), &requested),
                Err(SystemError::InterfaceMismatch { .. })
            ));
        }
        assert!(matches!(
            find_interface(
                std::slice::from_ref(&available),
                &InterfaceId {
                    name: "missing0".to_owned(),
                    index: 99,
                }
            ),
            Err(SystemError::InterfaceNotFound { .. })
        ));
    }

    #[test]
    fn interface_decision_is_destination_free_and_requires_a_nonzero_mtu() {
        let decision = interface_decision(interface()).expect("valid interface snapshot");
        assert_eq!(decision.selected_source, None);
        assert_eq!(decision.next_hop, None);
        assert_eq!(decision.selection_reason, SelectionReason::InterfaceOnly);
        assert_eq!(decision.destination_scope, Scope::Unspecified);

        let mut invalid = interface();
        invalid.mtu = Some(0);
        assert!(matches!(
            interface_decision(invalid),
            Err(SystemError::InvalidResponse { .. })
        ));
    }
}
