// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pure policy for validating and normalizing native route snapshots.

use std::net::IpAddr;

use crate::interface::{InterfaceAddress, InterfaceInfo};

use super::{
    DestinationScope, InterfaceId, NativeRouteError, RouteDecision, RouteSelectionReason,
    validate_native_interface,
};

pub(crate) struct NativeRouteSnapshot {
    pub interface: InterfaceInfo,
    pub selected_address: Option<IpAddr>,
    pub next_hop: Option<IpAddr>,
    pub route_mtu: Option<u32>,
    pub selection_reason: RouteSelectionReason,
}

pub(crate) fn finish_route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
    snapshot: NativeRouteSnapshot,
) -> Result<RouteDecision, NativeRouteError> {
    validate_native_interface(&snapshot.interface)?;
    if let Some(hint) = interface_hint {
        validate_interface_hint(hint, &snapshot.interface.id)?;
    }
    validate_preferred_source_family(destination, preferred_source)?;
    if let Some(source) = preferred_source
        && !snapshot
            .interface
            .addresses
            .iter()
            .any(|assigned| assigned.address == source)
    {
        return Err(NativeRouteError::SourceUnavailable {
            preferred_source: source,
            interface: snapshot.interface.id.name.clone(),
        });
    }

    if snapshot
        .next_hop
        .is_some_and(|next_hop| next_hop.is_ipv4() != destination.is_ipv4())
    {
        return Err(NativeRouteError::InvalidResponse {
            message: "next-hop family differs from destination family".to_owned(),
        });
    }
    let selected_address = preferred_source
        .or(snapshot.selected_address)
        .or_else(|| fallback_source(&snapshot.interface.addresses, destination))
        .ok_or_else(|| NativeRouteError::InvalidResponse {
            message: format!(
                "interface {} has no source address for {destination}",
                snapshot.interface.id.name
            ),
        })?;
    if selected_address.is_ipv4() != destination.is_ipv4() {
        return Err(NativeRouteError::InvalidResponse {
            message: "selected source family differs from destination family".to_owned(),
        });
    }
    let mtu = snapshot
        .route_mtu
        .filter(|mtu| *mtu != 0)
        .or(snapshot.interface.mtu.filter(|mtu| *mtu != 0))
        .ok_or_else(|| NativeRouteError::InvalidResponse {
            message: format!(
                "interface {} reported no usable MTU",
                snapshot.interface.id.name
            ),
        })?;
    let selection_reason = match snapshot.selection_reason {
        RouteSelectionReason::Local | RouteSelectionReason::InterfaceOnly => {
            snapshot.selection_reason
        }
        _ if snapshot.next_hop.is_some() => RouteSelectionReason::Gateway,
        _ => RouteSelectionReason::OnLink,
    };

    Ok(RouteDecision {
        interface: snapshot.interface.id,
        source_mac: snapshot.interface.mac_address,
        selected_address: Some(selected_address),
        preferred_source,
        next_hop: snapshot.next_hop,
        selection_reason,
        destination_scope: classify_destination(destination),
        mtu,
        capability: snapshot.interface.capability,
        link_type: snapshot.interface.link_type,
    })
}

pub(crate) fn interface_decision(
    interface: InterfaceInfo,
) -> Result<RouteDecision, NativeRouteError> {
    validate_native_interface(&interface)?;
    let mtu =
        interface
            .mtu
            .filter(|mtu| *mtu != 0)
            .ok_or_else(|| NativeRouteError::InvalidResponse {
                message: format!("interface {} reported no usable MTU", interface.id.name),
            })?;
    Ok(RouteDecision {
        interface: interface.id,
        source_mac: interface.mac_address,
        selected_address: None,
        preferred_source: None,
        next_hop: None,
        selection_reason: RouteSelectionReason::InterfaceOnly,
        destination_scope: DestinationScope::Unspecified,
        mtu,
        capability: interface.capability,
        link_type: interface.link_type,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn find_interface(
    interfaces: Vec<InterfaceInfo>,
    requested: &InterfaceId,
) -> Result<InterfaceInfo, NativeRouteError> {
    if let Some(interface) = interfaces
        .iter()
        .find(|interface| interface.id == *requested)
    {
        return Ok(interface.clone());
    }
    if let Some(actual) = interfaces.iter().find(|interface| {
        interface.id.name == requested.name || interface.id.index == requested.index
    }) {
        return Err(NativeRouteError::InterfaceMismatch {
            requested: requested.name.clone(),
            requested_index: requested.index,
            actual: actual.id.name.clone(),
            actual_index: actual.id.index,
        });
    }
    Err(NativeRouteError::InterfaceNotFound {
        name: requested.name.clone(),
        index: requested.index,
    })
}

pub(crate) fn classify_destination(address: IpAddr) -> DestinationScope {
    if address.is_unspecified() {
        return DestinationScope::Unspecified;
    }
    if address.is_multicast() {
        return DestinationScope::Multicast;
    }
    if address.is_loopback() {
        return DestinationScope::Host;
    }
    match address {
        IpAddr::V4(address) if address.is_link_local() => DestinationScope::Link,
        IpAddr::V6(address) if address.is_unicast_link_local() => DestinationScope::Link,
        IpAddr::V4(address) if address.is_private() => DestinationScope::Private,
        IpAddr::V6(address) if address.is_unique_local() => DestinationScope::Private,
        _ => DestinationScope::Global,
    }
}

pub(crate) fn validate_preferred_source_family(
    destination: IpAddr,
    preferred_source: Option<IpAddr>,
) -> Result<(), NativeRouteError> {
    if let Some(source) = preferred_source
        && source.is_ipv4() != destination.is_ipv4()
    {
        return Err(NativeRouteError::SourceFamilyMismatch {
            preferred_source: source,
            destination,
        });
    }
    Ok(())
}

fn validate_interface_hint(
    requested: &InterfaceId,
    actual: &InterfaceId,
) -> Result<(), NativeRouteError> {
    if requested == actual {
        return Ok(());
    }
    Err(NativeRouteError::InterfaceMismatch {
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

fn fallback_source(addresses: &[InterfaceAddress], destination: IpAddr) -> Option<IpAddr> {
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
