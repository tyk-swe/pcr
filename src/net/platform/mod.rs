// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Crate-private native adapter boundary.
//!
//! This directory is the only location in the crate permitted to contain FFI
//! or narrowly reviewed unsafe code. Public traits and values live in `net`.

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
use std::net::IpAddr;

mod capture_dispatch;
mod interface_dispatch;
mod layer2_dispatch;
mod layer3_dispatch;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
mod live_capture;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(all(feature = "native-layer2", windows))]
mod npcap;
#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos")
))]
mod pcap_backend;
#[cfg(all(
    feature = "live",
    not(windows),
    not(all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ))
))]
mod pnet_enumeration;
#[cfg(all(
    feature = "native-layer3",
    any(target_os = "linux", target_os = "macos", windows)
))]
mod raw_ip;
mod route_dispatch;
#[cfg(windows)]
mod windows;

pub(in crate::net) use capture_dispatch::system_capture;
pub(in crate::net) use interface_dispatch::system_interfaces;
pub(in crate::net) use layer2_dispatch::system_send_layer2;
pub(in crate::net) use layer3_dispatch::system_send_layer3;
pub(in crate::net) use route_dispatch::{system_interface_route, system_route};

use super::Error as LiveIoError;
#[cfg(any(
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ),
    all(any(feature = "live", feature = "native-route"), windows)
))]
use super::interface::InterfaceInfo;
#[cfg(any(
    all(
        feature = "native-layer2",
        any(target_os = "linux", target_os = "macos", windows)
    ),
    all(
        feature = "native-layer3",
        any(target_os = "linux", target_os = "macos", windows)
    ),
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos", windows)
    )
))]
use super::route::InterfaceId;
use super::route::NativeRouteError;
#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
use super::route::RouteDecision;
#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
use super::route::{RouteSelectionReason, classify_destination};

#[cfg(any(
    not(all(
        feature = "native-layer2",
        any(target_os = "linux", target_os = "macos", windows)
    )),
    not(all(
        feature = "native-layer3",
        any(target_os = "linux", target_os = "macos", windows)
    )),
    all(
        feature = "native-route",
        not(any(target_os = "linux", target_os = "macos", windows)),
        not(feature = "live")
    )
))]
fn unsupported_live_io(message: &'static str) -> LiveIoError {
    LiveIoError::Unsupported {
        message: message.to_owned(),
    }
}

#[cfg(not(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
)))]
fn unsupported_native_route(message: &'static str) -> NativeRouteError {
    NativeRouteError::Unsupported {
        message: message.to_owned(),
    }
}

#[cfg(all(
    any(feature = "native-layer2", feature = "native-layer3"),
    any(target_os = "linux", target_os = "macos", windows)
))]
fn validate_current_interface_identity(expected: &InterfaceId) -> Result<(), LiveIoError> {
    let interfaces = system_interfaces()?;
    if interfaces
        .iter()
        .any(|interface| interface_identity_matches(&interface.id, expected))
    {
        return Ok(());
    }
    let actual = interfaces
        .iter()
        .find(|interface| interface.id.index == expected.index)
        .map(|interface| format!("{} (index {})", interface.id.name, interface.id.index))
        .unwrap_or_else(|| "no current interface".to_owned());
    Err(LiveIoError::Device {
        interface: expected.name.clone(),
        message: format!(
            "interface identity changed before native I/O: expected {} (index {}), found {actual}",
            expected.name, expected.index
        ),
    })
}

#[cfg(any(
    all(
        any(feature = "native-layer2", feature = "native-layer3"),
        any(target_os = "linux", target_os = "macos", windows)
    ),
    all(
        test,
        feature = "native-route",
        any(target_os = "linux", target_os = "macos", windows)
    )
))]
fn interface_identity_matches(actual: &InterfaceId, expected: &InterfaceId) -> bool {
    actual.index == expected.index && actual.name == expected.name
}

#[cfg(any(
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ),
    all(any(feature = "live", feature = "native-route"), windows)
))]
fn validate_native_interfaces(
    interfaces: Vec<InterfaceInfo>,
) -> Result<Vec<InterfaceInfo>, NativeRouteError> {
    let mut identities = std::collections::HashSet::with_capacity(interfaces.len());
    for interface in &interfaces {
        validate_native_interface(interface)?;
        if !identities.insert(&interface.id) {
            return Err(NativeRouteError::InvalidResponse {
                message: format!(
                    "operating system returned duplicate interface {} (index {})",
                    interface.id.name, interface.id.index
                ),
            });
        }
    }
    Ok(interfaces)
}

#[cfg(any(
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ),
    all(any(feature = "live", feature = "native-route"), windows)
))]
fn validate_native_interface(interface: &InterfaceInfo) -> Result<(), NativeRouteError> {
    if interface.id.name.is_empty() || interface.id.index == 0 {
        return Err(NativeRouteError::InvalidResponse {
            message: "operating system returned an incomplete interface identity".to_owned(),
        });
    }
    for assigned in &interface.addresses {
        let maximum = if assigned.address.is_ipv4() { 32 } else { 128 };
        if assigned.prefix_length > maximum {
            return Err(NativeRouteError::InvalidResponse {
                message: format!(
                    "interface {} returned invalid prefix length {} for {}",
                    interface.id.name, assigned.prefix_length, assigned.address
                ),
            });
        }
    }
    Ok(())
}

#[cfg(any(
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ),
    all(any(feature = "live", feature = "native-route"), windows)
))]
fn interface_error(error: NativeRouteError) -> LiveIoError {
    match error {
        NativeRouteError::Unsupported { message } => LiveIoError::Unsupported { message },
        error => LiveIoError::InterfaceDiscovery {
            message: error.to_string(),
        },
    }
}

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
fn validate_preferred_source_family(
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

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(super) struct NativeRouteSnapshot {
    pub interface: InterfaceInfo,
    pub selected_address: Option<IpAddr>,
    pub next_hop: Option<IpAddr>,
    pub route_mtu: Option<u32>,
    pub selection_reason: RouteSelectionReason,
}

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(super) fn finish_route(
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

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SourceAddressRank {
    prefix_match: bool,
    matched_prefix_length: u8,
    scope_match: bool,
}

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
fn fallback_source(
    addresses: &[super::interface::InterfaceAddress],
    destination: IpAddr,
) -> Option<IpAddr> {
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

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
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

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
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

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos")
))]
pub(super) fn find_interface(
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

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(super) fn interface_decision(
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
        destination_scope: super::route::DestinationScope::Unspecified,
        mtu,
        capability: interface.capability,
        link_type: interface.link_type,
    })
}

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
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

#[cfg(all(
    test,
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
mod tests {
    use super::*;
    use crate::capture::LinkType;
    use crate::net::{
        interface::{InterfaceAddress, InterfaceFlags},
        link::{LinkCapability, MacAddress},
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn interface() -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId {
                name: "mock0".to_owned(),
                index: 17,
            },
            description: Some("injected native snapshot".to_owned()),
            mac_address: Some(MacAddress([0x02, 0, 0, 0, 0, 17])),
            addresses: vec![
                InterfaceAddress {
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 17)),
                    prefix_length: 24,
                },
                InterfaceAddress {
                    address: IpAddr::V6("2001:db8::17".parse::<Ipv6Addr>().unwrap()),
                    prefix_length: 64,
                },
            ],
            flags: InterfaceFlags {
                up: true,
                broadcast: true,
                loopback: false,
                point_to_point: false,
                multicast: true,
            },
            mtu: Some(1_500),
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
        }
    }

    #[test]
    fn native_io_identity_requires_the_current_name_and_index_pair() {
        let actual = interface().id;
        assert!(interface_identity_matches(&actual, &actual));
        assert!(!interface_identity_matches(
            &actual,
            &InterfaceId {
                name: "renamed0".to_owned(),
                index: actual.index,
            }
        ));
        assert!(!interface_identity_matches(
            &actual,
            &InterfaceId {
                name: actual.name.clone(),
                index: actual.index + 1,
            }
        ));
    }

    fn snapshot() -> NativeRouteSnapshot {
        NativeRouteSnapshot {
            interface: interface(),
            selected_address: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 17))),
            next_hop: None,
            route_mtu: None,
            selection_reason: RouteSelectionReason::OnLink,
        }
    }

    #[test]
    fn native_snapshot_preserves_gateway_reason_and_low_route_mtu() {
        let gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let decision = finish_route(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            Some(&interface().id),
            None,
            NativeRouteSnapshot {
                next_hop: Some(gateway),
                route_mtu: Some(576),
                // The shared finish step derives Gateway from the concrete
                // next hop even if an adapter reports a generic route kind.
                selection_reason: RouteSelectionReason::OnLink,
                ..snapshot()
            },
        )
        .unwrap();

        assert_eq!(decision.next_hop, Some(gateway));
        assert_eq!(decision.selection_reason, RouteSelectionReason::Gateway);
        assert_eq!(decision.mtu, 576);
    }

    #[test]
    fn native_snapshot_honors_an_assigned_source_preference() {
        let preferred = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 17));
        let decision = finish_route(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            None,
            Some(preferred),
            snapshot(),
        )
        .unwrap();

        assert_eq!(decision.selected_address, Some(preferred));
        assert_eq!(decision.preferred_source, Some(preferred));
    }

    #[test]
    fn native_snapshot_fallback_prefers_the_destination_prefix_and_scope() {
        let selected = IpAddr::V6("fd50:1::2".parse::<Ipv6Addr>().unwrap());
        let mut interface = interface();
        interface.addresses = vec![
            InterfaceAddress {
                address: IpAddr::V6("fe80::2".parse::<Ipv6Addr>().unwrap()),
                prefix_length: 64,
            },
            InterfaceAddress {
                address: selected,
                prefix_length: 64,
            },
            InterfaceAddress {
                address: IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
                prefix_length: 64,
            },
        ];
        let decision = finish_route(
            IpAddr::V6("fd50:1::9".parse::<Ipv6Addr>().unwrap()),
            None,
            None,
            NativeRouteSnapshot {
                interface,
                selected_address: None,
                next_hop: None,
                route_mtu: None,
                selection_reason: RouteSelectionReason::OnLink,
            },
        )
        .unwrap();

        assert_eq!(decision.selected_address, Some(selected));
    }

    #[test]
    fn native_snapshot_rejects_source_family_and_assignment_mismatches() {
        let destination = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let wrong_family = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(
            finish_route(destination, None, Some(wrong_family), snapshot()).unwrap_err(),
            NativeRouteError::SourceFamilyMismatch {
                preferred_source: wrong_family,
                destination,
            }
        );

        let unavailable = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
        assert_eq!(
            finish_route(destination, None, Some(unavailable), snapshot()).unwrap_err(),
            NativeRouteError::SourceUnavailable {
                preferred_source: unavailable,
                interface: "mock0".to_owned(),
            }
        );
    }

    #[test]
    fn native_snapshot_rejects_interface_mismatch() {
        let requested = InterfaceId {
            name: "mock0".to_owned(),
            index: 99,
        };
        assert!(matches!(
            finish_route(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                Some(&requested),
                None,
                snapshot(),
            ),
            Err(NativeRouteError::InterfaceMismatch { .. })
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn find_interface_rejects_missing_interface() {
        assert_eq!(
            find_interface(
                vec![interface()],
                &InterfaceId {
                    name: "missing0".to_owned(),
                    index: 404,
                },
            )
            .unwrap_err(),
            NativeRouteError::InterfaceNotFound {
                name: "missing0".to_owned(),
                index: 404,
            }
        );
    }

    #[test]
    fn interface_only_decision_requires_a_nonzero_mtu() {
        let decision = interface_decision(interface()).unwrap();
        assert_eq!(
            decision.selection_reason,
            RouteSelectionReason::InterfaceOnly
        );
        assert_eq!(decision.mtu, 1_500);

        let mut missing_mtu = interface();
        missing_mtu.mtu = Some(0);
        assert!(matches!(
            interface_decision(missing_mtu),
            Err(NativeRouteError::InvalidResponse { .. })
        ));
    }

    #[test]
    fn native_interfaces_reject_invalid_identity_and_address_prefixes() {
        let mut invalid_identity = interface();
        invalid_identity.id.index = 0;
        assert!(matches!(
            interface_decision(invalid_identity),
            Err(NativeRouteError::InvalidResponse { .. })
        ));

        let mut invalid_prefix = interface();
        invalid_prefix.addresses[0].prefix_length = 33;
        assert!(matches!(
            finish_route(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                None,
                None,
                NativeRouteSnapshot {
                    interface: invalid_prefix,
                    selected_address: None,
                    next_hop: None,
                    route_mtu: None,
                    selection_reason: RouteSelectionReason::OnLink,
                },
            ),
            Err(NativeRouteError::InvalidResponse { .. })
        ));
    }
}
