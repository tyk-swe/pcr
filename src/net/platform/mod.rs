// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Crate-private native adapter boundary.
//!
//! This directory is the only location in the crate permitted to contain FFI
//! or narrowly reviewed unsafe code. Public traits and values live in `net`.

#![allow(unsafe_code)]

use std::net::IpAddr;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(feature = "native-layer2")]
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
#[cfg(all(feature = "live", not(feature = "native-route"), not(windows)))]
mod pnet_enumeration;
#[cfg(all(
    feature = "native-layer3",
    any(target_os = "linux", target_os = "macos", windows)
))]
mod raw_ip;
#[cfg(windows)]
mod windows;

use super::provider_impl::{InterfaceInfo, LiveIoError};
#[cfg(feature = "native-route")]
use super::route_impl::{classify_destination, RouteSelectionReason};
use super::route_impl::{InterfaceId, NativeRouteError, RouteDecision};

#[cfg(feature = "native-layer2")]
pub(super) fn system_capture(
    route: &super::route_impl::PlannedRoute,
    limits: super::provider_impl::CaptureQueueLimits,
) -> Result<Box<dyn super::provider_impl::CaptureSession>, LiveIoError> {
    // Reject invalid bounds before opening a device or allocating native
    // resources. NativeCaptureSession validates again at its ownership seam.
    let limits = limits.validate()?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let parts = pcap_backend::open_capture(&route.route.interface, limits)?;
    #[cfg(windows)]
    let parts = npcap::open_capture(&route.route.interface, limits)?;
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    return Err(LiveIoError::Unsupported {
        message: "native Layer 2 capture is unsupported on this target".to_owned(),
    });

    Ok(Box::new(live_capture::NativeCaptureSession::spawn(
        parts, limits,
    )?))
}

#[cfg(not(feature = "native-layer2"))]
pub(super) fn system_capture(
    _route: &super::route_impl::PlannedRoute,
    _limits: super::provider_impl::CaptureQueueLimits,
) -> Result<Box<dyn super::provider_impl::CaptureSession>, LiveIoError> {
    Err(LiveIoError::Unsupported {
        message: "enable the native-layer2 feature for native packet capture".to_owned(),
    })
}

#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos")
))]
pub(super) fn system_send_layer2(
    frame: super::provider_impl::Layer2Frame<'_>,
) -> Result<super::provider_impl::IoSendReport, LiveIoError> {
    pcap_backend::send_layer2(frame)
}

#[cfg(all(
    feature = "native-layer3",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(super) fn system_send_layer3(
    frame: super::provider_impl::Layer3Frame<'_>,
) -> Result<super::provider_impl::IoSendReport, LiveIoError> {
    raw_ip::send_layer3(frame)
}

#[cfg(not(all(
    feature = "native-layer3",
    any(target_os = "linux", target_os = "macos", windows)
)))]
pub(super) fn system_send_layer3(
    _frame: super::provider_impl::Layer3Frame<'_>,
) -> Result<super::provider_impl::IoSendReport, LiveIoError> {
    Err(LiveIoError::Unsupported {
        message:
            "enable the native-layer3 feature on Linux, macOS, or Windows for raw IP transmission"
                .to_owned(),
    })
}

#[cfg(all(feature = "native-layer2", windows))]
pub(super) fn system_send_layer2(
    frame: super::provider_impl::Layer2Frame<'_>,
) -> Result<super::provider_impl::IoSendReport, LiveIoError> {
    npcap::send_layer2(frame)
}

#[cfg(any(
    not(feature = "native-layer2"),
    all(
        feature = "native-layer2",
        not(any(target_os = "linux", target_os = "macos", windows))
    )
))]
pub(super) fn system_send_layer2(
    _frame: super::provider_impl::Layer2Frame<'_>,
) -> Result<super::provider_impl::IoSendReport, LiveIoError> {
    Err(LiveIoError::Unsupported {
        message: "enable the native-layer2 feature on a supported target for Layer 2 injection"
            .to_owned(),
    })
}

#[cfg(all(feature = "native-route", target_os = "linux"))]
pub(super) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    linux::interfaces().map_err(interface_error)
}

#[cfg(all(feature = "native-route", target_os = "macos"))]
pub(super) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    macos::interfaces().map_err(interface_error)
}

#[cfg(all(feature = "native-route", windows))]
pub(super) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    windows::interfaces().map_err(interface_error)
}

#[cfg(all(not(feature = "native-route"), feature = "live", not(windows)))]
pub(super) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    Ok(pnet_enumeration::interfaces())
}

#[cfg(all(not(feature = "native-route"), feature = "live", windows))]
pub(super) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    Err(LiveIoError::Unsupported {
        message: "Windows interface enumeration is unavailable in the portable profile; use a PacketcraftR build with the Windows native adapter when available (Npcap is required only for native Layer 2 capture and injection)".to_owned(),
    })
}

#[cfg(all(not(feature = "native-route"), not(feature = "live")))]
pub(super) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    Err(LiveIoError::Unsupported {
        message: "interface enumeration is unavailable without the live feature".to_owned(),
    })
}

#[cfg(feature = "native-route")]
fn interface_error(error: NativeRouteError) -> LiveIoError {
    match error {
        NativeRouteError::Unsupported { message } => LiveIoError::Unsupported { message },
        error => LiveIoError::InterfaceDiscovery {
            message: error.to_string(),
        },
    }
}

#[cfg(all(feature = "native-route", target_os = "linux"))]
pub(super) fn system_route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    linux::route(destination, interface_hint, preferred_source)
}

#[cfg(all(feature = "native-route", target_os = "macos"))]
pub(super) fn system_route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    macos::route(destination, interface_hint, preferred_source)
}

#[cfg(all(feature = "native-route", windows))]
pub(super) fn system_route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    windows::route(destination, interface_hint, preferred_source)
}

#[cfg(not(feature = "native-route"))]
pub(super) fn system_route(
    _destination: IpAddr,
    _interface_hint: Option<&InterfaceId>,
    _preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    Err(NativeRouteError::Unsupported {
        message: "enable the native-route feature for passive operating-system route selection"
            .to_owned(),
    })
}

#[cfg(all(feature = "native-route", target_os = "linux"))]
pub(super) fn system_interface_route(
    interface: &InterfaceId,
) -> Result<RouteDecision, NativeRouteError> {
    linux::interface_route(interface)
}

#[cfg(all(feature = "native-route", target_os = "macos"))]
pub(super) fn system_interface_route(
    interface: &InterfaceId,
) -> Result<RouteDecision, NativeRouteError> {
    macos::interface_route(interface)
}

#[cfg(all(feature = "native-route", windows))]
pub(super) fn system_interface_route(
    interface: &InterfaceId,
) -> Result<RouteDecision, NativeRouteError> {
    windows::interface_route(interface)
}

#[cfg(not(feature = "native-route"))]
pub(super) fn system_interface_route(
    _interface: &InterfaceId,
) -> Result<RouteDecision, NativeRouteError> {
    Err(NativeRouteError::Unsupported {
        message: "enable the native-route feature for passive operating-system interface selection"
            .to_owned(),
    })
}

#[cfg(feature = "native-route")]
pub(super) struct NativeRouteSnapshot {
    pub interface: InterfaceInfo,
    pub selected_address: Option<IpAddr>,
    pub next_hop: Option<IpAddr>,
    pub route_mtu: Option<u32>,
    pub selection_reason: RouteSelectionReason,
}

#[cfg(feature = "native-route")]
pub(super) fn finish_route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
    snapshot: NativeRouteSnapshot,
) -> Result<RouteDecision, NativeRouteError> {
    if let Some(hint) = interface_hint {
        validate_interface_hint(hint, &snapshot.interface.id)?;
    }
    if let Some(source) = preferred_source {
        if source.is_ipv4() != destination.is_ipv4() {
            return Err(NativeRouteError::SourceFamilyMismatch {
                preferred_source: source,
                destination,
            });
        }
        if !snapshot
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

#[cfg(feature = "native-route")]
fn fallback_source(
    addresses: &[super::provider_impl::InterfaceAddress],
    destination: IpAddr,
) -> Option<IpAddr> {
    let mut best: Option<(IpAddr, (bool, u8, bool))> = None;
    for assigned in addresses {
        let address = assigned.address;
        if address.is_ipv4() != destination.is_ipv4()
            || address.is_unspecified()
            || address.is_multicast()
        {
            continue;
        }
        let prefix_match = prefix_matches(address, destination, assigned.prefix_length);
        let rank = (
            prefix_match,
            if prefix_match {
                assigned.prefix_length
            } else {
                0
            },
            address_scope(address) == address_scope(destination),
        );
        if best.as_ref().is_none_or(|(_, current)| rank > *current) {
            best = Some((address, rank));
        }
    }
    best.map(|(address, _)| address)
}

#[cfg(feature = "native-route")]
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

#[cfg(feature = "native-route")]
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

#[cfg(feature = "native-route")]
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

#[cfg(feature = "native-route")]
pub(super) fn interface_decision(
    interface: InterfaceInfo,
) -> Result<RouteDecision, NativeRouteError> {
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
        destination_scope: super::route_impl::DestinationScope::Unspecified,
        mtu,
        capability: interface.capability,
        link_type: interface.link_type,
    })
}

#[cfg(feature = "native-route")]
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

#[cfg(all(test, feature = "native-route"))]
mod tests {
    use super::*;
    use crate::capture::LinkType;
    use crate::net::{InterfaceAddress, InterfaceFlags, LinkCapability, MacAddress};
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
    fn native_snapshot_rejects_interface_mismatch_and_missing_interface() {
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
}
