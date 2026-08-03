// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(all(
    test,
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]

use super::*;
use crate::{
    interface::{InterfaceAddress, InterfaceFlags, InterfaceInfo},
    link::{LinkCapability, MacAddress},
    route::{
        InterfaceId, NativeRouteError, NativeRouteSnapshot, RouteSelectionReason, find_interface,
        finish_route, interface_decision,
    },
};
use packetcraftr_core::frame::LinkType;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
fn native_snapshot_preserves_gateway_reason_and_uses_conservative_route_mtu() {
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

    let decision = finish_route(
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        None,
        None,
        NativeRouteSnapshot {
            route_mtu: Some(9_000),
            ..snapshot()
        },
    )
    .unwrap();
    assert_eq!(decision.mtu, 1_500);
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

    assert!(matches!(
        finish_route(
            destination,
            None,
            None,
            NativeRouteSnapshot {
                selected_address: Some(unavailable),
                ..snapshot()
            }
        ),
        Err(NativeRouteError::InvalidResponse { .. })
    ));
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
