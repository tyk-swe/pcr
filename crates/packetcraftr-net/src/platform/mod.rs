// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Crate-private native adapter boundary.
//!
//! This directory is the only location in the crate permitted to contain FFI
//! or narrowly reviewed unsafe code. Public traits and values live in `net`.

mod capture_dispatch;
mod interface_dispatch;
mod layer2_dispatch;
mod layer3_dispatch;
#[cfg(all(target_os = "linux", feature = "native-route"))]
mod linux;
#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
mod live_capture;
#[cfg(all(target_os = "macos", feature = "native-route"))]
mod macos;
#[cfg(all(feature = "native-layer2", windows))]
mod npcap;
#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos")
))]
mod pcap_backend;
#[cfg(all(
    feature = "native-interfaces",
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
#[cfg(all(windows, any(feature = "native-interfaces", feature = "native-route")))]
mod windows;

pub(crate) use capture_dispatch::{system_capture, system_capture_with_filter};
pub(crate) use interface_dispatch::system_interfaces;
pub(crate) use layer2_dispatch::system_send_layer2;
pub(crate) use layer3_dispatch::system_send_layer3;
pub(crate) use route_dispatch::{system_interface_route, system_route};

use super::Error as LiveIoError;
#[cfg(any(
    all(
        any(feature = "native-layer2", feature = "native-layer3"),
        any(target_os = "linux", target_os = "macos", windows)
    ),
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ),
    all(any(feature = "native-interfaces", feature = "native-route"), windows)
))]
use super::interface::InterfaceInfo;
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
use super::route::InterfaceId;
use super::route::NativeRouteError;
#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos")
))]
use super::route::find_interface;
#[cfg(any(
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ),
    all(any(feature = "native-interfaces", feature = "native-route"), windows)
))]
use super::route::validate_native_interface;
#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
use super::route::{
    NativeRouteSnapshot, finish_route, interface_decision, validate_preferred_source_family,
};

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
        not(feature = "native-interfaces")
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
fn validate_current_interface_identity(
    expected: &InterfaceId,
) -> Result<InterfaceInfo, LiveIoError> {
    let interfaces = system_interfaces()?;
    if let Some(interface) = interfaces
        .iter()
        .find(|interface| interface_identity_matches(&interface.id, expected))
    {
        return Ok(interface.clone());
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
    all(any(feature = "native-interfaces", feature = "native-route"), windows)
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
    all(any(feature = "native-interfaces", feature = "native-route"), windows)
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
    test,
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
mod tests {
    use super::*;
    use crate::{
        interface::{InterfaceAddress, InterfaceFlags},
        link::{LinkCapability, MacAddress},
        route::RouteSelectionReason,
    };
    use packetcraftr_capture::LinkType;
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
}
