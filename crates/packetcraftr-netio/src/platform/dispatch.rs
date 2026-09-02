// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native capability dispatch: one entry point per capability, backed by the
//! module the build script selected for this target, or a fail-closed stub
//! whose message names the actionable cause.

use std::net::IpAddr;

use crate::{
    Error, capture,
    interface::{self, Id as InterfaceId},
    route::{Decision, SystemError},
    transmit::{self, Layer2Frame, Layer3Frame},
};

#[cfg(all(native_route, target_os = "linux"))]
use super::netlink as route_backend;

#[cfg(all(native_route, target_os = "macos"))]
use super::af_route as route_backend;

#[cfg(all(native_route, windows))]
use super::iphelper as route_backend;

#[cfg(pcap_backend)]
use super::pcap_backend as layer2_backend;

#[cfg(npcap_backend)]
use super::npcap as layer2_backend;

/// Distinguishes a target that has no native implementation from a build that
/// simply left the feature off.
#[cfg(not(all(native_route, native_layer2, native_layer3)))]
fn unsupported_message(feature_enabled: bool, feature: &str, capability: &str) -> String {
    if feature_enabled {
        format!("native {capability} is unsupported on this target")
    } else {
        format!("enable the {feature} feature for native {capability}")
    }
}

#[cfg(not(all(native_route, native_layer2, native_layer3)))]
fn unsupported(feature_enabled: bool, feature: &str, capability: &str) -> Error {
    Error::Unsupported {
        message: unsupported_message(feature_enabled, feature, capability),
        source: None,
    }
}

#[cfg(native_route)]
pub(crate) fn system_route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<Decision, SystemError> {
    route_backend::route(destination, interface_hint, preferred_source)
}

#[cfg(not(native_route))]
pub(crate) fn system_route(
    _destination: IpAddr,
    _interface_hint: Option<&InterfaceId>,
    _preferred_source: Option<IpAddr>,
) -> Result<Decision, SystemError> {
    Err(SystemError::Unsupported {
        message: unsupported_message(
            cfg!(feature = "native-route"),
            "native-route",
            "route selection",
        ),
    })
}

#[cfg(native_route)]
pub(crate) fn system_interface_route(interface: &InterfaceId) -> Result<Decision, SystemError> {
    route_backend::interface_route(interface)
}

#[cfg(not(native_route))]
pub(crate) fn system_interface_route(_interface: &InterfaceId) -> Result<Decision, SystemError> {
    Err(SystemError::Unsupported {
        message: unsupported_message(
            cfg!(feature = "native-route"),
            "native-route",
            "interface selection",
        ),
    })
}

#[cfg(native_route)]
pub(crate) fn system_interfaces() -> Result<Vec<interface::Info>, Error> {
    let interfaces = route_backend::interfaces().map_err(|error| match error {
        SystemError::Unsupported { message } => Error::Unsupported {
            message,
            source: None,
        },
        error => Error::InterfaceDiscovery {
            message: "the native route adapter refused the interface query".to_owned(),
            source: Some(std::sync::Arc::new(error)),
        },
    })?;
    super::interface_validation::validate_native_interfaces(interfaces).map_err(|error| {
        Error::InterfaceDiscovery {
            message: error.to_string(),
            source: None,
        }
    })
}

#[cfg(not(native_route))]
pub(crate) fn system_interfaces() -> Result<Vec<interface::Info>, Error> {
    Err(unsupported(
        cfg!(feature = "native-route"),
        "native-interfaces",
        "interface enumeration",
    ))
}

#[cfg(native_layer2)]
pub(crate) fn system_capture(
    request: &capture::Request,
) -> Result<Box<dyn capture::Session>, Error> {
    request.limits.validate()?;
    let validated_limits = request.limits;
    if let Some(filter) = request.filter.as_deref() {
        super::capture_filter::validate(&request.interface, filter)?;
    }
    let interface =
        super::interface_identity::validate_current_interface_identity(&request.interface)?;
    let netmask = capture_netmask(&interface);
    let parts = layer2_backend::open_capture(
        &interface.id,
        validated_limits,
        request.filter.as_deref(),
        netmask,
        request.promiscuous,
    )?;
    Ok(Box::new(super::live_capture::NativeCaptureSession::spawn(
        parts,
        validated_limits,
    )?))
}

#[cfg(not(native_layer2))]
pub(crate) fn system_capture(
    _request: &capture::Request,
) -> Result<Box<dyn capture::Session>, Error> {
    Err(unsupported(
        cfg!(feature = "native-layer2"),
        "native-layer2",
        "packet capture",
    ))
}

#[cfg(native_layer2)]
pub(crate) fn system_send_layer2(frame: Layer2Frame<'_>) -> Result<transmit::Report, Error> {
    super::interface_identity::verify_interface_identity(&frame.route().plan.decision.interface)?;
    layer2_backend::send_layer2(frame)
}

#[cfg(not(native_layer2))]
pub(crate) fn system_send_layer2(_frame: Layer2Frame<'_>) -> Result<transmit::Report, Error> {
    Err(unsupported(
        cfg!(feature = "native-layer2"),
        "native-layer2",
        "Layer 2 injection",
    ))
}

#[cfg(native_layer3)]
pub(crate) fn system_send_layer3(frame: Layer3Frame<'_>) -> Result<transmit::Report, Error> {
    super::interface_identity::verify_interface_identity(&frame.route().plan.decision.interface)?;
    super::raw_ip::send_layer3(frame)
}

#[cfg(not(native_layer3))]
pub(crate) fn system_send_layer3(_frame: Layer3Frame<'_>) -> Result<transmit::Report, Error> {
    Err(unsupported(
        cfg!(feature = "native-layer3"),
        "native-layer3",
        "raw IP transmission",
    ))
}

#[cfg(native_layer2)]
fn capture_netmask(interface: &interface::Info) -> Option<u32> {
    let assigned = interface
        .addresses
        .iter()
        .find(|assigned| assigned.address.is_ipv4())?;
    let shift = u32::BITS.checked_sub(u32::from(assigned.prefix_length))?;
    Some(u32::MAX.checked_shl(shift).unwrap_or(0).to_be())
}

#[cfg(all(test, native_layer2))]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use packetcraftr_core::frame::LinkType;

    use super::*;
    use crate::link::Capability;

    #[test]
    fn capture_netmask_uses_the_first_ipv4_assignment() {
        let interface = interface::Info {
            id: InterfaceId {
                name: "fixture0".to_owned(),
                index: 7,
            },
            description: None,
            mac_address: None,
            addresses: vec![
                interface::Address {
                    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    prefix_length: 8,
                },
                interface::Address {
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                    prefix_length: 24,
                },
            ],
            flags: interface::Flags::default(),
            mtu: None,
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        };

        assert_eq!(capture_netmask(&interface), Some((u32::MAX << 24).to_be()));

        let mut ipv6_only = interface;
        ipv6_only.addresses = vec![interface::Address {
            address: IpAddr::V6(Ipv6Addr::LOCALHOST),
            prefix_length: 128,
        }];
        assert_eq!(capture_netmask(&ipv6_only), None);
    }
}
