// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native backend selection: one entry point per native operation, backed by
//! the module the build script selected for this target, or a fail-closed
//! stub whose message names the actionable cause.
//!
//! Validation belongs to the capability that calls these entry points; each
//! one here forwards to its backend unchanged.

use std::net::IpAddr;

use packetcraftr_core::budget::Deadline;

use crate::{
    Error, interface,
    interface::Id as InterfaceId,
    route::{self, Decision},
    transmit::{self, Layer2Frame, Layer3Frame},
};
#[cfg(not(all(native_route, native_layer2, native_layer3)))]
use crate::{NativeCapability, Unsupported};

#[cfg(all(native_route, target_os = "linux"))]
use super::route::netlink as route_backend;

#[cfg(all(native_route, target_os = "macos"))]
use super::route::af_route as route_backend;

#[cfg(all(native_route, windows))]
use super::route::iphelper as route_backend;

#[cfg(pcap_backend)]
use super::layer2::pcap_backend as layer2_backend;

#[cfg(npcap_backend)]
use super::layer2::npcap as layer2_backend;

/// The failure for a native `capability` this build has no backend for. The
/// message names the `operation` and distinguishes a target that has no
/// native implementation from a build that simply left `feature` off.
#[cfg(not(all(native_route, native_layer2, native_layer3)))]
pub(crate) fn unsupported(
    capability: NativeCapability,
    feature_enabled: bool,
    feature: &str,
    operation: &str,
) -> Unsupported {
    Unsupported::new(
        capability,
        if feature_enabled {
            format!("native {operation} is unsupported on this target")
        } else {
            format!("enable the {feature} feature for native {operation}")
        },
    )
}

#[cfg(native_route)]
pub(crate) fn route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
    deadline: &Deadline,
) -> Result<Decision, route::Error> {
    route_backend::route(destination, interface_hint, preferred_source, deadline)
}

#[cfg(not(native_route))]
pub(crate) fn route(
    _destination: IpAddr,
    _interface_hint: Option<&InterfaceId>,
    _preferred_source: Option<IpAddr>,
    _deadline: &Deadline,
) -> Result<Decision, route::Error> {
    Err(unsupported(
        NativeCapability::Route,
        cfg!(feature = "native-route"),
        "native-route",
        "route selection",
    )
    .into())
}

#[cfg(native_route)]
pub(crate) fn interface_route(
    interface: &InterfaceId,
    deadline: &Deadline,
) -> Result<Decision, route::Error> {
    route_backend::interface_route(interface, deadline)
}

#[cfg(not(native_route))]
pub(crate) fn interface_route(
    _interface: &InterfaceId,
    _deadline: &Deadline,
) -> Result<Decision, route::Error> {
    Err(unsupported(
        NativeCapability::Route,
        cfg!(feature = "native-route"),
        "native-route",
        "interface selection",
    )
    .into())
}

#[cfg(native_route)]
pub(crate) fn interfaces(deadline: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
    route_backend::interfaces(deadline)
}

#[cfg(not(native_route))]
pub(crate) fn interfaces(_deadline: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
    Err(unsupported(
        NativeCapability::InterfaceEnumeration,
        cfg!(feature = "native-route"),
        "native-route",
        "interface enumeration",
    )
    .into())
}

/// Opens the backend's capture source; the capture capability owns every
/// check before this call and the session built from its parts.
#[cfg(native_layer2)]
pub(crate) fn open_capture(
    interface: &InterfaceId,
    limits: crate::capture::Limits,
    filter: Option<&str>,
    netmask: Option<u32>,
    promiscuous: bool,
    native: &crate::capture::NativeSettings,
) -> Result<crate::capture::live::NativeCaptureParts, Error> {
    layer2_backend::open_capture(interface, limits, filter, netmask, promiscuous, native)
}

#[cfg(native_layer2)]
pub(crate) fn timestamp_types(
    interface: &InterfaceId,
) -> Result<Vec<crate::capture::TimestampType>, Error> {
    layer2_backend::timestamp_types(interface)
}

#[cfg(native_layer2)]
pub(crate) fn send_layer2(frame: Layer2Frame<'_>) -> Result<transmit::Report, Error> {
    layer2_backend::send_layer2(frame)
}

#[cfg(not(native_layer2))]
pub(crate) fn send_layer2(_frame: Layer2Frame<'_>) -> Result<transmit::Report, Error> {
    Err(unsupported(
        NativeCapability::Transmission(crate::link::Mode::Layer2),
        cfg!(feature = "native-layer2"),
        "native-layer2",
        "Layer 2 injection",
    )
    .into())
}

#[cfg(native_layer3)]
pub(crate) fn send_layer3(frame: Layer3Frame<'_>) -> Result<transmit::Report, Error> {
    super::layer3::raw_ip::send_layer3(frame)
}

#[cfg(not(native_layer3))]
pub(crate) fn send_layer3(_frame: Layer3Frame<'_>) -> Result<transmit::Report, Error> {
    Err(unsupported(
        NativeCapability::Transmission(crate::link::Mode::Layer3),
        cfg!(feature = "native-layer3"),
        "native-layer3",
        "raw IP transmission",
    )
    .into())
}

/// Confirms the interface a send was routed to still has that name and index.
#[cfg(native_send)]
pub(crate) fn verify_interface_identity(expected: &InterfaceId) -> Result<(), Error> {
    super::interface_identity::verify_interface_identity(expected)
}

/// Confirms the interface is still current and returns its snapshot.
#[cfg(native_layer2)]
pub(crate) fn current_interface(
    expected: &InterfaceId,
    deadline: &Deadline,
) -> Result<interface::Info, Error> {
    super::interface_identity::validate_current_interface_identity(expected, deadline)
}
