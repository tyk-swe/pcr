// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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
use super::{interface::netlink as interface_backend, route::netlink as route_backend};

#[cfg(all(native_route, target_os = "macos"))]
use super::{interface::af_route as interface_backend, route::af_route as route_backend};

#[cfg(all(native_route, target_os = "windows"))]
use super::{interface::iphelper as interface_backend, route::iphelper as route_backend};

#[cfg(pcap_backend)]
use super::{capture::libpcap as capture_backend, transmit::libpcap as transmit_backend};

#[cfg(npcap_backend)]
use super::{capture::npcap as capture_backend, transmit::npcap as transmit_backend};

#[cfg(not(all(native_route, native_layer2, native_layer3)))]
pub(crate) fn unsupported(
    capability: NativeCapability,
    feature_enabled: bool,
    feature: &str,
    operation: &str,
) -> Unsupported {
    Unsupported::unbuilt(capability, feature_enabled, feature, operation)
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
    interface_backend::interfaces(deadline)
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

pub(crate) fn ipv6_interfaces(
    deadline: &Deadline,
) -> Result<Vec<interface::Info>, interface::Error> {
    #[cfg(all(native_route, target_os = "windows"))]
    {
        interface_backend::ipv6_interfaces(deadline)
    }
    #[cfg(not(all(native_route, target_os = "windows")))]
    {
        interfaces(deadline)
    }
}

#[cfg(native_send)]
pub(crate) fn interfaces_for_identity(
    expected: &InterfaceId,
    deadline: &Deadline,
) -> Result<Vec<interface::Info>, interface::Error> {
    #[cfg(all(native_route, target_os = "windows"))]
    {
        interface_backend::interfaces_for_identity(expected, deadline)
    }
    #[cfg(not(all(native_route, target_os = "windows")))]
    {
        let _ = expected;
        interfaces(deadline)
    }
}

#[cfg(native_layer2)]
pub(crate) fn open_capture(
    interface: &InterfaceId,
    limits: crate::capture::Limits,
    filter: Option<&str>,
    netmask: Option<u32>,
    promiscuous: bool,
    native: &crate::capture::NativeSettings,
) -> Result<crate::capture::live::NativeCaptureParts, Error> {
    capture_backend::open_capture(interface, limits, filter, netmask, promiscuous, native)
}

#[cfg(native_layer2)]
pub(crate) fn timestamp_types(
    interface: &InterfaceId,
) -> Result<Vec<crate::capture::TimestampType>, Error> {
    capture_backend::timestamp_types(interface)
}

#[cfg(native_layer2)]
pub(crate) fn send_layer2(frame: Layer2Frame<'_>) -> Result<transmit::Report, Error> {
    transmit_backend::send_layer2(frame)
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
    super::transmit::raw_ip::send_layer3(frame)
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

#[cfg(native_send)]
pub(crate) fn verify_interface_identity(expected: &InterfaceId) -> Result<(), Error> {
    super::interface::identity::verify_interface_identity(expected)
}
