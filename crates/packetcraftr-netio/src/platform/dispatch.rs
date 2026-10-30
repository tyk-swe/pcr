// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(not(native_route))]
use std::net::IpAddr;

#[cfg(any(not(native_route), native_send))]
use packetcraftr_core::budget::Deadline;

#[cfg(not(native_route))]
use crate::route::{self, Decision};
#[cfg(not(native_layer2))]
use crate::transmit::Layer2Frame;
#[cfg(not(native_layer3))]
use crate::transmit::Layer3Frame;
#[cfg(any(not(native_layer2), not(native_layer3)))]
use crate::{Error, transmit};
#[cfg(not(all(native_route, native_layer2, native_layer3)))]
use crate::{NativeCapability, Unsupported};
#[cfg(any(not(native_route), native_send))]
use crate::{interface, interface::Id as InterfaceId};

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

#[cfg(not(target_os = "windows"))]
pub(crate) use super::udp::stdlib::receive as receive_datagram;
#[cfg(target_os = "windows")]
pub(crate) use super::udp::winsock::receive as receive_datagram;

#[cfg(not(native_route))]
pub(crate) fn route(
    _destination: IpAddr,
    _interface_hint: Option<&InterfaceId>,
    _preferred_source: Option<IpAddr>,
    _deadline: &Deadline,
) -> Result<Decision, route::Error> {
    Err(Unsupported::unbuilt(
        NativeCapability::Route,
        cfg!(feature = "native-route"),
        "native-route",
        "route selection",
    )
    .into())
}

#[cfg(not(native_route))]
pub(crate) fn interface_route(
    _interface: &InterfaceId,
    _deadline: &Deadline,
) -> Result<Decision, route::Error> {
    Err(Unsupported::unbuilt(
        NativeCapability::Route,
        cfg!(feature = "native-route"),
        "native-route",
        "interface selection",
    )
    .into())
}

#[cfg(not(native_route))]
pub(crate) fn interfaces(_deadline: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
    Err(Unsupported::unbuilt(
        NativeCapability::InterfaceEnumeration,
        cfg!(feature = "native-route"),
        "native-route",
        "interface enumeration",
    )
    .into())
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

#[cfg(not(native_layer2))]
pub(crate) fn send_layer2(_frame: Layer2Frame<'_>) -> Result<transmit::Report, Error> {
    Err(Unsupported::unbuilt(
        NativeCapability::Transmission(crate::link::Mode::Layer2),
        cfg!(feature = "native-layer2"),
        "native-layer2",
        "Layer 2 injection",
    )
    .into())
}

#[cfg(not(native_layer3))]
pub(crate) fn send_layer3(_frame: Layer3Frame<'_>) -> Result<transmit::Report, Error> {
    Err(Unsupported::unbuilt(
        NativeCapability::Transmission(crate::link::Mode::Layer3),
        cfg!(feature = "native-layer3"),
        "native-layer3",
        "raw IP transmission",
    )
    .into())
}

#[cfg(native_send)]
pub(crate) use super::interface::identity::verify_interface_identity;
#[cfg(native_layer3)]
pub(crate) use super::transmit::raw_ip::send_layer3;
#[cfg(native_layer2)]
pub(crate) use capture_backend::{open_capture, timestamp_types};
#[cfg(native_route)]
pub(crate) use interface_backend::interfaces;
#[cfg(all(native_route, target_os = "windows"))]
pub(crate) use interface_backend::ipv6_interfaces;
#[cfg(not(all(native_route, target_os = "windows")))]
pub(crate) use interfaces as ipv6_interfaces;
#[cfg(native_route)]
pub(crate) use route_backend::{interface_route, route};
#[cfg(native_layer2)]
pub(crate) use transmit_backend::send_layer2;
