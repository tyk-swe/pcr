// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native route-selection capability dispatch.

#![forbid(unsafe_code)]

use std::net::IpAddr;

use super::super::route::{InterfaceId, NativeRouteError, RouteDecision};

#[cfg(all(feature = "native-route", target_os = "linux"))]
pub(in crate::net) fn system_route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    super::linux::route(destination, interface_hint, preferred_source)
}

#[cfg(all(feature = "native-route", target_os = "macos"))]
pub(in crate::net) fn system_route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    super::macos::route(destination, interface_hint, preferred_source)
}

#[cfg(all(feature = "native-route", windows))]
pub(in crate::net) fn system_route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    super::windows::route(destination, interface_hint, preferred_source)
}

#[cfg(all(
    feature = "native-route",
    not(any(target_os = "linux", target_os = "macos", windows))
))]
pub(in crate::net) fn system_route(
    _destination: IpAddr,
    _interface_hint: Option<&InterfaceId>,
    _preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    Err(super::unsupported_native_route(
        "native route selection is unsupported on this target",
    ))
}

#[cfg(not(feature = "native-route"))]
pub(in crate::net) fn system_route(
    _destination: IpAddr,
    _interface_hint: Option<&InterfaceId>,
    _preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    Err(super::unsupported_native_route(
        "enable the native-route feature for passive operating-system route selection",
    ))
}

#[cfg(all(feature = "native-route", target_os = "linux"))]
pub(in crate::net) fn system_interface_route(
    interface: &InterfaceId,
) -> Result<RouteDecision, NativeRouteError> {
    super::linux::interface_route(interface)
}

#[cfg(all(feature = "native-route", target_os = "macos"))]
pub(in crate::net) fn system_interface_route(
    interface: &InterfaceId,
) -> Result<RouteDecision, NativeRouteError> {
    super::macos::interface_route(interface)
}

#[cfg(all(feature = "native-route", windows))]
pub(in crate::net) fn system_interface_route(
    interface: &InterfaceId,
) -> Result<RouteDecision, NativeRouteError> {
    super::windows::interface_route(interface)
}

#[cfg(all(
    feature = "native-route",
    not(any(target_os = "linux", target_os = "macos", windows))
))]
pub(in crate::net) fn system_interface_route(
    _interface: &InterfaceId,
) -> Result<RouteDecision, NativeRouteError> {
    Err(super::unsupported_native_route(
        "native interface selection is unsupported on this target",
    ))
}

#[cfg(not(feature = "native-route"))]
pub(in crate::net) fn system_interface_route(
    _interface: &InterfaceId,
) -> Result<RouteDecision, NativeRouteError> {
    Err(super::unsupported_native_route(
        "enable the native-route feature for passive operating-system interface selection",
    ))
}
