// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native route-selection capability dispatch.

#![forbid(unsafe_code)]

use std::net::IpAddr;

use crate::{
    interface::Id as InterfaceId,
    route::{NativeRouteError, RouteDecision},
};

#[cfg(all(feature = "native-route", target_os = "linux"))]
use super::linux as native;

#[cfg(all(feature = "native-route", target_os = "macos"))]
use super::macos as native;

#[cfg(all(feature = "native-route", windows))]
use super::windows as native;

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(crate) fn system_route(
    destination: IpAddr,
    interface_hint: Option<&InterfaceId>,
    preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    native::route(destination, interface_hint, preferred_source)
}

#[cfg(all(
    feature = "native-route",
    not(any(target_os = "linux", target_os = "macos", windows))
))]
pub(crate) fn system_route(
    _destination: IpAddr,
    _interface_hint: Option<&InterfaceId>,
    _preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    Err(NativeRouteError::Unsupported {
        message: "native route selection is unsupported on this target".to_owned(),
    })
}

#[cfg(not(feature = "native-route"))]
pub(crate) fn system_route(
    _destination: IpAddr,
    _interface_hint: Option<&InterfaceId>,
    _preferred_source: Option<IpAddr>,
) -> Result<RouteDecision, NativeRouteError> {
    Err(NativeRouteError::Unsupported {
        message: "enable the native-route feature for passive operating-system route selection"
            .to_owned(),
    })
}

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(crate) fn system_interface_route(
    interface: &InterfaceId,
) -> Result<RouteDecision, NativeRouteError> {
    native::interface_route(interface)
}

#[cfg(all(
    feature = "native-route",
    not(any(target_os = "linux", target_os = "macos", windows))
))]
pub(crate) fn system_interface_route(
    _interface: &InterfaceId,
) -> Result<RouteDecision, NativeRouteError> {
    Err(NativeRouteError::Unsupported {
        message: "native interface selection is unsupported on this target".to_owned(),
    })
}

#[cfg(not(feature = "native-route"))]
pub(crate) fn system_interface_route(
    _interface: &InterfaceId,
) -> Result<RouteDecision, NativeRouteError> {
    Err(NativeRouteError::Unsupported {
        message: "enable the native-route feature for passive operating-system interface selection"
            .to_owned(),
    })
}
