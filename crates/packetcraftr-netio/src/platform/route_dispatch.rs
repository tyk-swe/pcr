// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native route-selection capability dispatch.

#![forbid(unsafe_code)]

use std::net::IpAddr;

use crate::{
    interface::Id as InterfaceId,
    route::{Decision, SystemError},
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
) -> Result<Decision, SystemError> {
    native::route(destination, interface_hint, preferred_source)
}

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(crate) fn system_interface_route(interface: &InterfaceId) -> Result<Decision, SystemError> {
    native::interface_route(interface)
}

#[cfg(not(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
)))]
pub(crate) fn system_route(
    _destination: IpAddr,
    _interface_hint: Option<&InterfaceId>,
    _preferred_source: Option<IpAddr>,
) -> Result<Decision, SystemError> {
    Err(unsupported("route selection"))
}

#[cfg(not(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
)))]
pub(crate) fn system_interface_route(_interface: &InterfaceId) -> Result<Decision, SystemError> {
    Err(unsupported("interface selection"))
}

/// Distinguishes a target that has no native implementation from a build that
/// simply left the feature off, so the message names the actionable cause.
#[cfg(not(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
)))]
fn unsupported(capability: &str) -> SystemError {
    SystemError::Unsupported {
        message: if cfg!(feature = "native-route") {
            format!("native {capability} is unsupported on this target")
        } else {
            format!("enable the native-route feature for passive operating-system {capability}")
        },
    }
}
