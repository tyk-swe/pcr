// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native interface-enumeration capability dispatch.

#![forbid(unsafe_code)]

use packetcraftr_net::{Error as LiveIoError, interface::InterfaceInfo};

#[cfg(all(feature = "native-route", target_os = "linux"))]
pub(crate) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    super::linux::interfaces()
        .and_then(super::validate_native_interfaces)
        .map_err(super::interface_error)
}

#[cfg(all(feature = "native-route", target_os = "macos"))]
pub(crate) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    super::macos::interfaces()
        .and_then(super::validate_native_interfaces)
        .map_err(super::interface_error)
}

#[cfg(all(any(feature = "native-interfaces", feature = "native-route"), windows))]
pub(crate) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    super::windows::interfaces()
        .and_then(super::validate_native_interfaces)
        .map_err(super::interface_error)
}

#[cfg(all(
    feature = "native-route",
    not(any(target_os = "linux", target_os = "macos", windows)),
    not(feature = "native-interfaces")
))]
pub(crate) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    Err(super::unsupported_live_io(
        "native route and interface discovery is unsupported on this target",
    ))
}

#[cfg(all(
    feature = "native-interfaces",
    not(windows),
    not(all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ))
))]
pub(crate) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    Ok(super::pnet_enumeration::interfaces())
}

#[cfg(all(not(feature = "native-route"), not(feature = "native-interfaces")))]
pub(crate) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    Err(super::unsupported_live_io(
        "interface enumeration is unavailable without the native-interfaces feature",
    ))
}
