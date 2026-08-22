// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native interface-enumeration capability dispatch.

#![forbid(unsafe_code)]

use crate::{Error as LiveIoError, interface::InterfaceInfo};

#[cfg(all(feature = "native-route", target_os = "linux"))]
use super::linux as native;

#[cfg(all(feature = "native-route", target_os = "macos"))]
use super::macos as native;

#[cfg(all(any(feature = "native-interfaces", feature = "native-route"), windows))]
use super::windows as native;

#[cfg(any(
    all(feature = "native-route", target_os = "linux"),
    all(feature = "native-route", target_os = "macos"),
    all(any(feature = "native-interfaces", feature = "native-route"), windows)
))]
pub(crate) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    let interfaces = native::interfaces().map_err(|error| match error {
        crate::route::SystemError::Unsupported { message } => LiveIoError::Unsupported { message },
        error => LiveIoError::InterfaceDiscovery {
            message: error.to_string(),
        },
    })?;
    super::interface_validation::validate_native_interfaces(interfaces).map_err(|message| {
        LiveIoError::InterfaceDiscovery {
            message: format!("native route response was invalid: {message}"),
        }
    })
}

#[cfg(all(
    feature = "native-route",
    not(any(target_os = "linux", target_os = "macos", windows)),
    not(feature = "native-interfaces")
))]
pub(crate) fn system_interfaces() -> Result<Vec<InterfaceInfo>, LiveIoError> {
    Err(LiveIoError::Unsupported {
        message: "native route and interface discovery is unsupported on this target".to_owned(),
    })
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
    Err(LiveIoError::Unsupported {
        message: "interface enumeration is unavailable without the native-interfaces feature"
            .to_owned(),
    })
}
