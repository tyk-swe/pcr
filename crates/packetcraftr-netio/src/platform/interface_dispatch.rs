// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native interface-enumeration capability dispatch.

use crate::{Error, interface};

// Unix interface enumeration shares the native route backend; native-interfaces
// depends directly on native-route in Cargo.toml.

#[cfg(all(feature = "native-route", target_os = "linux"))]
use super::linux as native;

#[cfg(all(feature = "native-route", target_os = "macos"))]
use super::macos as native;

#[cfg(all(any(feature = "native-interfaces", feature = "native-route"), windows))]
use super::windows as native;

#[cfg(any(
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ),
    all(any(feature = "native-interfaces", feature = "native-route"), windows)
))]
pub(crate) fn system_interfaces() -> Result<Vec<interface::Info>, Error> {
    let interfaces = native::interfaces().map_err(|error| match error {
        crate::route::SystemError::Unsupported { message } => Error::Unsupported {
            message,
            source: None,
        },
        error => Error::InterfaceDiscovery {
            message: "the native route adapter refused the interface query".to_owned(),
            source: Some(std::sync::Arc::new(error)),
        },
    })?;
    super::interface_validation::validate_native_interfaces(interfaces).map_err(|message| {
        Error::InterfaceDiscovery {
            message: format!("native route response was invalid: {message}"),
            source: None,
        }
    })
}

/// Distinguishes a target that has no native enumeration backend from a build
/// that simply left the feature off, so the message names the actionable cause.
#[cfg(not(any(
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ),
    all(any(feature = "native-interfaces", feature = "native-route"), windows)
)))]
pub(crate) fn system_interfaces() -> Result<Vec<interface::Info>, Error> {
    Err(Error::Unsupported {
        message: if cfg!(any(feature = "native-interfaces", feature = "native-route")) {
            "native route and interface discovery is unsupported on this target".to_owned()
        } else {
            "interface enumeration is unavailable without the native-interfaces feature".to_owned()
        },
        source: None,
    })
}
