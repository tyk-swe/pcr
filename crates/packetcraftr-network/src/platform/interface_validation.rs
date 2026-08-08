// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Operating-system native interface snapshot validation.

#![forbid(unsafe_code)]

#[cfg(any(
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ),
    all(any(feature = "native-interfaces", feature = "native-route"), windows)
))]
use crate::{Error as LiveIoError, interface::InterfaceInfo, route::NativeRouteError};

#[cfg(any(
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ),
    all(any(feature = "native-interfaces", feature = "native-route"), windows)
))]
pub(crate) fn validate_native_interface(interface: &InterfaceInfo) -> Result<(), NativeRouteError> {
    if interface.id.name.is_empty() || interface.id.index == 0 {
        return Err(NativeRouteError::InvalidResponse {
            message: "operating system returned an incomplete interface identity".to_owned(),
        });
    }
    for assigned in &interface.addresses {
        let maximum = if assigned.address.is_ipv4() { 32 } else { 128 };
        if assigned.prefix_length > maximum {
            return Err(NativeRouteError::InvalidResponse {
                message: format!(
                    "interface {} returned invalid prefix length {} for {}",
                    interface.id.name, assigned.prefix_length, assigned.address
                ),
            });
        }
    }
    Ok(())
}

#[cfg(any(
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ),
    all(any(feature = "native-interfaces", feature = "native-route"), windows)
))]
pub(crate) fn validate_native_interfaces(
    interfaces: Vec<InterfaceInfo>,
) -> Result<Vec<InterfaceInfo>, NativeRouteError> {
    let mut identities = std::collections::HashSet::with_capacity(interfaces.len());
    for interface in &interfaces {
        validate_native_interface(interface)?;
        if !identities.insert(&interface.id) {
            return Err(NativeRouteError::InvalidResponse {
                message: format!(
                    "operating system returned duplicate interface {} (index {})",
                    interface.id.name, interface.id.index
                ),
            });
        }
    }
    Ok(interfaces)
}

#[cfg(any(
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ),
    all(any(feature = "native-interfaces", feature = "native-route"), windows)
))]
pub(crate) fn interface_error(error: NativeRouteError) -> LiveIoError {
    match error {
        NativeRouteError::Unsupported { message } => LiveIoError::Unsupported { message },
        error => LiveIoError::InterfaceDiscovery {
            message: error.to_string(),
        },
    }
}
