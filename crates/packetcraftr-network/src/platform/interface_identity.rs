// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Interface identity validation for native I/O boundaries.

#![forbid(unsafe_code)]

#[cfg(all(
    any(feature = "native-layer2", feature = "native-layer3"),
    any(target_os = "linux", target_os = "macos", windows)
))]
use crate::route::InterfaceId;

#[cfg(all(
    any(feature = "native-layer2", feature = "native-layer3"),
    any(target_os = "linux", target_os = "macos", windows)
))]
use crate::{
    Error as LiveIoError, interface::InterfaceInfo, platform::interface_dispatch::system_interfaces,
};

#[cfg(all(
    any(feature = "native-layer2", feature = "native-layer3"),
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(crate) fn validate_current_interface_identity(
    expected: &InterfaceId,
) -> Result<InterfaceInfo, LiveIoError> {
    let mut interfaces = system_interfaces()?;
    if let Some(position) = interfaces
        .iter()
        .position(|interface| interface_identity_matches(&interface.id, expected))
    {
        return Ok(interfaces.swap_remove(position));
    }
    let actual = interfaces
        .iter()
        .find(|interface| interface.id.index == expected.index)
        .map(|interface| format!("{} (index {})", interface.id.name, interface.id.index))
        .unwrap_or_else(|| "no current interface".to_owned());
    Err(LiveIoError::Device {
        interface: expected.name.clone(),
        message: format!(
            "interface identity changed before native I/O: expected {} (index {}), found {actual}",
            expected.name, expected.index
        ),
    })
}

#[cfg(all(
    any(feature = "native-layer2", feature = "native-layer3"),
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(crate) fn interface_identity_matches(actual: &InterfaceId, expected: &InterfaceId) -> bool {
    actual.index == expected.index && actual.name == expected.name
}
