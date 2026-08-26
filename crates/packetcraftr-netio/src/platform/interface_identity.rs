// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Interface identity validation for native I/O boundaries.

#![forbid(unsafe_code)]

use crate::{
    Error,
    interface::{self, Id as InterfaceId},
    platform::interface_dispatch::system_interfaces,
};

pub(super) fn validate_current_interface_identity(
    expected: &InterfaceId,
) -> Result<interface::Info, Error> {
    let mut interfaces = system_interfaces()?;
    if let Some(position) = interfaces
        .iter()
        .position(|interface| interface.id == *expected)
    {
        return Ok(interfaces.swap_remove(position));
    }
    let actual = interfaces
        .iter()
        .find(|interface| interface.id.index == expected.index)
        .map(|interface| format!("{} (index {})", interface.id.name, interface.id.index))
        .unwrap_or_else(|| "no current interface".to_owned());
    Err(Error::Device {
        interface: expected.name.clone(),
        message: format!(
            "interface identity changed before native I/O: expected {} (index {}), found {actual}",
            expected.name, expected.index
        ),
    })
}
