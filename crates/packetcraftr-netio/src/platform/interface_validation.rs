// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Operating-system native interface snapshot validation.

#![forbid(unsafe_code)]

use crate::interface::InterfaceInfo;

pub(crate) fn validate_native_interface(interface: &InterfaceInfo) -> Result<(), String> {
    if interface.id.name.is_empty() || interface.id.index == 0 {
        return Err("operating system returned an incomplete interface identity".to_owned());
    }
    for assigned in &interface.addresses {
        let maximum = if assigned.address.is_ipv4() { 32 } else { 128 };
        if assigned.prefix_length > maximum {
            return Err(format!(
                "interface {} returned invalid prefix length {} for {}",
                interface.id.name, assigned.prefix_length, assigned.address
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_native_interfaces(
    interfaces: Vec<InterfaceInfo>,
) -> Result<Vec<InterfaceInfo>, String> {
    let mut identities = std::collections::HashSet::with_capacity(interfaces.len());
    for interface in &interfaces {
        validate_native_interface(interface)?;
        if !identities.insert(&interface.id) {
            return Err(format!(
                "operating system returned duplicate interface {} (index {})",
                interface.id.name, interface.id.index
            ));
        }
    }
    Ok(interfaces)
}
