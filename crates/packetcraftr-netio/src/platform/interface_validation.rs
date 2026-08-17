// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Operating-system native interface snapshot validation.

#![forbid(unsafe_code)]

use std::fmt;

use crate::interface::InterfaceInfo;

#[derive(Debug)]
pub(crate) struct ValidationError {
    message: String,
}

impl ValidationError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ValidationError {}

pub(crate) fn validate_native_interface(interface: &InterfaceInfo) -> Result<(), ValidationError> {
    if interface.id.name.is_empty() || interface.id.index == 0 {
        return Err(ValidationError::new(
            "operating system returned an incomplete interface identity".to_owned(),
        ));
    }
    for assigned in &interface.addresses {
        let maximum = if assigned.address.is_ipv4() { 32 } else { 128 };
        if assigned.prefix_length > maximum {
            return Err(ValidationError::new(format!(
                "interface {} returned invalid prefix length {} for {}",
                interface.id.name, assigned.prefix_length, assigned.address
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_native_interfaces(
    interfaces: Vec<InterfaceInfo>,
) -> Result<Vec<InterfaceInfo>, ValidationError> {
    let mut identities = std::collections::HashSet::with_capacity(interfaces.len());
    for interface in &interfaces {
        validate_native_interface(interface)?;
        if !identities.insert(&interface.id) {
            return Err(ValidationError::new(format!(
                "operating system returned duplicate interface {} (index {})",
                interface.id.name, interface.id.index
            )));
        }
    }
    Ok(interfaces)
}
