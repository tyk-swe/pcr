// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{interface, route};

pub(crate) fn validate_native_interface(interface: &interface::Info) -> Result<(), route::Error> {
    if interface.id.name.is_empty() || interface.id.index == 0 {
        return Err(invalid_response(
            "operating system returned an incomplete interface identity".to_owned(),
        ));
    }
    for assigned in &interface.addresses {
        let maximum = if assigned.address.is_ipv4() { 32 } else { 128 };
        if assigned.prefix_length > maximum {
            return Err(invalid_response(format!(
                "interface {} returned invalid prefix length {} for {}",
                interface.id.name, assigned.prefix_length, assigned.address
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_native_interfaces(
    interfaces: Vec<interface::Info>,
) -> Result<Vec<interface::Info>, route::Error> {
    let mut identities = std::collections::HashSet::with_capacity(interfaces.len());
    for interface in &interfaces {
        validate_native_interface(interface)?;
        if !identities.insert(&interface.id) {
            return Err(invalid_response(format!(
                "operating system returned duplicate interface {} (index {})",
                interface.id.name, interface.id.index
            )));
        }
    }
    Ok(interfaces)
}

fn invalid_response(message: String) -> route::Error {
    route::Error::InvalidResponse { message }
}
