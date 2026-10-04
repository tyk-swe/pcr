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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr};

    use super::*;
    use crate::test_support::{assigned, interface_info, v4};

    fn interface(name: &str, index: u32, addresses: Vec<interface::Address>) -> interface::Info {
        interface::Info {
            addresses,
            ..interface_info(name, index)
        }
    }

    #[test]
    fn native_interface_rejects_bad_identity_and_prefix() {
        for invalid in [
            interface("", 7, Vec::new()),
            interface("fixture0", 0, Vec::new()),
            interface("fixture0", 7, vec![assigned(v4(127, 0, 0, 1), 33)]),
            interface(
                "fixture0",
                7,
                vec![assigned(IpAddr::V6(Ipv6Addr::LOCALHOST), 129)],
            ),
        ] {
            assert!(validate_native_interface(&invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn native_interface_snapshot_rejects_duplicate_stable_identities() {
        let first = interface("fixture0", 7, Vec::new());
        let duplicate = first.clone();

        let error = validate_native_interfaces(vec![first, duplicate])
            .expect_err("duplicate identity must fail closed");

        assert!(matches!(
            error,
            route::Error::InvalidResponse { ref message }
                if message.contains("duplicate interface fixture0 (index 7)")
        ));
    }
}
