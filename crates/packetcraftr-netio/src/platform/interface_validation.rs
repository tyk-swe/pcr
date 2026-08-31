// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Operating-system native interface snapshot validation.

use crate::interface;

pub(crate) fn validate_native_interface(interface: &interface::Info) -> Result<(), String> {
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
    interfaces: Vec<interface::Info>,
) -> Result<Vec<interface::Info>, String> {
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use packetcraftr_core::frame::LinkType;

    use super::*;
    use crate::{
        interface::{self, Id as InterfaceId},
        link::Capability,
    };

    fn interface(name: &str, index: u32, addresses: Vec<interface::Address>) -> interface::Info {
        interface::Info {
            id: InterfaceId {
                name: name.to_owned(),
                index,
            },
            description: None,
            mac_address: None,
            addresses,
            flags: interface::Flags::default(),
            mtu: Some(1_500),
            capability: Capability::Layer3,
            link_type: LinkType::RAW,
        }
    }

    #[test]
    fn native_interface_validation_accepts_complete_identity_and_family_prefix_bounds() {
        let interfaces = vec![interface(
            "fixture0",
            7,
            vec![
                interface::Address {
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    prefix_length: 32,
                },
                interface::Address {
                    address: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    prefix_length: 128,
                },
            ],
        )];

        assert_eq!(
            validate_native_interfaces(interfaces.clone()).expect("valid native snapshot"),
            interfaces
        );
    }

    #[test]
    fn native_interface_validation_rejects_incomplete_identity_and_invalid_family_prefixes() {
        for invalid in [
            interface("", 7, Vec::new()),
            interface("fixture0", 0, Vec::new()),
            interface(
                "fixture0",
                7,
                vec![interface::Address {
                    address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    prefix_length: 33,
                }],
            ),
            interface(
                "fixture0",
                7,
                vec![interface::Address {
                    address: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    prefix_length: 129,
                }],
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

        assert!(error.contains("duplicate interface fixture0 (index 7)"));
    }
}
