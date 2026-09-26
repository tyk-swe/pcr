// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Interface discovery and portable interface descriptions.

mod error;
pub(crate) mod validation;

use std::net::IpAddr;
use std::sync::Arc;

use packetcraftr_core::budget::Deadline;

use super::link::{Capability, MacAddress};

pub use error::Error;

/// Stable operating-system interface identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct Id {
    pub name: String,
    pub index: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Address {
    pub address: IpAddr,
    pub prefix_length: u8,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, serde::Serialize)]
pub struct Flags {
    pub up: bool,
    pub broadcast: bool,
    pub loopback: bool,
    pub point_to_point: bool,
    pub multicast: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    pub id: Id,
    pub description: Option<String>,
    pub mac_address: Option<MacAddress>,
    pub addresses: Vec<Address>,
    pub flags: Flags,
    /// Native MTU, if reported by the adapter.
    pub mtu: Option<u32>,
    pub capability: Capability,
    pub link_type: packetcraftr_core::frame::LinkType,
}

/// Enumerates interfaces without exposing a native handle or wrapper type.
/// Enumeration follows the [deadline convention](crate::deadline).
pub trait Provider: Send + Sync {
    fn interfaces(&self, deadline: &Deadline) -> Result<Vec<Info>, Error>;
}

/// Provider backed by the adapter selected for the current target and feature
/// set. Portable profiles return a typed capability error.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl Provider for SystemProvider {
    fn interfaces(&self, deadline: &Deadline) -> Result<Vec<Info>, Error> {
        crate::deadline::remaining(deadline).map_err(Error::interrupted)?;
        validate_snapshot(super::platform::interfaces(deadline)?)
    }
}

/// Refuses a native snapshot with an incomplete identity, an impossible
/// prefix, or a duplicate interface.
fn validate_snapshot(interfaces: Vec<Info>) -> Result<Vec<Info>, Error> {
    validation::validate_native_interfaces(interfaces).map_err(|error| Error::Discovery {
        message: "the native route adapter returned an invalid interface snapshot".to_owned(),
        source: Arc::new(error),
    })
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use packetcraftr_core::{error::Classified, frame::LinkType};

    use super::*;
    use crate::route::SystemError;

    #[test]
    fn discovery_retains_actual_snapshot_validation_failures() {
        let valid = Info {
            id: Id {
                name: "fixture0".to_owned(),
                index: 7,
            },
            description: None,
            mac_address: None,
            addresses: Vec::new(),
            flags: Flags::default(),
            mtu: None,
            capability: Capability::Layer3,
            link_type: LinkType::RAW,
        };
        assert_eq!(
            validate_snapshot(vec![valid.clone()]).unwrap(),
            std::slice::from_ref(&valid)
        );
        let mut invalid_identity = valid.clone();
        invalid_identity.id.index = 0;
        let mut invalid_prefix = valid.clone();
        invalid_prefix.addresses.push(Address {
            address: "192.0.2.1".parse().unwrap(),
            prefix_length: 33,
        });
        for snapshot in [
            vec![invalid_identity],
            vec![invalid_prefix],
            vec![valid.clone(), valid],
        ] {
            let error = validate_snapshot(snapshot).unwrap_err();
            // SystemFault already uses Arc storage; thiserror exposes that Arc as the source.
            let source = error
                .source()
                .unwrap()
                .downcast_ref::<crate::SystemFault>()
                .unwrap()
                .as_ref()
                .downcast_ref::<SystemError>()
                .unwrap();
            assert!(matches!(source, SystemError::InvalidResponse { .. }));
            assert_eq!(error.classification().code, "io.interface_discovery");
            assert_eq!(source.classification().code, "internal.route_response");
            assert_eq!(error.causes(), [source.to_string()]);
            assert!(!error.to_string().contains(&source.to_string()));
            assert!(source.source().is_none());
        }
    }

    #[test]
    fn a_spent_caller_is_refused_before_enumeration() {
        let frozen = std::time::Instant::now();
        let spent = Deadline::with_time_source(std::time::Duration::ZERO, move || frozen);
        let error = SystemProvider.interfaces(&spent).unwrap_err();
        assert!(matches!(error, Error::DeadlineExceeded { .. }));
        assert_eq!(error.classification().code, "io.deadline_exceeded");
    }
}
