// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod error;
pub(crate) mod validation;

use std::net::IpAddr;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::Source;
use packetcraftr_core::packet::MacAddress;

use super::link::Capability;

pub use error::Error;
pub(crate) use error::discovery_classification;

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
    pub mtu: Option<u32>,
    pub capability: Capability,
    pub link_type: packetcraftr_core::frame::LinkType,
}

pub trait Provider: Send + Sync {
    fn interfaces(&self, deadline: &Deadline) -> Result<Vec<Info>, Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl SystemProvider {
    /// Enumerates interfaces with their IPv6 indexes for scoped addresses.
    /// Interfaces without an IPv6 index are omitted on Windows.
    pub fn ipv6_interfaces(&self, deadline: &Deadline) -> Result<Vec<Info>, Error> {
        deadline.live_remaining().map_err(Error::interrupted)?;
        validate_snapshot(super::platform::ipv6_interfaces(deadline)?)
    }
}

impl Provider for SystemProvider {
    fn interfaces(&self, deadline: &Deadline) -> Result<Vec<Info>, Error> {
        deadline.live_remaining().map_err(Error::interrupted)?;
        validate_snapshot(super::platform::interfaces(deadline)?)
    }
}

/// Linux and macOS sends verify by name lookup instead, so a build with only
/// Layer 3 there has no caller.
#[cfg(native_send)]
#[cfg_attr(not(native_layer2), allow(dead_code))]
pub(crate) fn current(expected: &Id, deadline: &Deadline) -> Result<Info, crate::Error> {
    deadline.live_remaining().map_err(Error::interrupted)?;
    let mut interfaces = validate_snapshot(super::platform::interfaces_for_identity(
        expected, deadline,
    )?)?;
    if let Some(position) = interfaces
        .iter()
        .position(|interface| interface.id == *expected)
    {
        return Ok(interfaces.swap_remove(position));
    }
    let actual = interfaces
        .iter()
        .find(|interface| interface.id.index == expected.index)
        .map(|interface| interface.id.name.clone());
    Err(identity_changed(expected, actual.as_deref()))
}

#[cfg(native_send)]
pub(crate) fn identity_changed(expected: &Id, actual: Option<&str>) -> crate::Error {
    let actual = actual.map_or_else(
        || "no current interface".to_owned(),
        |name| format!("{name} (index {})", expected.index),
    );
    crate::Error::Device {
        interface: expected.name.clone(),
        message: format!(
            "interface identity changed before native I/O: expected {} (index {}), found {actual}",
            expected.name, expected.index
        ),
        source: None,
    }
}

fn validate_snapshot(interfaces: Vec<Info>) -> Result<Vec<Info>, Error> {
    validation::validate_native_interfaces(interfaces).map_err(|error| Error::Discovery {
        message: "the native route backend returned an invalid interface snapshot".to_owned(),
        source: Source::new(error),
    })
}

#[cfg(test)]
mod tests {

    use packetcraftr_core::error::Classified;

    use super::*;

    #[test]
    fn a_spent_caller_is_refused_before_enumeration() {
        let frozen = std::time::Instant::now();
        let spent = Deadline::with_time_source(std::time::Duration::ZERO, move || frozen);
        let error = SystemProvider.interfaces(&spent).unwrap_err();
        assert!(matches!(error, Error::DeadlineExceeded { .. }));
        assert_eq!(error.classification().code, "io.deadline_exceeded");
    }
}
