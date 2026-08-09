// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Interface discovery and portable interface descriptions.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::Error;
use super::link::{Capability, MacAddress};

pub(crate) use self::Info as InterfaceInfo;
#[cfg(any(
    feature = "native-interfaces",
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos", windows)
    )
))]
pub(crate) use self::{Address as InterfaceAddress, Flags as InterfaceFlags};

/// Stable operating-system interface identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Id {
    pub name: String,
    pub index: u32,
}

/// Portable address assigned to an interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address {
    pub address: IpAddr,
    pub prefix_length: u8,
}

/// Portable interface state exposed by every platform adapter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Flags {
    pub up: bool,
    pub broadcast: bool,
    pub loopback: bool,
    pub point_to_point: bool,
    pub multicast: bool,
}

/// Platform-neutral interface description.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Info {
    pub id: Id,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<MacAddress>,
    pub addresses: Vec<Address>,
    pub flags: Flags,
    /// Native MTU, if reported by the adapter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    pub capability: Capability,
    pub link_type: packetcraftr_packet::frame::LinkType,
}

/// Enumerates interfaces without exposing a native handle or wrapper type.
pub trait Provider: Send + Sync {
    fn interfaces(&self) -> Result<Vec<Info>, Error>;
}

/// Provider backed by the adapter selected for the current target and feature
/// set. Portable profiles return a typed capability error.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl Provider for SystemProvider {
    fn interfaces(&self) -> Result<Vec<Info>, Error> {
        super::platform::system_interfaces()
    }
}
