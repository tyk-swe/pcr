// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use crate::interface::Id as InterfaceId;
use crate::link::Capability;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::Classified;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::MacAddress;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Host,
    Link,
    Private,
    Global,
    Multicast,
    Unspecified,
}

/// Why the operating system selected a route. The concrete next hop remains
/// in [`Decision::next_hop`]; this enum is stable across native APIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionReason {
    Local,
    OnLink,
    Broadcast,
    Gateway,
    InterfaceOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub interface: InterfaceId,
    /// Interface-owned source MAC used for Layer 2 materialization.
    pub source_mac: Option<MacAddress>,
    pub selected_source: Option<IpAddr>,
    pub preferred_source: Option<IpAddr>,
    pub next_hop: Option<IpAddr>,
    pub selection_reason: SelectionReason,
    pub destination_scope: Scope,
    pub mtu: u32,
    pub capability: Capability,
    pub link_type: LinkType,
}

/// Passive route and interface lookups.
///
/// Provider errors classify themselves, so injected providers choose their
/// own stable codes without exposing native operating-system error types.
/// Both lookups follow the [deadline convention](crate::deadline): they stop
/// when the caller's `deadline` is cancelled or spent.
pub trait Provider: Send + Sync {
    type Error: Classified + Send + Sync + 'static;

    /// Passively selects a consistent per-exchange route snapshot without neighbor traffic.
    /// `preferred_source` constrains interface selection but never rewrites packet source.
    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
        deadline: &Deadline,
    ) -> Result<Decision, Self::Error>;

    /// Passively selects an interface for destination-free packets without default-route IP
    /// lookup or neighbor traffic. Defaults to `None` for IP-only providers.
    fn lookup_interface(
        &self,
        _interface: &InterfaceId,
        _deadline: &Deadline,
    ) -> Result<Option<Decision>, Self::Error> {
        Ok(None)
    }
}
