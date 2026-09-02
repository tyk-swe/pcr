// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Link-layer addressing, VLAN tags, and transmission capabilities.

/// Maximum explicit VLAN headers carried by one planned link-layer route.
pub const MAX_VLAN_TAGS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    Layer2,
    Layer3,
    Layer2AndLayer3,
}

impl Capability {
    /// Whether an interface with this capability can transmit in `mode`.
    /// Unresolved [`Mode::Auto`] is never supported: the mode must be decided
    /// before a capability question is meaningful.
    pub const fn supports(self, mode: Mode) -> bool {
        match mode {
            Mode::Layer2 => matches!(self, Self::Layer2 | Self::Layer2AndLayer3),
            Mode::Layer3 => matches!(self, Self::Layer3 | Self::Layer2AndLayer3),
            Mode::Auto => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Auto,
    Layer2,
    Layer3,
}

pub use packetcraftr_core::packet::link::{MacAddress, VlanKind, VlanTag};
