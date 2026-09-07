// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Link-layer addressing, VLAN tags, and transmission capabilities.

use std::fmt;

/// Maximum explicit VLAN headers carried by one planned link-layer route.
pub const MAX_VLAN_TAGS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Layer2,
    Layer3,
    #[serde(rename = "layer2_and3")]
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Auto,
    Layer2,
    Layer3,
}

pub use packetcraftr_core::packet::link::{MacAddress, VlanKind, VlanTag};

impl Capability {
    /// The serialized spelling, so a text renderer and the JSON document never
    /// name the same capability two ways.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Layer2 => "layer2",
            Self::Layer3 => "layer3",
            Self::Layer2AndLayer3 => "layer2_and3",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Mode {
    /// The serialized spelling, so a text renderer and the JSON document never
    /// name the same mode two ways.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Layer2 => "layer2",
            Self::Layer3 => "layer3",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
