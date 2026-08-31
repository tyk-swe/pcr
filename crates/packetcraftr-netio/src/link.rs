// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Link-layer addressing, VLAN tags, and transmission capabilities.

use std::fmt;

use packetcraftr_core::semantics;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.0;
        write!(
            formatter,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            value[0], value[1], value[2], value[3], value[4], value[5]
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VlanKind {
    Ieee8021Q,
    Ieee8021Ad,
}

impl VlanKind {
    pub const fn ether_type(self) -> u16 {
        match self {
            Self::Ieee8021Q => 0x8100,
            Self::Ieee8021Ad => 0x88a8,
        }
    }
}

impl From<semantics::VlanKind> for VlanKind {
    fn from(value: semantics::VlanKind) -> Self {
        match value {
            semantics::VlanKind::Ieee8021Q => Self::Ieee8021Q,
            semantics::VlanKind::Ieee8021Ad => Self::Ieee8021Ad,
        }
    }
}

/// One fixed-width tag copied from a packet's explicit VLAN stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VlanTag {
    pub kind: VlanKind,
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
}

impl From<semantics::VlanMetadata> for VlanTag {
    fn from(value: semantics::VlanMetadata) -> Self {
        Self {
            kind: value.kind.into(),
            priority: value.priority,
            drop_eligible: value.drop_eligible,
            vlan_id: value.vlan_id,
        }
    }
}
