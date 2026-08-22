// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Link-layer addressing and transmission capabilities.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    Layer2,
    Layer3,
    Layer2AndLayer3,
}

impl Capability {
    pub(crate) fn supports_layer2(self) -> bool {
        matches!(self, Self::Layer2 | Self::Layer2AndLayer3)
    }

    pub(crate) fn supports_layer3(self) -> bool {
        matches!(self, Self::Layer3 | Self::Layer2AndLayer3)
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
