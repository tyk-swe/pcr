// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::ValueEnum;

/// Address-family selection shared by target-based live workflows.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum AddressFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

impl From<AddressFamily> for packetcraftr::target::Family {
    fn from(value: AddressFamily) -> Self {
        match value {
            AddressFamily::Any => Self::Any,
            AddressFamily::Ipv4 => Self::Ipv4,
            AddressFamily::Ipv6 => Self::Ipv6,
        }
    }
}
