// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::ValueEnum;

/// Address-family selection shared by target-based live workflows.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum CliAddressFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

impl From<CliAddressFamily> for packetcraftr::target::Family {
    fn from(value: CliAddressFamily) -> Self {
        match value {
            CliAddressFamily::Any => Self::Any,
            CliAddressFamily::Ipv4 => Self::Ipv4,
            CliAddressFamily::Ipv6 => Self::Ipv6,
        }
    }
}
