// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use clap::{Args, ValueEnum};
use packetcraftr::netio as net;

use super::recipe::RecipeArgs;

/// Route-selection constraints shared by live commands.
#[derive(Debug, Args)]
pub(crate) struct RouteSelectionArgs {
    /// Interface name or numeric index used as an exact route constraint.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(crate) interface: Option<String>,
    /// Interface-owned source preference used only for route selection.
    #[arg(long)]
    pub(crate) source: Option<IpAddr>,
    /// Automatic, Layer 2, or raw Layer 3 transmission intent.
    #[arg(long, value_enum, default_value_t = LinkMode::Auto)]
    pub(crate) link_mode: LinkMode,
}

impl RouteSelectionArgs {
    /// Kernel-managed TCP cannot preserve packet-oriented interface, source,
    /// or link-mode overrides from the raw UDP path.
    pub(crate) const fn supports_kernel_tcp(&self) -> bool {
        self.interface.is_none()
            && self.source.is_none()
            && matches!(self.link_mode, LinkMode::Auto)
    }
}

/// Route-selection inputs shared by packet-oriented live commands.
#[derive(Debug, Args)]
pub(crate) struct RouteArgs {
    #[command(flatten)]
    pub(crate) recipe: RecipeArgs,
    /// Explicit address or hostname when the packet has no fixed destination.
    #[arg(long, value_name = "ADDRESS_OR_HOSTNAME")]
    pub(crate) destination: Option<String>,
    #[command(flatten)]
    pub(crate) route: RouteSelectionArgs,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum LinkMode {
    #[default]
    Auto,
    Layer2,
    Layer3,
}

impl From<LinkMode> for net::link::Mode {
    fn from(value: LinkMode) -> Self {
        match value {
            LinkMode::Auto => Self::Auto,
            LinkMode::Layer2 => Self::Layer2,
            LinkMode::Layer3 => Self::Layer3,
        }
    }
}
