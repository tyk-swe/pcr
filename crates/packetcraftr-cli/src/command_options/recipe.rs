// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::{Args, ValueEnum};
use packetcraftr::core;

/// Packet input shared by commands that construct or inspect a recipe.
#[derive(Debug, Args)]
pub(crate) struct RecipeArgs {
    /// Inline packet layer expression; conflicts with --packet-file.
    #[arg(long, conflicts_with = "packet_file")]
    pub(crate) packet: Option<String>,
    /// Versioned JSON or YAML packet document; conflicts with --packet.
    #[arg(long, value_name = "PATH", conflicts_with = "packet")]
    pub(crate) packet_file: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum CliBuildMode {
    #[default]
    Strict,
    Permissive,
}

impl From<CliBuildMode> for core::build::BuildMode {
    fn from(value: CliBuildMode) -> Self {
        match value {
            CliBuildMode::Strict => Self::Strict,
            CliBuildMode::Permissive => Self::Permissive,
        }
    }
}
