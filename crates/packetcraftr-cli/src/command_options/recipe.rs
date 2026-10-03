// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, ValueEnum};
use packetcraftr_core as core;

/// Packet input shared by commands that construct or inspect a recipe.
#[derive(Debug, Args)]
pub(crate) struct RecipeArgs {
    /// Inline packet layer expression; conflicts with --packet-file.
    #[arg(long, conflicts_with = "packet_file")]
    pub(crate) packet: Option<String>,
    /// Versioned JSON or YAML packet document; conflicts with --packet.
    #[arg(long, value_name = "PATH", conflicts_with = "packet")]
    pub(crate) packet_file: Option<PathBuf>,
    /// Literal bytes for a recipe field loaded from a file, e.g.
    /// raw.bytes=data.bin or 2.bytes=data.bin. The layer is a protocol name
    /// with an optional #occurrence, or a zero-based index. The field must be
    /// bytes-typed and empty in the recipe; the file stays inside the packet
    /// input limit.
    #[arg(long, value_name = "SELECTOR=PATH")]
    pub(crate) payload_file: Option<OsString>,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum BuildMode {
    #[default]
    Strict,
    Permissive,
}

impl From<BuildMode> for core::codec::Mode {
    fn from(value: BuildMode) -> Self {
        match value {
            BuildMode::Strict => Self::Strict,
            BuildMode::Permissive => Self::Permissive,
        }
    }
}
