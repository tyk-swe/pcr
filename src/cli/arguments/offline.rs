// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Offline packet construction, dissection, and capture-reading arguments.

use std::path::PathBuf;

use clap::{Args, ValueEnum};
use packetcraftr::capture;

#[derive(Debug, Args)]
pub(in crate::cli) struct RecipeArgs {
    /// Inline packet layer expression; conflicts with --packet-file.
    #[arg(long, conflicts_with = "packet_file")]
    pub(in crate::cli) packet: Option<String>,
    /// Versioned JSON or YAML packet document; conflicts with --packet.
    #[arg(long, value_name = "PATH", conflicts_with = "packet")]
    pub(in crate::cli) packet_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(in crate::cli) struct BuildArgs {
    #[command(flatten)]
    pub(in crate::cli) recipe: RecipeArgs,
    /// Enforce protocol invariants or preserve explicitly permissive values.
    #[arg(long, value_enum, default_value_t = CliBuildMode::Strict)]
    pub(in crate::cli) mode: CliBuildMode,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(in crate::cli) enum CliBuildMode {
    #[default]
    Strict,
    Permissive,
}

#[derive(Debug, Args)]
pub(in crate::cli) struct DissectArgs {
    /// Whole-frame hexadecimal bytes.
    #[arg(long, conflicts_with = "file")]
    pub(in crate::cli) hex: Option<String>,
    /// File containing raw frame bytes.
    #[arg(long, value_name = "PATH", conflicts_with = "hex")]
    pub(in crate::cli) file: Option<PathBuf>,
    /// Open numeric DLT/link type (defaults to Ethernet/DLT 1).
    #[arg(long, default_value_t = 1)]
    pub(in crate::cli) link_type: u32,
}

#[derive(Debug, Args)]
pub(in crate::cli) struct ReadArgs {
    /// Classic PCAP or PCAPNG input path.
    pub(in crate::cli) path: PathBuf,
    /// Maximum frames read or copied from the capture stream.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_FRAMES)]
    pub(in crate::cli) max_frames: u64,
    /// Maximum aggregate captured payload bytes read or copied.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    pub(in crate::cli) max_bytes: u64,
    /// Maximum bytes accepted from any one captured frame or PCAPNG block.
    #[arg(long, default_value_t = capture::DEFAULT_SIZE_LIMIT)]
    pub(in crate::cli) max_frame_bytes: usize,
    /// Maximum PCAPNG interfaces accepted from the input.
    #[arg(long, default_value_t = capture::DEFAULT_INTERFACE_LIMIT)]
    pub(in crate::cli) max_interfaces: usize,
}
