// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Offline packet construction, dissection, and capture-reading arguments.

use std::path::PathBuf;

use clap::{Args, ValueEnum};
use packetcraftr::capture;

use super::capture_limits::CaptureLimitArgs;
use super::sink::CaptureSinkArgs;

#[derive(Debug, Args)]
pub(crate) struct RecipeArgs {
    /// Inline packet layer expression; conflicts with --packet-file.
    #[arg(long, conflicts_with = "packet_file")]
    pub(crate) packet: Option<String>,
    /// Versioned JSON or YAML packet document; conflicts with --packet.
    #[arg(long, value_name = "PATH", conflicts_with = "packet")]
    pub(crate) packet_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct BuildArgs {
    #[command(flatten)]
    pub(crate) recipe: RecipeArgs,
    /// Enforce protocol invariants or preserve explicitly permissive values.
    #[arg(long, value_enum, default_value_t = CliBuildMode::Strict)]
    pub(crate) mode: CliBuildMode,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum CliBuildMode {
    #[default]
    Strict,
    Permissive,
}

#[derive(Debug, Args)]
pub(crate) struct DissectArgs {
    /// Whole-frame hexadecimal bytes.
    #[arg(long, conflicts_with = "file")]
    pub(crate) hex: Option<String>,
    /// File containing raw frame bytes.
    #[arg(long, value_name = "PATH", conflicts_with = "hex")]
    pub(crate) file: Option<PathBuf>,
    /// Open numeric DLT/link type (defaults to Ethernet/DLT 1).
    #[arg(long, default_value_t = 1)]
    pub(crate) link_type: u32,
}

#[derive(Debug, Args)]
pub(crate) struct ProtocolsArgs {
    /// Built-in protocol name or alias to describe.
    #[arg(value_name = "PROTOCOL")]
    pub(crate) protocol: Option<String>,
}

/// Bounds shared by every command that streams a capture file.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct CaptureStreamLimitArgs {
    /// Maximum frames accepted from the capture stream.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_FRAMES)]
    pub(crate) max_frames: u64,
    /// Maximum aggregate captured payload bytes accepted from the stream.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    pub(crate) max_bytes: u64,
    /// Maximum bytes accepted from any one captured frame or PCAPNG block.
    #[arg(long, default_value_t = capture::DEFAULT_SIZE_LIMIT)]
    pub(crate) max_frame_bytes: usize,
    /// Maximum PCAPNG interfaces accepted from the input.
    #[arg(long, default_value_t = capture::DEFAULT_INTERFACE_LIMIT)]
    pub(crate) max_interfaces: usize,
}

#[derive(Debug, Args)]
pub(crate) struct ReadArgs {
    /// Classic PCAP or PCAPNG input path.
    pub(crate) path: PathBuf,
    #[command(flatten)]
    pub(crate) limits: CaptureStreamLimitArgs,
    #[command(flatten)]
    pub(crate) sink: CaptureSinkArgs,
}

#[derive(Debug, Args)]
pub(crate) struct DecodeArgs {
    /// Classic PCAP or PCAPNG input path; conflicts with --interface.
    #[arg(required_unless_present = "interface")]
    pub(crate) path: Option<PathBuf>,
    /// Interface name or numeric index to observe live; conflicts with PATH.
    #[arg(long, value_name = "NAME_OR_INDEX", conflicts_with = "path")]
    pub(crate) interface: Option<String>,
    /// Print every decoded layer field instead of one summary line per frame.
    #[arg(long)]
    pub(crate) verbose: bool,
    /// Live capture window in milliseconds; used only with --interface.
    #[arg(long, default_value_t = 3_000)]
    pub(crate) timeout_ms: u64,
    /// Capture only traffic the interface would accept anyway.
    #[arg(long)]
    pub(crate) no_promiscuous: bool,
    #[command(flatten)]
    pub(crate) limits: CaptureStreamLimitArgs,
    #[command(flatten)]
    pub(crate) capture_limits: CaptureLimitArgs,
}
