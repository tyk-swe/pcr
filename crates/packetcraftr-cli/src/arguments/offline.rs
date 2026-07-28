// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Offline packet construction, dissection, and capture-reading arguments.

use std::path::PathBuf;

use clap::{Args, ValueEnum};
use packetcraftr::{analysis, capture};

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
    /// Emit the dissection only when the frame matches a display filter.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct ProtocolsArgs {
    /// Built-in protocol name or alias to describe.
    #[arg(value_name = "PROTOCOL")]
    pub(crate) protocol: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CliStatsTable {
    Conversations,
    Endpoints,
    Protocols,
    Ports,
    Io,
}

#[derive(Debug, Args)]
pub(crate) struct StatsArgs {
    /// Classic PCAP or PCAPNG input path.
    pub(crate) path: PathBuf,
    /// Statistics table to compute and report.
    #[arg(long, value_enum, default_value_t = CliStatsTable::Conversations)]
    pub(crate) table: CliStatsTable,
    /// Keep only frames matching a display filter; stream indices stay
    /// capture-global.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    /// Bucket width of the io table in milliseconds.
    #[arg(long, default_value_t = 1_000)]
    pub(crate) interval_ms: u64,
    /// Maximum frames read from the capture stream.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_FRAMES)]
    pub(crate) max_frames: u64,
    /// Maximum aggregate captured payload bytes read.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    pub(crate) max_bytes: u64,
    /// Maximum bytes accepted from any one captured frame or PCAPNG block.
    #[arg(long, default_value_t = capture::DEFAULT_SIZE_LIMIT)]
    pub(crate) max_frame_bytes: usize,
    /// Maximum PCAPNG interfaces accepted from the input.
    #[arg(long, default_value_t = capture::DEFAULT_INTERFACE_LIMIT)]
    pub(crate) max_interfaces: usize,
    /// Maximum distinct conversations tracked per transport.
    #[arg(long, default_value_t = analysis::Limits::default().max_flows)]
    pub(crate) max_flows: usize,
    /// Maximum analysis run time in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(crate) max_duration_ms: u64,
}

#[derive(Debug, Args)]
pub(crate) struct ExpertArgs {
    /// Classic PCAP or PCAPNG input path.
    pub(crate) path: PathBuf,
    /// Keep only frames matching a display filter; stream indices stay
    /// capture-global.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    /// Maximum frames read from the capture stream.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_FRAMES)]
    pub(crate) max_frames: u64,
    /// Maximum aggregate captured payload bytes read.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    pub(crate) max_bytes: u64,
    /// Maximum bytes accepted from any one captured frame or PCAPNG block.
    #[arg(long, default_value_t = capture::DEFAULT_SIZE_LIMIT)]
    pub(crate) max_frame_bytes: usize,
    /// Maximum PCAPNG interfaces accepted from the input.
    #[arg(long, default_value_t = capture::DEFAULT_INTERFACE_LIMIT)]
    pub(crate) max_interfaces: usize,
    /// Maximum distinct conversations tracked per transport.
    #[arg(long, default_value_t = analysis::Limits::default().max_flows)]
    pub(crate) max_flows: usize,
    /// Maximum analysis run time in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(crate) max_duration_ms: u64,
}

/// How a followed conversation's chunks are narrowed by sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum CliFollowDirection {
    /// Both directions, interleaved in delivery order.
    Both,
    /// Only bytes the client — the conversation's first captured sender —
    /// sent.
    Client,
    /// Only bytes the server sent.
    Server,
}

#[derive(Debug, Args)]
pub(crate) struct FollowArgs {
    /// Classic PCAP or PCAPNG input path.
    pub(crate) path: PathBuf,
    /// Conversation to follow, as `tcp:INDEX` or `udp:INDEX`, using the
    /// same indices stats reports and stream filters match.
    #[arg(long, value_name = "TRANSPORT:INDEX")]
    pub(crate) stream: String,
    /// Which sender's bytes to emit.
    #[arg(long, value_enum, default_value_t = CliFollowDirection::Both)]
    pub(crate) direction: CliFollowDirection,
    /// Maximum frames read from the capture stream.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_FRAMES)]
    pub(crate) max_frames: u64,
    /// Maximum aggregate captured payload bytes read.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    pub(crate) max_bytes: u64,
    /// Maximum bytes accepted from any one captured frame or PCAPNG block.
    #[arg(long, default_value_t = capture::DEFAULT_SIZE_LIMIT)]
    pub(crate) max_frame_bytes: usize,
    /// Maximum PCAPNG interfaces accepted from the input.
    #[arg(long, default_value_t = capture::DEFAULT_INTERFACE_LIMIT)]
    pub(crate) max_interfaces: usize,
    /// Maximum distinct conversations tracked per transport.
    #[arg(long, default_value_t = analysis::Limits::default().max_flows)]
    pub(crate) max_flows: usize,
    /// Maximum analysis run time in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(crate) max_duration_ms: u64,
}

#[derive(Debug, Args)]
pub(crate) struct ReadArgs {
    /// Classic PCAP or PCAPNG input path.
    pub(crate) path: PathBuf,
    /// Maximum frames read or copied from the capture stream.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_FRAMES)]
    pub(crate) max_frames: u64,
    /// Maximum aggregate captured payload bytes read or copied.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    pub(crate) max_bytes: u64,
    /// Maximum bytes accepted from any one captured frame or PCAPNG block.
    #[arg(long, default_value_t = capture::DEFAULT_SIZE_LIMIT)]
    pub(crate) max_frame_bytes: usize,
    /// Maximum PCAPNG interfaces accepted from the input.
    #[arg(long, default_value_t = capture::DEFAULT_INTERFACE_LIMIT)]
    pub(crate) max_interfaces: usize,
    /// Keep only frames matching a display filter; implies dissection.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    /// Include each frame's dissected layer stack in the output.
    #[arg(long)]
    pub(crate) dissect: bool,
}
