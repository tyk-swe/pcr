// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::Args;
use packetcraftr::{analysis, analysis::pcap as capture};

/// Capture-reader bounds shared by offline commands.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct OfflineCaptureLimits {
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
}

/// Capture and analysis bounds shared by stats, expert, and follow.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct OfflineAnalysisLimits {
    #[command(flatten)]
    pub(crate) capture: OfflineCaptureLimits,
    /// Maximum distinct conversations tracked per transport.
    #[arg(long, default_value_t = analysis::Limits::default().max_flows)]
    pub(crate) max_flows: usize,
    /// Maximum conversations indexed before a stream-field filter runs.
    #[arg(long, default_value_t = analysis::Limits::default().max_indexed_flows)]
    pub(crate) max_indexed_flows: usize,
    /// Maximum analysis run time in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(crate) max_duration_ms: u64,
}
