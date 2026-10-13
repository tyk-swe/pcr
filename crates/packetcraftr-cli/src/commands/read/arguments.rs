// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::{
    CompressionArgs, DecodeArgs, EpochBoundsArgs, FrameSelectionArgs, OfflineCaptureLimitsArgs,
    TreeArgs,
};

pub(crate) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr read capture.pcapng --max-frames 100
  packetcraftr --output ndjson read - < capture.pcapng
  packetcraftr read capture.pcapng --filter 'tcp.flags.syn == 1 && !tcp.flags.ack' --dissect
  packetcraftr --output pcapng read capture.pcapng --filter 'udp.port == 53' > dns.pcapng
  packetcraftr --output pcapng read - --normalize --filter 'udp' < capture.pcap > selected.pcapng
  packetcraftr read capture.pcapng --start-epoch 1700000000.5 --stop-epoch 1700000060
  packetcraftr read capture.pcapng --frames 1-100,250,300- --every 5
  packetcraftr read capture.pcapng --filter 'dns' --dissect --tree

Selection (--start-epoch/--stop-epoch, --frames, --every, --filter) preserves
one-based source frame numbers; skipped frames still count toward --max-frames
and --max-bytes, and epoch bounds exclude untimestamped frames.

Capture output preserves the input format unless --normalize is set. --normalize
writes matching physical frames into one PCAPNG section or a single-interface
classic PCAP (requiring one link type, timestamps, and no direction metadata),
discarding comments and unknown blocks/options while rejecting declared FCS.

See `packetcraftr topics filters` for the --filter language.";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Select a registered field; repeat to preserve the requested column order.
    #[arg(long = "field", value_name = "PATH", conflicts_with_all = ["normalize", "dissect", "tree"])]
    pub(crate) fields: Vec<String>,
    /// Maximum encoded projection data bytes across all rows (excluding envelopes).
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    pub(crate) max_projection_bytes: usize,

    #[command(flatten)]
    pub(crate) compression: CompressionArgs,

    /// Classic PCAP or PCAPNG input path; - reads redirected stdin.
    pub(crate) path: PathBuf,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) epoch: EpochBoundsArgs,
    #[command(flatten)]
    pub(crate) selection: FrameSelectionArgs,
    /// Keep only frames matching a display filter.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    /// Export a new PCAPNG or single-interface PCAP from physical frames, discarding source-only metadata.
    #[arg(long)]
    pub(crate) normalize: bool,
    /// Include each frame's dissected layer stack in the output.
    #[arg(long)]
    pub(crate) dissect: bool,
    #[command(flatten)]
    pub(crate) tree: TreeArgs,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
}
