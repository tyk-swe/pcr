// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr_core::capture_file::{self, MAX_REORDER_FRAMES};

use crate::command_options::{CompressionArgs, OfflineCaptureLimitsArgs};

pub(crate) const AFTER_LONG_HELP: &str = r"Captures merge in timestamp order, and each input must already be ordered by timestamp unless --max-reorder-frames repairs small inversions; frames with equal timestamps keep the order the captures were named in. --order append instead writes every frame of the first capture, then the second, and so on, keeping each timestamp verbatim, so the output may be non-monotonic and is never checked for clock regression. Every input interface becomes its own interface in the one PCAPNG section written, and the destination is published only after every frame was written.

Examples:
  packetcraftr merge --write merged.pcapng first.pcapng second.pcap
  packetcraftr merge --write merged.pcapng.zst --compression zstd first.pcapng - < second.pcapng
  packetcraftr merge --write combined.pcapng --order append first.pcapng second.pcapng
  packetcraftr merge --write sorted.pcapng --max-reorder-frames 64 queue0.pcapng queue1.pcapng
  packetcraftr merge --write sorted.pcapng --max-reorder-frames 64 single.pcapng";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Captures in stable tie-breaking order; at most one may read stdin with -.
    /// At least two, or one with --max-reorder-frames.
    #[arg(required = true, num_args = 1..)]
    pub(crate) paths: Vec<PathBuf>,
    /// How frames are sequenced: chronological interleaves by timestamp;
    /// append writes each capture whole in argument order with timestamps
    /// kept verbatim, so the output may be non-monotonic. Conflicts with
    /// --max-reorder-frames.
    #[arg(long, value_enum, default_value_t)]
    pub(crate) order: OrderArg,
    /// Per-capture look-ahead window, in frames, that emits small timestamp
    /// inversions in order (0 disables it); a frame displaced further than
    /// the window still fails. The window's frames count against --max-bytes.
    /// Permits a single capture.
    #[arg(
        long,
        default_value_t = 0,
        value_parser = clap::value_parser!(u64).range(0..=MAX_REORDER_FRAMES as u64)
    )]
    pub(crate) max_reorder_frames: u64,
    /// New PCAPNG destination. Existing files are never overwritten.
    #[arg(long)]
    pub(crate) write: PathBuf,
    #[command(flatten)]
    pub(crate) compression: CompressionArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
}

/// How merged frames are sequenced across captures.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum OrderArg {
    /// Interleave by timestamp, each capture already ordered.
    #[default]
    Chronological,
    /// Concatenate captures in argument order without sorting.
    Append,
}

impl From<OrderArg> for capture_file::MergeOrder {
    fn from(order: OrderArg) -> Self {
        match order {
            OrderArg::Chronological => Self::Chronological,
            OrderArg::Append => Self::Append,
        }
    }
}
