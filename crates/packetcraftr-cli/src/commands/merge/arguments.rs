// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::{CompressionArgs, OfflineCaptureLimitsArgs, SavedPcapNg};

pub(crate) const AFTER_LONG_HELP: &str = r"Captures merge in timestamp order, and each input must already be ordered by timestamp; frames with equal timestamps keep the order the captures were named in. Every input interface becomes its own interface in the one PCAPNG section written, and the destination is published only after every frame was written.

Examples:
  packetcraftr merge --write merged.pcapng first.pcapng second.pcap
  packetcraftr merge --write merged.pcapng.zst --compression zstd first.pcapng - < second.pcapng";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Captures in stable tie-breaking order; at most one may read stdin with -.
    #[arg(required = true, num_args = 2..)]
    pub(crate) paths: Vec<PathBuf>,
    /// New PCAPNG destination. Existing files are never overwritten.
    #[arg(long)]
    pub(crate) write: PathBuf,
    #[command(flatten)]
    pub(crate) compression: CompressionArgs<SavedPcapNg>,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
}
