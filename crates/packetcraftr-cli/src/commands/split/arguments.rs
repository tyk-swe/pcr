// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ops::RangeInclusive;
use std::path::PathBuf;

use crate::command_options::{
    CompressionArgs, Destination, MaxDurationArgs, OfflineCaptureLimitsArgs, RunTime,
};

pub(crate) const AFTER_LONG_HELP: &str = r"Split writes each contiguous physical-frame range of the input as its own same-format capture under --write-dir, named part-NNNNNN.pcap or part-NNNNNN.pcapng with .gz or .zst when --compression selects one. The detected container format decides the extension, never the source filename. Every part holds the complete source metadata: header, interface descriptions, and non-packet records describe the source capture, including interface statistics. Stream conversations and IP datagrams may span part boundaries; export produces dependency-complete selections instead. Files are staged, sealed, and published in index order without overwriting existing files, and the whole report is prepared before the first file is committed.

Examples:
  packetcraftr split capture.pcapng --frames-per-file 1000 --write-dir parts
  packetcraftr split capture.pcap.gz --frames-per-file 500 --write-dir parts --compression zstd
  packetcraftr --output json split - --frames-per-file 100 --write-dir parts < capture.pcapng";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Classic PCAP or PCAPNG input path; - reads redirected stdin. Input
    /// compression is detected and does not affect output compression.
    pub(crate) path: PathBuf,
    /// Physical frames per generated part, at least 1. The final part holds
    /// the remainder, and an empty capture produces one metadata-only part.
    #[arg(long, value_name = "N")]
    pub(crate) frames_per_file: u64,
    /// Existing directory the fixed part-NNNNNN files are written into. No
    /// existing file is overwritten and the directory is never removed.
    #[arg(long, value_name = "DIR")]
    pub(crate) write_dir: PathBuf,
    /// Maximum generated parts, including an empty capture's one
    /// metadata-only part, within 1..=4096.
    #[arg(long, default_value_t = 256)]
    pub(crate) max_files: usize,
    /// Maximum retained header plus non-packet records across the source,
    /// cumulative, within 1..=4096.
    #[arg(long, default_value_t = 4096)]
    pub(crate) max_split_metadata_records: usize,
    /// Maximum retained raw header/metadata bytes across the source plus 128
    /// bytes of bookkeeping per record, cumulative, within 1..=67108864.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    pub(crate) max_split_metadata_bytes: usize,
    /// Maximum decoded part bytes and, separately, encoded saved-file bytes,
    /// each cumulative across all parts.
    #[arg(long, default_value_t = 256 * 1024 * 1024)]
    pub(crate) max_split_output_bytes: u64,
    #[command(flatten)]
    pub(crate) compression: CompressionArgs<SavedParts>,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) duration: MaxDurationArgs<SplitRunTime>,
}

/// Every generated part, in either source container format.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SavedParts;

impl Destination for SavedParts {
    const HELP: &'static str = "Compression applied independently to each saved capture part";
}

/// The split run deadline, an ordinary `cli.error` parse failure outside
/// `1..=3,600,000` before any source I/O.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SplitRunTime;

impl RunTime for SplitRunTime {
    const HELP: &'static str = "Maximum split run time in milliseconds";
    const PARSED: RangeInclusive<u64> = 1..=crate::command_options::MAX_DURATION_MILLISECONDS;
}
