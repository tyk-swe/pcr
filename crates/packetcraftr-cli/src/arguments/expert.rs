// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::Args;

use super::offline_limits::OfflineAnalysisLimits;

pub(super) const AFTER_LONG_HELP: &str = r#"Expert analysis is computed offline over dissected frames; no live capture or transmission is involved.

Retransmissions (including retransmissions whose content changed) come from bounded TCP reassembly, and duplicate acknowledgments, zero windows and their probes, window-full and window-exceeded conditions, keep-alives, resets, and uncaptured earlier segments come from cross-frame header tracking. Dissection diagnostics such as checksum mismatches surface as findings under their own codes. Stream-aware filters such as 'tcp.stream == 7' are supported.

Examples:
  packetcraftr expert capture.pcapng
  packetcraftr expert capture.pcapng --filter 'tcp.stream == 3'
  packetcraftr --output ndjson expert capture.pcapng"#;

#[derive(Debug, Args)]
pub(crate) struct ExpertArgs {
    /// Classic PCAP or PCAPNG input path.
    pub(crate) path: PathBuf,
    /// Keep only frames matching a display filter; stream indices stay
    /// capture-global.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    #[command(flatten)]
    pub(crate) limits: OfflineAnalysisLimits,
}
