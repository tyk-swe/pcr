// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::{Args, ValueEnum};

use crate::command_options::OfflineAnalysisLimits;

pub(crate) const AFTER_LONG_HELP: &str = r#"Statistics are computed offline over dissected frames; no live capture or transmission is involved.

Conversation (stream) indices are assigned in first-seen order over the whole capture before any --filter runs, so the index one invocation reports names the same conversation in every other invocation, and stream-aware filters such as 'tcp.stream == 7' are supported.

Examples:
  packetcraftr stats capture.pcapng --table conversations
  packetcraftr stats capture.pcapng --table protocols --filter 'ip.src in 10.0.0.0/8'
  packetcraftr --output json stats capture.pcapng --table io --interval-ms 100"#;

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
    #[command(flatten)]
    pub(crate) limits: OfflineAnalysisLimits,
}
