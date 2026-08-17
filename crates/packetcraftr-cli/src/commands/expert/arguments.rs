// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::{ArgAction, ValueEnum};

use crate::command_options::OfflineAnalysisLimitsArgs;

pub(crate) const AFTER_LONG_HELP: &str = r#"Expert analysis is computed offline over dissected frames; no live capture or transmission is involved.

Retransmissions (including retransmissions whose content changed) come from bounded TCP reassembly, and duplicate acknowledgments, zero windows and their probes, window-full and window-exceeded conditions, keep-alives, resets, and uncaptured earlier segments come from cross-frame header tracking. Dissection diagnostics such as checksum mismatches surface as findings under their own codes. Stream-aware filters such as 'tcp.stream == 7' are supported.

Examples:
  packetcraftr expert capture.pcapng
  packetcraftr expert capture.pcapng --filter 'tcp.stream == 3'
  packetcraftr expert capture.pcapng --min-severity warning
  packetcraftr expert capture.pcapng --code tcp.reset --code tcp.retransmission
  packetcraftr --output ndjson expert capture.pcapng"#;

/// Minimum finding severity selector for `expert`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[value(rename_all = "snake_case")]
pub(crate) enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub(crate) const fn rank(self) -> u8 {
        match self {
            Self::Info => 1,
            Self::Warning => 2,
            Self::Error => 3,
        }
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Classic PCAP or PCAPNG input path.
    pub(crate) path: PathBuf,
    /// Keep only frames matching a display filter; stream indices stay
    /// capture-global.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    /// Minimum finding severity to include in output.
    #[arg(long, value_enum, default_value_t = Severity::Info)]
    pub(crate) min_severity: Severity,
    /// Keep only findings matching an exact code; repeatable.
    #[arg(long = "code", value_name = "CODE", action = ArgAction::Append)]
    pub(crate) codes: Vec<String>,
    #[command(flatten)]
    pub(crate) limits: OfflineAnalysisLimitsArgs,
}
