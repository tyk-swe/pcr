// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::{ArgAction, ValueEnum};

use crate::command_options::{DecodeArgs, OfflineLimitsArgs};

pub(crate) const AFTER_LONG_HELP: &str = r"Expert analysis is computed offline over dissected frames; no live capture or transmission is involved.

Retransmissions (including retransmissions whose content changed) come from bounded TCP reassembly, and duplicate acknowledgments, zero windows and their probes, window-full and window-exceeded conditions, keep-alives, resets, and uncaptured earlier segments come from cross-frame header tracking. Dissection diagnostics such as checksum mismatches surface as findings under their own codes, and capture-level evidence — snaplen-truncated frames and timestamps that regress below the capture's high-water mark — surfaces as capture.* findings attributed to the frame that carried it. Stream-aware filters such as 'tcp.stream == 7' are supported.

A gate enabled by --fail-on counts every produced finding — including findings --min-severity, --code, or aggregate retention keep out of the report — and requires --minimum-frames matched frames for a conclusive verdict. A completed fail or inconclusive verdict publishes the normal report and exits 1; a pass establishes only the declared predicate over the selected evidence, not network health.

Examples:
  packetcraftr expert capture.pcapng
  packetcraftr expert capture.pcapng --filter 'tcp.stream == 3'
  packetcraftr expert capture.pcapng --min-severity warning
  packetcraftr expert capture.pcapng --code tcp.reset --code tcp.retransmission
  packetcraftr expert capture.pcapng --fail-on warning
  packetcraftr expert capture.pcapng --fail-on error --allow-findings 2 --minimum-frames 20
  packetcraftr --output ndjson expert capture.pcapng";

/// Minimum finding severity selector for `expert`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "snake_case")]
pub(crate) enum Severity {
    Info,
    Warning,
    Error,
}

impl From<Severity> for packetcraftr_core::diagnostic::Severity {
    fn from(value: Severity) -> Self {
        match value {
            Severity::Info => Self::Info,
            Severity::Warning => Self::Warning,
            Severity::Error => Self::Error,
        }
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Classic PCAP or PCAPNG input path; - reads redirected stdin.
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
    /// Enable the CI gate: after a completed analysis, fail when findings at
    /// this severity or above exceed --allow-findings.
    #[arg(long, value_enum)]
    pub(crate) fail_on: Option<Severity>,
    /// Triggering findings the gate permits before it fails (default 0).
    /// Analysis criteria, not an input bound; requires --fail-on.
    #[arg(long, requires = "fail_on", value_name = "N")]
    pub(crate) allow_findings: Option<u64>,
    /// Matched frames the gate requires for a conclusive verdict (default 1).
    /// Analysis criteria, not an input bound; requires --fail-on.
    #[arg(
        long,
        requires = "fail_on",
        value_name = "N",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub(crate) minimum_frames: Option<u64>,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}
