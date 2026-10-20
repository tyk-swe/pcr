// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::{ArgAction, ValueEnum};

use crate::command_options::{DecodeArgs, OfflineLimitsArgs};

pub(crate) const AFTER_LONG_HELP: &str = r"Offline protocol health analysis over dissected frames.

Reports TCP retransmission/fast-retransmission/out-of-order/gap findings,
duplicate ACKs, window conditions, handshake/reset/close anomalies, decode
diagnostics, and capture truncation or clock regressions. Findings are judged on
frames passing --filter; filter by stream (e.g. 'tcp.stream == 3') or host pair
to keep both directions of a conversation.

Examples:
  packetcraftr analyze expert capture.pcapng
  packetcraftr analyze expert capture.pcapng --filter 'tcp.stream == 3'
  packetcraftr analyze expert capture.pcapng --min-severity warning
  packetcraftr analyze expert capture.pcapng --code tcp.reset --code tcp.retransmission
  packetcraftr --output ndjson analyze expert capture.pcapng";

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
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}
