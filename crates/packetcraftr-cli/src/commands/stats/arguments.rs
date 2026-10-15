// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::{DecodeArgs, OfflineLimitsArgs};
use crate::output;

pub(crate) const AFTER_LONG_HELP: &str = r"Offline capture statistics. Conversation indices (`tcp.stream`, `udp.stream`)
and the `fragments` table are computed capture-globally before `--filter`.

Examples:
  packetcraftr analyze stats capture.pcapng --table conversations
  packetcraftr analyze stats capture.pcapng --table overview
  packetcraftr analyze stats capture.pcapng --table conversations --sort bytes --top 10
  packetcraftr --output csv analyze stats capture.pcapng --table endpoints
  packetcraftr analyze stats capture.pcapng --table fragments
  packetcraftr analyze stats capture.pcapng --table rtt
  packetcraftr analyze stats capture.pcapng --table protocols --filter 'ip.src in 10.0.0.0/8'
  packetcraftr --output json analyze stats capture.pcapng --table io --interval-ms 100";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Classic PCAP or PCAPNG input path; - reads redirected stdin.
    pub(crate) path: PathBuf,
    /// Statistics table to compute and report.
    #[arg(long, value_enum, default_value_t = Table::Conversations)]
    pub(crate) table: Table,
    /// Keep only frames matching a display filter; stream indices stay
    /// capture-global.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    /// Bucket width of the io table in milliseconds.
    #[arg(long, default_value_t = 1_000)]
    pub(crate) interval_ms: u64,
    /// Maximum retained rows; overview defaults to five per leaderboard (zero
    /// keeps totals only). Without --sort, tables preserve their usual ordering:
    /// busiest frames then bytes for conversations/endpoints/ports, frames then
    /// name for protocols, chronological for io. Fragments use --max-ip-outcomes.
    /// Limits final rows, not keys needed for exact aggregation.
    #[arg(long, value_name = "N")]
    pub(crate) top: Option<usize>,
    /// Rank rows by descending frames or bytes before --top, breaking ties by
    /// the other metric then natural key. Overview defaults to frames.
    /// Not supported for fragments or rtt.
    #[arg(long, value_enum)]
    pub(crate) sort: Option<Sort>,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}

/// The `--table` selector for [`output::stats::Table`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Table {
    Conversations,
    Endpoints,
    Protocols,
    Ports,
    Io,
    Fragments,
    Overview,
    Rtt,
}

impl From<Table> for output::stats::Table {
    fn from(value: Table) -> Self {
        match value {
            Table::Conversations => Self::Conversations,
            Table::Endpoints => Self::Endpoints,
            Table::Protocols => Self::Protocols,
            Table::Ports => Self::Ports,
            Table::Io => Self::Io,
            Table::Fragments => Self::Fragments,
            Table::Overview => Self::Overview,
            Table::Rtt => Self::Rtt,
        }
    }
}

impl From<Table> for packetcraftr_core::analysis::stats::Table {
    fn from(value: Table) -> Self {
        match value {
            Table::Conversations => Self::Conversations,
            Table::Endpoints => Self::Endpoints,
            Table::Protocols => Self::Protocols,
            Table::Ports => Self::Ports,
            Table::Io => Self::Io,
            Table::Fragments => Self::Fragments,
            Table::Overview => Self::Overview,
            Table::Rtt => Self::Rtt,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Sort {
    Frames,
    Bytes,
}

impl Args {
    pub(crate) fn effective_top(&self) -> Option<usize> {
        self.top
            .or_else(|| (self.table == Table::Overview).then_some(5))
    }
}
