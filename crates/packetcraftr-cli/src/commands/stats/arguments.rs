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
  packetcraftr analyze stats capture.pcapng --sort duration --min-frames 10 --top 10
  packetcraftr --output csv analyze stats capture.pcapng --table endpoints
  packetcraftr analyze stats capture.pcapng --table fragments
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
    /// natural order for conversations/endpoints/ports unless --top is given,
    /// frames then name for protocols, chronological for io.
    /// Fragments use --max-ip-outcomes.
    /// Limits final rows, not keys needed for exact aggregation.
    #[arg(long, value_name = "N")]
    pub(crate) top: Option<usize>,
    /// Keep rows with at least N frames before sorting and --top. Directional
    /// counts are combined; overview totals are unchanged. Not supported for fragments.
    #[arg(long, value_name = "N")]
    pub(crate) min_frames: Option<u64>,
    /// Rank rows by descending frames or bytes before --top, breaking ties by
    /// the other metric then natural key. Overview defaults to frames.
    /// Duration ranks conversations only, longest first, then frames and bytes.
    /// Not supported for fragments.
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
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Sort {
    Frames,
    Bytes,
    Duration,
}

impl Args {
    pub(super) fn validate_selection(&self) -> Result<(), crate::errors::CliError> {
        use crate::errors::CliError;
        use packetcraftr_core::error::Kind;
        if self.table == Table::Fragments {
            if self.top.is_some() || self.min_frames.is_some() {
                return Err(CliError::new(
                    Kind::Usage,
                    "--top and --min-frames are not supported for fragments; use --max-ip-outcomes to limit retained outcomes",
                ));
            }
            if self.sort.is_some() {
                return Err(CliError::new(
                    Kind::Usage,
                    "--sort is not supported for fragments",
                ));
            }
        }
        if self.sort == Some(Sort::Duration) && self.table != Table::Conversations {
            return Err(CliError::new(
                Kind::Usage,
                "--sort duration requires --table conversations",
            ));
        }
        Ok(())
    }

    pub(crate) fn effective_top(&self) -> Option<usize> {
        self.top
            .or_else(|| (self.table == Table::Overview).then_some(5))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestArgs {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn unsupported_table_options_fail_validation() {
        for flags in [
            vec!["--table", "fragments", "--top", "0"],
            vec!["--table", "fragments", "--min-frames", "0"],
            vec!["--table", "fragments", "--sort", "frames"],
            vec!["--table", "overview", "--sort", "duration"],
            vec!["--table", "io", "--sort", "duration"],
        ] {
            let args = TestArgs::parse_from(["stats", "missing.pcap"].into_iter().chain(flags));
            assert!(args.args.validate_selection().is_err());
        }
        let args = TestArgs::parse_from([
            "stats",
            "missing.pcap",
            "--sort",
            "duration",
            "--min-frames",
            "10",
        ]);
        assert!(args.args.validate_selection().is_ok());
    }
}
