// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::ValueEnum;

use crate::command_options::{OfflineLimitsArgs, TlsPortArgs};

pub(crate) const AFTER_LONG_HELP: &str = r#"Statistics are computed offline over dissected frames; no live capture or transmission is involved.

Conversation (stream) indices are assigned in first-seen order over the whole capture before any --filter runs, so the index one invocation reports names the same conversation in every other invocation, and stream-aware filters such as 'tcp.stream == 7' are supported.

The fragments table reports capture-global IPv4 and IPv6 reassembly because every physical fragment must advance the same bounded state even when --filter narrows downstream frames. Its derived datagram and payload bytes are separate from the physical matched frame and byte totals.

Examples:
  packetcraftr stats capture.pcapng --table conversations
  packetcraftr stats capture.pcapng --table fragments
  packetcraftr stats capture.pcapng --table protocols --filter 'ip.src in 10.0.0.0/8'
  packetcraftr --output json stats capture.pcapng --table io --interval-ms 100"#;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum Table {
    Conversations,
    Endpoints,
    Protocols,
    Ports,
    Io,
    Fragments,
}

impl From<Table> for packetcraftr::output::stats::Table {
    fn from(value: Table) -> Self {
        match value {
            Table::Conversations => Self::Conversations,
            Table::Endpoints => Self::Endpoints,
            Table::Protocols => Self::Protocols,
            Table::Ports => Self::Ports,
            Table::Io => Self::Io,
            Table::Fragments => Self::Fragments,
        }
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Classic PCAP or PCAPNG input path.
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
    /// Maximum rows kept for the protocols, conversations, endpoints, ports,
    /// and io tables. The fragments table stays bounded by --max-ip-outcomes
    /// instead, because its accounting is capture-global.
    #[arg(long, value_name = "N")]
    pub(crate) top: Option<usize>,
    #[command(flatten)]
    pub(crate) tls_ports: TlsPortArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}
