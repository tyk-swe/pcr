// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::ValueEnum;

use crate::command_options::OfflineAnalysisLimitsArgs;

pub(crate) const AFTER_LONG_HELP: &str = r#"Following is computed offline over dissected frames; no live capture or transmission is involved.

The conversation index comes from the same first-seen numbering stats reports and stream filters match, so 'follow --stream tcp:7' extracts the conversation 'tcp.stream == 7' selects. The client is the endpoint that sent the conversation's first captured frame. TCP payload is reassembled in stream order per direction; UDP emits one chunk per datagram. IP-fragmented datagrams carry no conversation index and are not followed. Raw output needs a single direction, since interleaved raw bytes would be indistinguishable.

Examples:
  packetcraftr follow capture.pcapng --stream tcp:0
  packetcraftr follow capture.pcapng --stream tcp:0 --direction client --output raw > client.bin
  packetcraftr --output json follow capture.pcapng --stream udp:2
  packetcraftr --output ndjson follow capture.pcapng --stream tcp:7"#;

/// How a followed conversation's chunks are narrowed by sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum Direction {
    /// Both directions, interleaved in delivery order.
    Both,
    /// Only bytes the client — the conversation's first captured sender — sent.
    Client,
    /// Only bytes the server sent.
    Server,
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Classic PCAP or PCAPNG input path.
    pub(crate) path: PathBuf,
    /// Conversation to follow, as `tcp:INDEX` or `udp:INDEX`, using the
    /// same indices stats reports and stream filters match.
    #[arg(long, value_name = "TRANSPORT:INDEX")]
    pub(crate) stream: String,
    /// Which sender's bytes to emit.
    #[arg(long, value_enum, default_value_t = Direction::Both)]
    pub(crate) direction: Direction,
    #[command(flatten)]
    pub(crate) limits: OfflineAnalysisLimitsArgs,
}
