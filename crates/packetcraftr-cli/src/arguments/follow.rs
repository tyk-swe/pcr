// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::{Args, ValueEnum};

use super::offline_limits::OfflineAnalysisLimits;

pub(super) const AFTER_LONG_HELP: &str = r#"Following is computed offline over dissected frames; no live capture or transmission is involved.

The conversation index comes from the same first-seen numbering stats reports and stream filters match, so 'follow --stream tcp:7' extracts the conversation 'tcp.stream == 7' selects. The client is the endpoint that sent the conversation's first captured frame. TCP payload is reassembled in stream order per direction; UDP emits one chunk per datagram. IP-fragmented datagrams carry no conversation index and are not followed. Raw output needs a single direction, since interleaved raw bytes would be indistinguishable.

Examples:
  packetcraftr follow capture.pcapng --stream tcp:0
  packetcraftr follow capture.pcapng --stream tcp:0 --direction client --output raw > client.bin
  packetcraftr --output json follow capture.pcapng --stream udp:2"#;

/// How a followed conversation's chunks are narrowed by sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum CliFollowDirection {
    /// Both directions, interleaved in delivery order.
    Both,
    /// Only bytes the client — the conversation's first captured sender — sent.
    Client,
    /// Only bytes the server sent.
    Server,
}

#[derive(Debug, Args)]
pub(crate) struct FollowArgs {
    /// Classic PCAP or PCAPNG input path.
    pub(crate) path: PathBuf,
    /// Conversation to follow, as `tcp:INDEX` or `udp:INDEX`, using the
    /// same indices stats reports and stream filters match.
    #[arg(long, value_name = "TRANSPORT:INDEX")]
    pub(crate) stream: String,
    /// Which sender's bytes to emit.
    #[arg(long, value_enum, default_value_t = CliFollowDirection::Both)]
    pub(crate) direction: CliFollowDirection,
    #[command(flatten)]
    pub(crate) limits: OfflineAnalysisLimits,
}
