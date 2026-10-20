// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr_core::analysis::StreamRef;

use crate::command_options::{
    ApplicationLimitsArgs, DecodeArgs, OfflineLimitsArgs, Selector, stream_selector,
};

pub(crate) const AFTER_LONG_HELP: &str = r"Offline DNS message and transaction inspection over UDP and reassembled TCP on
port 53 and each --dns-port. Pairs queries and responses by flow and DNS ID into
matched, unanswered, orphan, or duplicate transactions.

Examples:
  packetcraftr analyze dns capture.pcapng
  packetcraftr analyze dns capture.pcapng --dns-port 5353 --stream udp:3
  packetcraftr --output ndjson analyze dns - < capture.pcapng";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// PCAP/PCAPNG input; - reads redirected stdin. gzip and Zstd are detected.
    pub(crate) path: PathBuf,
    /// Keep one whole conversation: tcp:INDEX or udp:INDEX.
    #[arg(long, value_name = "TRANSPORT:INDEX", value_parser = stream_selector)]
    pub(crate) stream: Option<Selector<StreamRef>>,
    /// Additional DNS service ports; repeat to add services. Port 53 is always analyzed.
    #[arg(long = "dns-port", value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) dns_ports: Vec<u16>,
    #[command(flatten)]
    pub(crate) application: ApplicationLimitsArgs,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}
