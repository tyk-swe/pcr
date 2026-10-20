// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr_core::analysis::StreamRef;

use crate::command_options::{
    ApplicationLimitsArgs, DecodeArgs, OfflineLimitsArgs, Selector, stream_selector,
};

pub(crate) const AFTER_LONG_HELP: &str = r"Offline HTTP/1 inspection over reassembled TCP streams on ports 80, 8080, and
each --http-port. Bodies are counted against --max-http-body-bytes and discarded.

Examples:
  packetcraftr analyze http capture.pcapng
  packetcraftr analyze http capture.pcapng --http-port 8000 --stream tcp:2
  packetcraftr --output json analyze http capture.pcapng";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// PCAP/PCAPNG input; - reads redirected stdin. gzip and Zstd are detected.
    pub(crate) path: PathBuf,
    /// Select a whole TCP conversation, using tcp:INDEX.
    #[arg(long, value_name = "TRANSPORT:INDEX", value_parser = stream_selector)]
    pub(crate) stream: Option<Selector<StreamRef>>,
    /// Additional cleartext HTTP/1 ports; repeat to add services. Ports 80 and
    /// 8080 are always inspected.
    #[arg(long = "http-port", value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) http_ports: Vec<u16>,
    /// Maximum counted entity bytes in one message. Bodies are discarded.
    #[arg(long, default_value_t = 16 * 1024 * 1024, value_parser = clap::value_parser!(u64).range(1..=256 * 1024 * 1024))]
    pub(crate) max_http_body_bytes: u64,
    #[command(flatten)]
    pub(crate) application: ApplicationLimitsArgs,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}
