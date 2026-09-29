// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr_core::analysis::StreamRef;

use crate::command_options::{
    ApplicationLimitsArgs, DecodeArgs, OfflineLimitsArgs, Selector, stream_selector,
};

pub(crate) const AFTER_LONG_HELP: &str = r"HTTP/1 messages are read offline from reassembled TCP streams on ports 80 and 8080 and every --http-port; nothing is transmitted. Bodies are counted against --max-http-body-bytes, and each response names the request it answers when both were captured. --write streams complete dechunked entities into a new directory; incomplete bodies receive diagnostics and no complete-object file. --decode-content retains encoded files and adds decoded gzip or zlib-wrapped deflate files under decoded and cumulative export budgets.

--stream keeps one TCP conversation, as tcp:INDEX. Text prints start lines and header fields escaped; JSON and NDJSON keep their exact bytes as hex.

Examples:
  packetcraftr http capture.pcapng
  packetcraftr http capture.pcapng --http-port 8000 --stream tcp:2
  packetcraftr --output json http capture.pcapng";

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
    /// Export complete dechunked HTTP entities to a new directory.
    #[arg(long)]
    pub(crate) write: Option<PathBuf>,
    /// Decode gzip or zlib-wrapped deflate alongside the exact encoded entity.
    #[arg(long, requires = "write")]
    pub(crate) decode_content: bool,
    /// Maximum encoded and decoded entity bytes exported across the operation.
    #[arg(long, default_value_t = 256 * 1024 * 1024, value_parser = clap::value_parser!(u64).range(1..))]
    pub(crate) max_http_export_bytes: u64,
    /// Maximum entity bytes in one message, also limiting decoded content.
    #[arg(long, default_value_t = 16 * 1024 * 1024, value_parser = clap::value_parser!(u64).range(1..=256 * 1024 * 1024))]
    pub(crate) max_http_body_bytes: u64,
    #[command(flatten)]
    pub(crate) application: ApplicationLimitsArgs,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}
