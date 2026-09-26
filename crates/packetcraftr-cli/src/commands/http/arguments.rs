// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::{ApplicationLimitsArgs, DecodeArgs, OfflineLimitsArgs};

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// PCAP/PCAPNG input; - reads redirected stdin. gzip and Zstd are detected.
    pub(crate) path: PathBuf,
    /// Select a whole TCP conversation, using tcp:INDEX.
    #[arg(long)]
    pub(crate) stream: Option<String>,
    /// Additional cleartext HTTP/1 ports; repeat to add services. Ports 80 and
    /// 8080 are always inspected.
    #[arg(long = "http-port")]
    pub(crate) http_ports: Vec<u16>,
    /// Maximum counted entity bytes in one message. Bodies are discarded.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    pub(crate) max_http_body_bytes: u64,
    #[command(flatten)]
    pub(crate) application: ApplicationLimitsArgs,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}
