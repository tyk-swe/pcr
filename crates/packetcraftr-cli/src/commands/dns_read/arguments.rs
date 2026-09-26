// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr_core::analysis::StreamRef;

use crate::command_options::{
    ApplicationLimitsArgs, DecodeArgs, OfflineLimitsArgs, stream_selector,
};

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// PCAP/PCAPNG input; - reads redirected stdin. gzip and Zstd are detected.
    pub(crate) path: PathBuf,
    /// Keep one whole conversation: tcp:INDEX or udp:INDEX.
    #[arg(long, value_name = "TRANSPORT:INDEX", value_parser = stream_selector)]
    pub(crate) stream: Option<StreamRef>,
    /// Additional DNS service ports; repeat to add services. Port 53 is always analyzed.
    #[arg(long = "dns-port")]
    pub(crate) dns_ports: Vec<u16>,
    #[command(flatten)]
    pub(crate) application: ApplicationLimitsArgs,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}
