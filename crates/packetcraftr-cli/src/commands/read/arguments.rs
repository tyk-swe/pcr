// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::OfflineCaptureLimitsArgs;

pub(crate) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr read capture.pcapng --max-frames 100
  packetcraftr --output ndjson read capture.pcap
  packetcraftr read capture.pcapng --filter 'tcp.flags.syn == 1 && !tcp.flags.ack' --dissect
  packetcraftr --output pcapng read capture.pcapng > validated-copy.pcapng

Capture output validates and rewrites every source record without normalization.
It requires the output format to match the input and cannot be combined with --filter."#;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Classic PCAP or PCAPNG input path.
    pub(crate) path: PathBuf,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
    /// Keep only frames matching a display filter; unavailable for capture output.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    /// Include each frame's dissected layer stack in the output.
    #[arg(long)]
    pub(crate) dissect: bool,
}
