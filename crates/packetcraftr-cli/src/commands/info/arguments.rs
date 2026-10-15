// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::OfflineCaptureLimitsArgs;

pub(crate) const AFTER_LONG_HELP: &str = r"Describe a capture file: its container format, compression, byte order, timestamp
bounds, interfaces with their link types and snapshot lengths, PCAPNG section and
block inventory, and frame and byte totals. Reads every record without decoding
any packet; the frame and byte ceilings of --max-frames and --max-bytes bound the
pass and fail it rather than truncating the report.

Examples:
  packetcraftr files info capture.pcapng
  packetcraftr files info - < capture.pcap.gz
  packetcraftr --output json files info capture.pcap";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// PCAP/PCAPNG input; - reads redirected stdin. gzip and Zstd are detected
    #[arg(required = true)]
    pub(crate) path: PathBuf,
    #[command(flatten)]
    pub(crate) limits: OfflineCaptureLimitsArgs,
}
