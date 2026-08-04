// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::Args;
use packetcraftr::capture;

pub(super) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr read capture.pcapng --max-frames 100
  packetcraftr --output ndjson read capture.pcap
  packetcraftr read capture.pcapng --filter 'tcp.flags.syn == 1 && !tcp.flags.ack' --dissect
  packetcraftr --output pcapng read capture.pcapng --filter 'ip.src in 10.0.0.0/8' > subset.pcapng"#;

#[derive(Debug, Args)]
pub(crate) struct ReadArgs {
    /// Classic PCAP or PCAPNG input path.
    pub(crate) path: PathBuf,
    /// Maximum frames read or copied from the capture stream.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_FRAMES)]
    pub(crate) max_frames: u64,
    /// Maximum aggregate captured payload bytes read or copied.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    pub(crate) max_bytes: u64,
    /// Maximum bytes accepted from any one captured frame or PCAPNG block.
    #[arg(long, default_value_t = capture::DEFAULT_SIZE_LIMIT)]
    pub(crate) max_frame_bytes: usize,
    /// Maximum PCAPNG interfaces accepted from the input.
    #[arg(long, default_value_t = capture::DEFAULT_INTERFACE_LIMIT)]
    pub(crate) max_interfaces: usize,
    /// Keep only frames matching a display filter; implies dissection.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    /// Include each frame's dissected layer stack in the output.
    #[arg(long)]
    pub(crate) dissect: bool,
}
