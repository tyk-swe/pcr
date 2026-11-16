// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::{DecodeArgs, OfflineLimitsArgs};

pub(crate) const AFTER_LONG_HELP: &str = r"Passive inventory reads a capture file only, it sends no packet and resolves no name. Every host, protocol, and observed port in the report was present in a decoded frame, and observed ports are endpoints seen in either direction, not proof that a host listens on them. A MAC address is tied to an address only when an ARP sender mapping in the capture establishes it, so a router MAC on a routed frame is never attributed to the remote host it forwarded for.

Examples:
  packetcraftr analyze inventory capture.pcapng
  packetcraftr --output json analyze inventory capture.pcapng --filter 'ip.src in 10.0.0.0/8'";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Classic PCAP or PCAPNG input path; - reads redirected stdin.
    pub(crate) path: PathBuf,
    /// Keep only frames matching a display filter.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}
