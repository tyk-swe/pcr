// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::{Args, ValueEnum};
use packetcraftr::capture;

use super::policy::ReplayPolicyArgs;
use super::route::CliLinkMode;

pub(super) const AFTER_LONG_HELP: &str = r#"Replay is policy-gated and may require native features, dependencies, and privileges.

Frames a --filter rejects are skipped before authorization, so they are never policy-checked or transmitted, but they still count against the operation's frame budget. Transmitted frames keep their original spacing: the delay before a kept frame spans any skipped frames in between.

Examples:
  packetcraftr replay capture.pcapng --interface eth0 --timing immediate
  packetcraftr replay capture.pcap --interface 2 --rate 100
  packetcraftr replay capture.pcap --interface eth0 --filter 'udp && ip.dst == 10.0.0.2'"#;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum CliReplayTiming {
    #[default]
    Original,
    Immediate,
}

#[derive(Debug, Args)]
pub(crate) struct ReplayArgs {
    /// Classic PCAP or PCAPNG input path.
    pub(crate) path: PathBuf,
    /// Exact interface name or numeric index used for every transmission.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(crate) interface: String,
    /// Automatic, Layer 2, or raw Layer 3 replay intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    pub(crate) link_mode: CliLinkMode,
    /// Preserve captured intervals or send immediately.
    #[arg(long, value_enum, default_value_t = CliReplayTiming::Original)]
    pub(crate) timing: CliReplayTiming,
    /// Positive multiplier for captured replay speed (2 means twice as fast).
    #[arg(long, conflicts_with = "rate")]
    pub(crate) speed: Option<f64>,
    /// Positive fixed frame rate, overriding captured intervals.
    #[arg(long, conflicts_with = "speed")]
    pub(crate) rate: Option<f64>,
    /// Maximum cumulative intentional replay delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(crate) max_duration_ms: u64,
    /// Maximum bytes accepted from any one captured frame or PCAPNG block.
    #[arg(long, default_value_t = capture::DEFAULT_SIZE_LIMIT)]
    pub(crate) max_frame_bytes: usize,
    /// Maximum PCAPNG interfaces accepted from the input.
    #[arg(long, default_value_t = capture::DEFAULT_INTERFACE_LIMIT)]
    pub(crate) max_interfaces: usize,
    /// Per-operation opt-in required when dissection preserves malformed bytes.
    #[arg(long)]
    pub(crate) allow_malformed_live: bool,
    /// Replay only frames matching a display filter; skipped frames are never
    /// authorized or transmitted.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    #[command(flatten)]
    pub(crate) policy: ReplayPolicyArgs,
}
