// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::{CaptureReaderBoundsArgs, LinkMode, ReplayPolicyArgs};
use clap::ValueEnum;

pub(crate) const AFTER_LONG_HELP: &str = r#"Replay is policy-gated and may require native features, dependencies, and privileges.

Frames a --filter rejects are skipped before authorization, so they are never policy-checked or transmitted, but they still count against the operation's frame budget. With original/scaled timing, the delay before a kept frame spans any skipped frames in between.

--bps counts exact submitted frame bytes, with no synthetic link overhead. The first selected frame is immediate; subsequent targets use the cumulative bytes already sent. Filtered frames do not consume bit-rate timing. Scheduled duration and transmitted bytes describe the run; the requested bit rate is not a throughput guarantee.

Examples:
  packetcraftr replay capture.pcapng --interface eth0 --timing immediate
  packetcraftr replay capture.pcap --interface 2 --rate 100
  packetcraftr replay capture.pcap --interface 2 --bps 8000000
  packetcraftr replay capture.pcap --interface eth0 --filter 'udp && ip.dst == 10.0.0.2'"#;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum Timing {
    #[default]
    Original,
    Immediate,
}

impl From<Timing> for packetcraftr::replay::Timing {
    fn from(value: Timing) -> Self {
        match value {
            Timing::Original => Self::Original,
            Timing::Immediate => Self::Immediate,
        }
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Classic PCAP or PCAPNG input path.
    pub(crate) path: PathBuf,
    /// Exact interface name or numeric index used for every transmission.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(crate) interface: String,
    /// Automatic, Layer 2, or raw Layer 3 replay intent.
    #[arg(long, value_enum, default_value_t = LinkMode::Auto)]
    pub(crate) link_mode: LinkMode,
    /// Preserve captured intervals or send immediately.
    #[arg(long, value_enum, default_value_t = Timing::Original)]
    pub(crate) timing: Timing,
    /// Positive multiplier for captured replay speed (2 means twice as fast).
    #[arg(long, conflicts_with = "rate")]
    pub(crate) speed: Option<f64>,
    /// Positive fixed frame rate in frames per second, overriding captured
    /// intervals; unlike the live commands' `--rate` ceiling, replay sends at
    /// exactly this rate.
    #[arg(long, conflicts_with = "speed")]
    pub(crate) rate: Option<f64>,
    /// Positive integer bit rate, counting submitted frame bytes without
    /// synthetic media overhead. Scheduling is best effort; first frame is immediate.
    #[arg(long, conflicts_with_all = ["rate", "speed"], value_parser = clap::value_parser!(u64).range(1..))]
    pub(crate) bps: Option<u64>,
    /// Maximum cumulative intentional replay delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(crate) max_duration_ms: u64,
    #[command(flatten)]
    pub(crate) reader: CaptureReaderBoundsArgs,
    /// Per-operation opt-in required for a permissively built or malformed live frame.
    #[arg(long, alias = "allow-malformed-live")]
    pub(crate) allow_permissive_live: bool,
    /// Replay only frames matching a display filter; skipped frames are never
    /// authorized or transmitted.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    #[command(flatten)]
    pub(crate) policy: ReplayPolicyArgs,
}
