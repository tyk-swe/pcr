// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Route, transmission, capture, exchange, and replay arguments.

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Args, ValueEnum};
use packetcraftr::{capture, client, net};

use super::capture_limits::CaptureLimitArgs;
use super::offline::{CliBuildMode, RecipeArgs};
use super::policy::{ReplayPolicyArgs, TrafficPolicyArgs};
use super::sink::CaptureSinkArgs;

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
    #[command(flatten)]
    pub(crate) policy: ReplayPolicyArgs,
    #[command(flatten)]
    pub(crate) sink: CaptureSinkArgs,
}

#[derive(Debug, Args)]
pub(crate) struct RouteArgs {
    #[command(flatten)]
    pub(crate) recipe: RecipeArgs,
    /// Explicit address or hostname when the packet has no fixed destination.
    #[arg(long, value_name = "ADDRESS_OR_HOSTNAME")]
    pub(crate) destination: Option<String>,
    /// Interface name or numeric index used as an exact route constraint.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(crate) interface: Option<String>,
    /// Interface-owned source preference used only for route selection.
    #[arg(long)]
    pub(crate) source: Option<IpAddr>,
    /// Automatic, Layer 2, or raw Layer 3 transmission intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    pub(crate) link_mode: CliLinkMode,
    #[command(flatten)]
    pub(crate) policy: TrafficPolicyArgs,
}

#[derive(Debug, Args)]
pub(crate) struct SendArgs {
    #[command(flatten)]
    pub(crate) route: RouteArgs,
    /// Strict or permissive packet construction.
    #[arg(long, value_enum, default_value_t = CliBuildMode::Strict)]
    pub(crate) mode: CliBuildMode,
    /// Per-operation opt-in required for a permissively built live frame.
    #[arg(long)]
    pub(crate) allow_permissive_live: bool,
    #[command(flatten)]
    pub(crate) sink: CaptureSinkArgs,
}

#[derive(Debug, Args)]
pub(crate) struct CaptureArgs {
    #[command(flatten)]
    pub(crate) route: RouteArgs,
    /// Overall capture window in milliseconds.
    #[arg(long, default_value_t = 3_000)]
    pub(crate) timeout_ms: u64,
    /// Capture only traffic the interface would accept anyway.
    #[arg(long)]
    pub(crate) no_promiscuous: bool,
    /// Kernel capture filter in libpcap syntax, such as 'udp port 53'.
    #[arg(long, value_name = "FILTER")]
    pub(crate) bpf: Option<String>,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitArgs,
    #[command(flatten)]
    pub(crate) sink: CaptureSinkArgs,
}

#[derive(Debug, Args)]
pub(crate) struct ExchangeArgs {
    #[command(flatten)]
    pub(crate) send: SendArgs,
    /// Overall response window in milliseconds.
    #[arg(long, default_value_t = 3_000)]
    pub(crate) timeout_ms: u64,
    /// Maximum matched responses retained across the exchange.
    #[arg(long, default_value_t = client::exchange::DEFAULT_MAX_UNSOLICITED_FRAMES)]
    pub(crate) max_responses: usize,
    /// Maximum unsolicited decoded frames retained across the exchange.
    #[arg(long, default_value_t = client::exchange::DEFAULT_MAX_UNSOLICITED_FRAMES)]
    pub(crate) max_unsolicited: usize,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitArgs,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum CliLinkMode {
    #[default]
    Auto,
    Layer2,
    Layer3,
}

impl From<CliLinkMode> for net::link::Mode {
    fn from(value: CliLinkMode) -> Self {
        match value {
            CliLinkMode::Auto => Self::Auto,
            CliLinkMode::Layer2 => Self::Layer2,
            CliLinkMode::Layer3 => Self::Layer3,
        }
    }
}
