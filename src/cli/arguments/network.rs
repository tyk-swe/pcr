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

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(in crate::cli) enum CliReplayTiming {
    #[default]
    Original,
    Immediate,
}

#[derive(Debug, Args)]
pub(in crate::cli) struct ReplayArgs {
    /// Classic PCAP or PCAPNG input path.
    pub(in crate::cli) path: PathBuf,
    /// Exact interface name or numeric index used for every transmission.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(in crate::cli) interface: String,
    /// Automatic, Layer 2, or raw Layer 3 replay intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    pub(in crate::cli) link_mode: CliLinkMode,
    /// Preserve captured intervals or send immediately.
    #[arg(long, value_enum, default_value_t = CliReplayTiming::Original)]
    pub(in crate::cli) timing: CliReplayTiming,
    /// Positive multiplier for captured replay speed (2 means twice as fast).
    #[arg(long, conflicts_with = "rate")]
    pub(in crate::cli) speed: Option<f64>,
    /// Positive fixed frame rate, overriding captured intervals.
    #[arg(long, conflicts_with = "speed")]
    pub(in crate::cli) rate: Option<f64>,
    /// Maximum cumulative intentional replay delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(in crate::cli) max_duration_ms: u64,
    /// Maximum bytes accepted from any one captured frame or PCAPNG block.
    #[arg(long, default_value_t = capture::DEFAULT_SIZE_LIMIT)]
    pub(in crate::cli) max_frame_bytes: usize,
    /// Maximum PCAPNG interfaces accepted from the input.
    #[arg(long, default_value_t = capture::DEFAULT_INTERFACE_LIMIT)]
    pub(in crate::cli) max_interfaces: usize,
    /// Per-operation opt-in required when dissection preserves malformed bytes.
    #[arg(long)]
    pub(in crate::cli) allow_malformed_live: bool,
    #[command(flatten)]
    pub(in crate::cli) policy: ReplayPolicyArgs,
}

#[derive(Debug, Args)]
pub(in crate::cli) struct RouteArgs {
    #[command(flatten)]
    pub(in crate::cli) recipe: RecipeArgs,
    /// Explicit address or hostname when the packet has no fixed destination.
    #[arg(long, value_name = "ADDRESS_OR_HOSTNAME")]
    pub(in crate::cli) destination: Option<String>,
    /// Interface name or numeric index used as an exact route constraint.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(in crate::cli) interface: Option<String>,
    /// Interface-owned source preference used only for route selection.
    #[arg(long)]
    pub(in crate::cli) source: Option<IpAddr>,
    /// Automatic, Layer 2, or raw Layer 3 transmission intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    pub(in crate::cli) link_mode: CliLinkMode,
    #[command(flatten)]
    pub(in crate::cli) policy: TrafficPolicyArgs,
}

#[derive(Debug, Args)]
pub(in crate::cli) struct SendArgs {
    #[command(flatten)]
    pub(in crate::cli) route: RouteArgs,
    /// Strict or permissive packet construction.
    #[arg(long, value_enum, default_value_t = CliBuildMode::Strict)]
    pub(in crate::cli) mode: CliBuildMode,
    /// Per-operation opt-in required for a permissively built live frame.
    #[arg(long)]
    pub(in crate::cli) allow_permissive_live: bool,
}

#[derive(Debug, Args)]
pub(in crate::cli) struct CaptureArgs {
    #[command(flatten)]
    pub(in crate::cli) route: RouteArgs,
    /// Overall capture window in milliseconds.
    #[arg(long, default_value_t = 3_000)]
    pub(in crate::cli) timeout_ms: u64,
    #[command(flatten)]
    pub(in crate::cli) limits: CaptureLimitArgs,
}

#[derive(Debug, Args)]
pub(in crate::cli) struct ExchangeArgs {
    #[command(flatten)]
    pub(in crate::cli) send: SendArgs,
    /// Overall response window in milliseconds.
    #[arg(long, default_value_t = 3_000)]
    pub(in crate::cli) timeout_ms: u64,
    /// Maximum matched responses retained across the exchange.
    #[arg(long, default_value_t = client::exchange::DEFAULT_MAX_UNSOLICITED_FRAMES)]
    pub(in crate::cli) max_responses: usize,
    /// Maximum unsolicited decoded frames retained across the exchange.
    #[arg(long, default_value_t = client::exchange::DEFAULT_MAX_UNSOLICITED_FRAMES)]
    pub(in crate::cli) max_unsolicited: usize,
    #[command(flatten)]
    pub(in crate::cli) limits: CaptureLimitArgs,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(in crate::cli) enum CliLinkMode {
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
