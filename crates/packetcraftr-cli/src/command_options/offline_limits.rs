// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::{Args, ValueEnum};
use packetcraftr::{analysis, analysis::pcap as capture};

/// How conflicting bytes in overlapping IP fragments are handled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum IpOverlap {
    /// Reject the datagram when overlapping bytes conflict.
    #[default]
    Reject,
    /// Preserve the conflicting bytes received first.
    First,
    /// Replace conflicting bytes with those received last.
    Last,
}

impl From<IpOverlap> for analysis::reassembly::ip::OverlapPolicy {
    fn from(value: IpOverlap) -> Self {
        match value {
            IpOverlap::Reject => Self::Reject,
            IpOverlap::First => Self::First,
            IpOverlap::Last => Self::Last,
        }
    }
}

fn default_ip_idle_expiry_ms() -> u64 {
    u64::try_from(analysis::Limits::default().ip_idle_expiry.as_millis()).unwrap_or(u64::MAX)
}

/// Capture-reader bounds shared by offline commands.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct OfflineCaptureLimitsArgs {
    /// Maximum frames read from the capture stream.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_FRAMES)]
    pub(crate) max_frames: u64,
    /// Maximum aggregate captured payload bytes read.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    pub(crate) max_bytes: u64,
    /// Maximum bytes accepted from any one captured frame or PCAPNG block.
    #[arg(long, default_value_t = capture::DEFAULT_SIZE_LIMIT)]
    pub(crate) max_frame_bytes: usize,
    /// Maximum PCAPNG interfaces accepted from the input.
    #[arg(long, default_value_t = capture::DEFAULT_INTERFACE_LIMIT)]
    pub(crate) max_interfaces: usize,
}

/// Capture and analysis bounds shared by stats, expert, follow, and TLS.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct OfflineLimitsArgs {
    #[command(flatten)]
    pub(crate) capture: OfflineCaptureLimitsArgs,
    /// Maximum distinct conversations tracked per transport.
    #[arg(long, default_value_t = analysis::Limits::default().max_flows)]
    pub(crate) max_flows: usize,
    /// Policy for conflicting bytes in overlapping IPv4 or IPv6 fragments.
    #[arg(long, value_enum, default_value_t = IpOverlap::Reject)]
    pub(crate) ip_overlap: IpOverlap,
    /// Maximum incomplete IPv4 and IPv6 datagrams retained concurrently.
    #[arg(long, default_value_t = analysis::Limits::default().max_ip_datagrams)]
    pub(crate) max_ip_datagrams: usize,
    /// Maximum physical fragments accepted for one retained IP datagram.
    #[arg(
        long,
        default_value_t = analysis::Limits::default().max_ip_fragments_per_datagram
    )]
    pub(crate) max_ip_fragments_per_datagram: usize,
    /// Maximum fragmentable payload bytes accepted for one IP datagram.
    #[arg(
        long,
        default_value_t = analysis::Limits::default().max_ip_bytes_per_datagram
    )]
    pub(crate) max_ip_bytes_per_datagram: usize,
    /// Maximum retained IP, derived cascade, and metadata bytes.
    #[arg(
        long,
        default_value_t = analysis::Limits::default().max_ip_reassembly_bytes
    )]
    pub(crate) max_ip_reassembly_bytes: usize,
    /// Maximum per-datagram IP outcomes retained for aggregate reporting.
    #[arg(long, default_value_t = analysis::Limits::default().max_ip_outcomes)]
    pub(crate) max_ip_outcomes: usize,
    /// IP datagram inactivity interval in capture-time milliseconds.
    #[arg(long, default_value_t = default_ip_idle_expiry_ms())]
    pub(crate) ip_idle_expiry_ms: u64,
    /// Maximum analysis run time in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(crate) max_duration_ms: u64,
}
