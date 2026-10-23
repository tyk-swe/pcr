// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::ValueEnum;
use packetcraftr_core as core;

use crate::command_options::{
    AddressFamily, CaptureLimitsArgs, HostnamePolicyArgs, MaxDurationArgs, RouteSelectionArgs,
    TimeoutArgs,
};

pub(crate) const LONG_ABOUT: &str = "Run bounded, policy-gated traceroute probes. UDP starts at --port and increments the destination port for every probe; TCP keeps --port fixed. Each hop sends its attempts as one burst and shares one --timeout-ms response window. With --multipath, --flows (default 16) selects stable flows, --attempts counts complete sweeps, destination ports stay fixed, and IPv6 flow labels stay stable. Multipath text and NDJSON publish progress; JSON collects the result. Graph edges are observed consecutive-hop adjacencies, not exhaustive ECMP discovery or proof of physical links. Unanswered probes do not measure forwarding loss. Traceroute supports text, JSON, and NDJSON output. Public destinations and hostname resolution require their respective explicit policy options.";

pub(crate) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr network traceroute 192.0.2.1 --strategy icmp
  packetcraftr --output ndjson network traceroute example.test --allow-hostname-resolution
  packetcraftr --output ndjson network traceroute 192.0.2.10 --multipath --flows 16 --attempts 3";

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum Strategy {
    #[default]
    Udp,
    Icmp,
    Tcp,
}

impl From<Strategy> for packetcraftr::probe::Transport {
    fn from(value: Strategy) -> Self {
        match value {
            Strategy::Udp => Self::Udp,
            Strategy::Icmp => Self::Icmp,
            Strategy::Tcp => Self::Tcp,
        }
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Explicit IP address or hostname to trace.
    #[arg(value_name = "ADDRESS_OR_HOSTNAME")]
    pub(crate) target: String,
    /// Trace stable flows in repeated sweeps and report observed multipath topology.
    #[arg(long)]
    pub(crate) multipath: bool,
    /// Stable flows per sweep (default 16); requires --multipath.
    #[arg(long, requires = "multipath", value_parser = clap::value_parser!(u16).range(1..=64))]
    pub(crate) flows: Option<u16>,
    /// UDP, ICMP echo, or TCP SYN probes.
    #[arg(long, value_enum, default_value_t = Strategy::Udp)]
    pub(crate) strategy: Strategy,
    /// Select the first authorized address or only one IP family.
    #[arg(long, value_enum, default_value_t = AddressFamily::Any)]
    pub(crate) family: AddressFamily,
    /// UDP base port or TCP destination port; fixed for all multipath probes.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) port: Option<u16>,
    /// UDP/TCP source port; in multipath mode, first port of the flow range.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) source_port: Option<u16>,
    /// UDP/ICMP padding; multipath adds a required correlation payload before it.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u16).range(..=i64::from(packetcraftr::traceroute::MAX_PAYLOAD_SIZE)))]
    pub(crate) payload_size: u16,
    /// Set the IPv4 Don't Fragment flag on every probe; refused for an IPv6 destination.
    #[arg(long)]
    pub(crate) dont_fragment: bool,
    /// Differentiated Services code point (0..=63) for the IPv4 TOS or IPv6 traffic class.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(..=i64::from(packetcraftr::traceroute::MAX_DSCP)))]
    pub(crate) dscp: u8,
    /// First non-zero IPv4 TTL or IPv6 hop limit.
    #[arg(long, default_value_t = packetcraftr::traceroute::DEFAULT_FIRST_HOP, value_parser = clap::value_parser!(u8).range(1..))]
    pub(crate) first_hop: u8,
    /// Last IPv4 TTL or IPv6 hop limit attempted.
    #[arg(long, default_value_t = packetcraftr::traceroute::DEFAULT_MAX_HOPS)]
    pub(crate) max_hops: u8,
    /// Attempts per hop, or complete repeated sweeps with --multipath.
    #[arg(long, default_value_t = packetcraftr::traceroute::DEFAULT_PROBES_PER_HOP)]
    pub(crate) attempts: u32,
    #[command(flatten)]
    pub(crate) timeout: TimeoutArgs,
    /// Optional average probe-rate ceiling; each hop remains one deliberate burst.
    #[arg(long)]
    pub(crate) rate: Option<u32>,
    /// Maximum generated probes across all hops.
    #[arg(long, default_value_t = core::template::DEFAULT_MAX_TEMPLATE_PACKETS)]
    pub(crate) max_probes: usize,
    #[command(flatten)]
    pub(crate) duration: MaxDurationArgs,
    /// Maximum hop-scoped undecodable exact frames retained.
    #[arg(long, default_value_t = packetcraftr::traceroute::DEFAULT_MAX_UNDECODED_FRAMES)]
    pub(crate) max_undecoded: usize,
    #[command(flatten)]
    pub(crate) route: RouteSelectionArgs,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) policy: HostnamePolicyArgs,
}
