// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::ValueEnum;
use packetcraftr_core as core;

use crate::command_options::{
    AddressFamily, CaptureLimitsArgs, HostnamePolicyArgs, MaxDurationArgs, Probing,
    RouteSelectionArgs, TimeoutArgs, Window,
};

pub(crate) const LONG_ABOUT: &str = "Run bounded, policy-gated traceroute probes. UDP starts at --port and increments the destination port for every probe; TCP keeps --port fixed. Each hop sends its attempts as one burst and shares one --timeout-ms response window. Traceroute supports text, JSON, and NDJSON output. Public destinations and hostname resolution require their respective explicit policy options.";

pub(crate) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr traceroute 192.0.2.1 --strategy icmp
  packetcraftr --output ndjson traceroute example.test --allow-hostname-resolution";

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
    /// UDP, ICMP echo, or TCP SYN probes.
    #[arg(long, value_enum, default_value_t = Strategy::Udp)]
    pub(crate) strategy: Strategy,
    /// Select the first authorized address or only one IP family.
    #[arg(long, value_enum, default_value_t = AddressFamily::Any)]
    pub(crate) family: AddressFamily,
    /// Non-zero UDP base port (incremented per probe) or fixed TCP destination port.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) port: Option<u16>,
    /// Optional non-zero UDP/TCP source port; defaults to the ephemeral base.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) source_port: Option<u16>,
    /// First non-zero IPv4 TTL or IPv6 hop limit.
    #[arg(long, default_value_t = packetcraftr::traceroute::DEFAULT_FIRST_HOP, value_parser = clap::value_parser!(u8).range(1..))]
    pub(crate) first_hop: u8,
    /// Last IPv4 TTL or IPv6 hop limit attempted.
    #[arg(long, default_value_t = packetcraftr::traceroute::DEFAULT_MAX_HOPS)]
    pub(crate) max_hops: u8,
    /// Number of attempts retained for every hop.
    #[arg(long, default_value_t = packetcraftr::traceroute::DEFAULT_PROBES_PER_HOP)]
    pub(crate) attempts: u32,
    #[command(flatten)]
    pub(crate) timeout: TimeoutArgs<HopWindow>,
    /// Optional average probe-rate ceiling; each hop remains one deliberate burst.
    #[arg(long)]
    pub(crate) rate: Option<u32>,
    /// Maximum generated probes across all hops.
    #[arg(long, default_value_t = core::template::DEFAULT_MAX_TEMPLATE_PACKETS)]
    pub(crate) max_probes: usize,
    #[command(flatten)]
    pub(crate) duration: MaxDurationArgs<Probing>,
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

/// One window per hop batch.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct HopWindow;

impl Window for HopWindow {
    const DEFAULT_MILLISECONDS: &'static str = "1000";
    const HELP: &'static str = "Shared response window for every capture-ready hop batch";
}
