// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::{Args, ValueEnum};
use packetcraftr::core;

use crate::command_options::{
    CaptureLimitArgs, CliAddressFamily, HostnameTrafficPolicyArgs, RouteSelectionArgs,
};

pub(crate) const LONG_ABOUT: &str = "Run bounded, policy-gated traceroute probes. UDP starts at --port and increments the destination port for every probe; TCP keeps --port fixed. Each hop sends its attempts as one burst and shares one --timeout-ms response window. Traceroute supports text, JSON, and NDJSON output. Public destinations and hostname resolution require their respective explicit policy options.";

pub(crate) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr traceroute 192.0.2.1 --strategy icmp
  packetcraftr --output ndjson traceroute example.test --allow-hostname-resolution"#;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum CliTracerouteStrategy {
    #[default]
    Udp,
    Icmp,
    Tcp,
}

impl From<CliTracerouteStrategy> for packetcraftr::traceroute::Strategy {
    fn from(value: CliTracerouteStrategy) -> Self {
        match value {
            CliTracerouteStrategy::Udp => Self::Udp,
            CliTracerouteStrategy::Icmp => Self::Icmp,
            CliTracerouteStrategy::Tcp => Self::Tcp,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct TracerouteArgs {
    /// Explicit IP address or hostname to trace.
    #[arg(value_name = "ADDRESS_OR_HOSTNAME")]
    pub(crate) target: String,
    /// UDP, ICMP echo, or TCP SYN probes.
    #[arg(long, value_enum, default_value_t = CliTracerouteStrategy::Udp)]
    pub(crate) strategy: CliTracerouteStrategy,
    /// Select the first authorized address or only one IP family.
    #[arg(long, value_enum, default_value_t = CliAddressFamily::Any)]
    pub(crate) family: CliAddressFamily,
    /// Non-zero UDP base port (incremented per probe) or fixed TCP destination port.
    #[arg(long)]
    pub(crate) port: Option<u16>,
    /// First non-zero IPv4 TTL or IPv6 hop limit.
    #[arg(long, default_value_t = packetcraftr::traceroute::DEFAULT_TRACEROUTE_FIRST_HOP)]
    pub(crate) first_hop: u8,
    /// Last IPv4 TTL or IPv6 hop limit attempted.
    #[arg(long, default_value_t = packetcraftr::traceroute::DEFAULT_TRACEROUTE_MAX_HOPS)]
    pub(crate) max_hops: u8,
    /// Number of attempts retained for every hop.
    #[arg(long, default_value_t = packetcraftr::traceroute::DEFAULT_TRACEROUTE_PROBES_PER_HOP)]
    pub(crate) attempts: u32,
    /// Shared response window for every capture-ready hop batch.
    #[arg(long, default_value_t = 1_000)]
    pub(crate) timeout_ms: u64,
    /// Optional average probe-rate ceiling; each hop remains one deliberate burst.
    #[arg(long)]
    pub(crate) rate: Option<u32>,
    /// Maximum generated probes across all hops.
    #[arg(long, default_value_t = core::template::DEFAULT_MAX_TEMPLATE_PACKETS)]
    pub(crate) max_probes: usize,
    /// Maximum worst-case timeout plus intentional rate delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(crate) max_duration_ms: u64,
    /// Maximum hop-scoped undecodable exact frames retained.
    #[arg(long, default_value_t = packetcraftr::traceroute::DEFAULT_MAX_UNDECODED_TRACEROUTE_FRAMES)]
    pub(crate) max_undecoded: usize,
    #[command(flatten)]
    pub(crate) route: RouteSelectionArgs,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitArgs,
    #[command(flatten)]
    pub(crate) policy: HostnameTrafficPolicyArgs,
}
