// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::Args;

use crate::command_options::{CaptureLimitArgs, HostnameTrafficPolicyArgs, RouteArgs};

pub(crate) const AFTER_LONG_HELP: &str = r#"Live capture may require native features, dependencies, and privileges.

--capture-filter <BPF> uses the stable resolver-free core of libpcap/Npcap BPF syntax and narrows what reaches PacketcraftR. Frames it rejects never enter PacketcraftR's capture queue and do not consume queue capacity or operation frame and byte budgets.

Use core BPF keywords and numeric address, network, port, and protocol operands. Other symbolic tokens are rejected before native compilation so capture filters cannot perform hidden hostname or name-database resolution; --allow-hostname-resolution does not change this rule.

--filter <EXPR> uses PacketcraftR's display-filter language after capture. Frames it rejects have already occupied PacketcraftR's capture queue and passed the native BPF filter, so they still consume operation frame and byte budgets.

The two filters use different languages and may be combined.

Examples:
  packetcraftr capture --packet 'ipv4(dst=192.0.2.53)/udp(dport=53)' --timeout-ms 1000
  packetcraftr capture \
    --packet 'ipv4(dst=192.0.2.53)/udp(dport=53)' \
    --capture-filter 'udp port 53' \
    --filter 'udp.source_port == 53'"#;

#[derive(Debug, Args)]
pub(crate) struct CaptureArgs {
    #[command(flatten)]
    pub(crate) route: RouteArgs,
    /// Overall capture window in milliseconds.
    #[arg(long, default_value_t = 3_000)]
    pub(crate) timeout_ms: u64,
    /// Resolver-free core libpcap/Npcap BPF, applied before capture.
    #[arg(long, value_name = "BPF")]
    pub(crate) capture_filter: Option<String>,
    /// Keep only frames matching PacketcraftR's post-capture display filter.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitArgs,
    #[command(flatten)]
    pub(crate) policy: HostnameTrafficPolicyArgs,
}
