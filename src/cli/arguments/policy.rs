// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Shared live-traffic and replay policy arguments.

use clap::Args;
use packetcraftr::{capture, client, net};

#[derive(Clone, Debug, Args)]
pub(in crate::cli) struct TrafficPolicyArgs {
    /// Deliberately authorize globally routable destinations.
    #[arg(long)]
    allow_public_destinations: bool,
    /// Deliberately authorize hostname resolution before route lookup.
    #[arg(long)]
    allow_hostname_resolution: bool,
    /// Policy-level opt-in for permissively built live packets.
    #[arg(long)]
    allow_permissive_packets: bool,
    /// Maximum packets authorized for one operation.
    #[arg(long, default_value_t = 10_000)]
    max_packets: u64,
    /// Maximum wire bytes authorized for one operation.
    #[arg(long, default_value_t = net::capture::Limits::default().max_bytes as u64)]
    max_bytes: u64,
    /// Maximum distinct addresses accepted from one hostname resolution.
    #[arg(long, default_value_t = client::policy::DEFAULT_MAX_RESOLVED_ADDRESSES)]
    max_resolved_addresses: usize,
}

#[derive(Clone, Debug, Args)]
pub(in crate::cli) struct ReplayPolicyArgs {
    /// Deliberately authorize globally routable destinations.
    #[arg(long)]
    allow_public_destinations: bool,
    /// Policy-level opt-in for malformed/permissive live bytes.
    #[arg(long)]
    allow_permissive_packets: bool,
    /// Maximum packets authorized for one operation.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_FRAMES)]
    pub(in crate::cli) max_packets: u64,
    /// Maximum wire bytes authorized for one operation.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    pub(in crate::cli) max_bytes: u64,
}

impl TrafficPolicyArgs {
    pub(in crate::cli) fn into_policy(self) -> client::policy::Policy {
        client::policy::Policy {
            allow_public_destinations: self.allow_public_destinations,
            allow_hostname_resolution: self.allow_hostname_resolution,
            allow_permissive_packets: self.allow_permissive_packets,
            max_packets_per_operation: self.max_packets,
            max_bytes_per_operation: self.max_bytes,
            max_resolved_addresses: self.max_resolved_addresses,
        }
    }
}

impl ReplayPolicyArgs {
    pub(in crate::cli) fn into_policy(self) -> client::policy::Policy {
        client::policy::Policy {
            allow_public_destinations: self.allow_public_destinations,
            allow_permissive_packets: self.allow_permissive_packets,
            max_packets_per_operation: self.max_packets,
            max_bytes_per_operation: self.max_bytes,
            ..client::policy::Policy::default()
        }
    }
}
