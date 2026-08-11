// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::Args;
use packetcraftr::{analysis::pcap as capture, netio as net};

#[derive(Clone, Debug, Args)]
struct PublicDestinationArgs {
    /// Authorize destinations classified as public: globally routable and multicast addresses.
    #[arg(long)]
    allow_public_destinations: bool,
}

#[derive(Clone, Debug, Args)]
struct HostnameResolutionArgs {
    /// Authorize hostname resolution before route lookup.
    #[arg(long)]
    allow_hostname_resolution: bool,
    /// Maximum distinct addresses accepted from one hostname resolution.
    #[arg(long, default_value_t = packetcraftr::policy::DEFAULT_MAX_RESOLVED_ADDRESSES)]
    max_resolved_addresses: usize,
}

#[derive(Clone, Debug, Args)]
struct PermissivePacketArgs {
    /// Policy-level opt-in for permissive or malformed live packets.
    #[arg(long)]
    allow_permissive_packets: bool,
}

#[derive(Clone, Debug, Args)]
struct TrafficBudgetArgs {
    /// Maximum packets authorized for one operation.
    #[arg(long, default_value_t = 10_000)]
    max_packets: u64,
    /// Maximum wire bytes authorized for one operation.
    #[arg(long, default_value_t = net::capture::Limits::default().max_bytes as u64)]
    max_bytes: u64,
}

#[derive(Clone, Debug, Args)]
struct ReplayTrafficBudgetArgs {
    /// Maximum packets authorized for one operation.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_FRAMES)]
    max_packets: u64,
    /// Maximum wire bytes authorized for one operation.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    max_bytes: u64,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct PlanPolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    hostname_resolution: HostnameResolutionArgs,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct SendPolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    hostname_resolution: HostnameResolutionArgs,
    #[command(flatten)]
    permissive_packet: PermissivePacketArgs,
    #[command(flatten)]
    budgets: TrafficBudgetArgs,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct HostnameTrafficPolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    hostname_resolution: HostnameResolutionArgs,
    #[command(flatten)]
    budgets: TrafficBudgetArgs,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct ReplayPolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    permissive_packet: PermissivePacketArgs,
    #[command(flatten)]
    budgets: ReplayTrafficBudgetArgs,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct FuzzPolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    permissive_packet: PermissivePacketArgs,
    #[command(flatten)]
    budgets: TrafficBudgetArgs,
}

impl PublicDestinationArgs {
    fn apply_to(self, policy: &mut packetcraftr::policy::Policy) {
        policy.allow_public_destinations = self.allow_public_destinations;
    }
}

impl HostnameResolutionArgs {
    fn apply_to(self, policy: &mut packetcraftr::policy::Policy) {
        policy.allow_hostname_resolution = self.allow_hostname_resolution;
        policy.max_resolved_addresses = self.max_resolved_addresses;
    }
}

impl PermissivePacketArgs {
    fn apply_to(self, policy: &mut packetcraftr::policy::Policy) {
        policy.allow_permissive_packets = self.allow_permissive_packets;
    }
}

impl TrafficBudgetArgs {
    fn apply_to(self, policy: &mut packetcraftr::policy::Policy) {
        policy.max_packets_per_operation = self.max_packets;
        policy.max_bytes_per_operation = self.max_bytes;
    }
}

impl ReplayTrafficBudgetArgs {
    fn apply_to(self, policy: &mut packetcraftr::policy::Policy) {
        policy.max_packets_per_operation = self.max_packets;
        policy.max_bytes_per_operation = self.max_bytes;
    }
}

impl PlanPolicyArgs {
    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.hostname_resolution.apply_to(&mut policy);
        policy
    }
}

impl SendPolicyArgs {
    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.hostname_resolution.apply_to(&mut policy);
        self.permissive_packet.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        policy
    }
}

impl HostnameTrafficPolicyArgs {
    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.hostname_resolution.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        policy
    }
}

impl ReplayPolicyArgs {
    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.permissive_packet.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        policy
    }
}

impl FuzzPolicyArgs {
    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.permissive_packet.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        policy
    }
}
