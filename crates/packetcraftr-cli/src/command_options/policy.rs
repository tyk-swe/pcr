// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};

use clap::Args;

use crate::resources::{Settings, declare};

#[derive(Clone, Debug, Args)]
pub(crate) struct PublicDestinationArgs {
    /// Authorize destinations classified as public: globally routable and multicast addresses.
    #[arg(long)]
    allow_public_destinations: bool,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct HostnameResolutionArgs {
    /// Authorize hostname resolution before route lookup.
    #[arg(long)]
    allow_hostname_resolution: bool,
    /// Maximum distinct addresses accepted from one hostname resolution.
    #[arg(long, default_value_t = packetcraftr::policy::DEFAULT_MAX_RESOLVED_ADDRESSES)]
    max_resolved_addresses: usize,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct PermissivePacketArgs {
    /// Policy-level opt-in for permissive or malformed live packets.
    #[arg(long)]
    allow_permissive_packets: bool,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct SourceSpoofingArgs {
    /// Policy-level opt-in for outer IP or Ethernet sources the selected interface does not own.
    #[arg(long)]
    allow_source_spoofing: bool,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct DestinationAllowlistArgs {
    /// Restrict live destinations to an exact IP address or a canonical CIDR
    /// network. Repeatable. Constraints only narrow permission; every other
    /// policy opt-in still applies.
    #[arg(long, value_name = "ADDRESS[/PREFIX]")]
    allow_destination: Vec<packetcraftr::policy::DestinationConstraint>,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct ScopeArgs {
    /// Engagement scope document (packetcraftr.scope/v1 JSON, regular file).
    /// A scope only narrows this command's policy and budgets, it never
    /// grants an opt-in the command flags did not give.
    #[arg(long, value_name = "PATH")]
    scope_file: Option<PathBuf>,
}

impl ScopeArgs {
    pub(crate) fn path(&self) -> Option<&Path> {
        self.scope_file.as_deref()
    }
}

pub(crate) trait PolicyOptions {
    fn into_base_policy(self) -> (packetcraftr::policy::Policy, ScopeArgs);
}

#[derive(Clone, Debug, Args)]
pub(crate) struct TrafficBudgetArgs {
    /// Maximum packets authorized for one operation.
    #[arg(
        long,
        default_value_t = packetcraftr::policy::DEFAULT_MAX_PACKETS_PER_OPERATION
    )]
    max_packets: u64,
    /// Maximum wire or captured bytes authorized for one operation.
    #[arg(
        long,
        default_value_t = packetcraftr::policy::DEFAULT_MAX_BYTES_PER_OPERATION
    )]
    max_bytes: u64,
}

/// `send` and `exchange`: everything a hand-built packet can ask for.
#[derive(Clone, Debug, Args)]
pub(crate) struct SendPolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    hostname_resolution: HostnameResolutionArgs,
    #[command(flatten)]
    permissive_packet: PermissivePacketArgs,
    #[command(flatten)]
    source_spoofing: SourceSpoofingArgs,
    #[command(flatten)]
    destination_allowlist: DestinationAllowlistArgs,
    #[command(flatten)]
    pub(crate) budgets: TrafficBudgetArgs,
    #[command(flatten)]
    scope: ScopeArgs,
}

/// `fuzz` and `replay`: packets addressed numerically, so no hostname
/// resolution.
#[derive(Clone, Debug, Args)]
pub(crate) struct NumericPolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    permissive_packet: PermissivePacketArgs,
    #[command(flatten)]
    source_spoofing: SourceSpoofingArgs,
    #[command(flatten)]
    destination_allowlist: DestinationAllowlistArgs,
    #[command(flatten)]
    pub(crate) budgets: TrafficBudgetArgs,
    #[command(flatten)]
    scope: ScopeArgs,
}

/// `scan`, `traceroute`, and `dns`: a named target, packets built by the
/// workflow itself.
#[derive(Clone, Debug, Args)]
pub(crate) struct HostnamePolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    hostname_resolution: HostnameResolutionArgs,
    #[command(flatten)]
    destination_allowlist: DestinationAllowlistArgs,
    #[command(flatten)]
    pub(crate) budgets: TrafficBudgetArgs,
    #[command(flatten)]
    scope: ScopeArgs,
}

/// `identify`, `audit`, and `differential-responder`: numeric endpoints, no
/// hostname resolution, and no raw packet opt-ins.
#[derive(Clone, Debug, Args)]
pub(crate) struct EndpointPolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    destination_allowlist: DestinationAllowlistArgs,
    #[command(flatten)]
    pub(crate) budgets: TrafficBudgetArgs,
    #[command(flatten)]
    scope: ScopeArgs,
}

impl PolicyOptions for EndpointPolicyArgs {
    fn into_base_policy(self) -> (packetcraftr::policy::Policy, ScopeArgs) {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.destination_allowlist.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        (policy, self.scope)
    }
}

impl NumericPolicyArgs {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        self.budgets.resources(settings);
    }
}

impl EndpointPolicyArgs {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        self.budgets.resources(settings);
    }
}

impl HostnameResolutionArgs {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        declare!(settings, self, [max_resolved_addresses: Count @ Operation]);
    }
}

impl TrafficBudgetArgs {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        declare!(settings, self, [
            max_packets: Count @ Operation,
            max_bytes: Bytes @ Operation,
        ]);
    }
}

impl SendPolicyArgs {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        self.hostname_resolution.resources(settings);
        self.budgets.resources(settings);
    }
}

impl HostnamePolicyArgs {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        self.hostname_resolution.resources(settings);
        self.budgets.resources(settings);
    }
}

impl PublicDestinationArgs {
    pub(crate) fn apply_to(self, policy: &mut packetcraftr::policy::Policy) {
        policy.allow_public_destinations = self.allow_public_destinations;
    }
}

impl HostnameResolutionArgs {
    pub(crate) fn apply_to(self, policy: &mut packetcraftr::policy::Policy) {
        policy.allow_hostname_resolution = self.allow_hostname_resolution;
        policy.max_resolved_addresses = self.max_resolved_addresses;
    }
}

impl PermissivePacketArgs {
    pub(crate) fn apply_to(self, policy: &mut packetcraftr::policy::Policy) {
        policy.allow_permissive_packets = self.allow_permissive_packets;
    }
}

impl SourceSpoofingArgs {
    pub(crate) fn apply_to(self, policy: &mut packetcraftr::policy::Policy) {
        policy.allow_source_spoofing = self.allow_source_spoofing;
    }
}

impl DestinationAllowlistArgs {
    pub(crate) fn apply_to(self, policy: &mut packetcraftr::policy::Policy) {
        policy.allowed_destinations = self.allow_destination;
    }
}

impl TrafficBudgetArgs {
    pub(crate) fn apply_to(self, policy: &mut packetcraftr::policy::Policy) {
        policy.max_packets_per_operation = self.max_packets;
        policy.max_bytes_per_operation = self.max_bytes;
    }

    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.apply_to(&mut policy);
        policy
    }
}

impl PolicyOptions for SendPolicyArgs {
    fn into_base_policy(self) -> (packetcraftr::policy::Policy, ScopeArgs) {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.hostname_resolution.apply_to(&mut policy);
        self.permissive_packet.apply_to(&mut policy);
        self.source_spoofing.apply_to(&mut policy);
        self.destination_allowlist.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        (policy, self.scope)
    }
}

impl PolicyOptions for NumericPolicyArgs {
    fn into_base_policy(self) -> (packetcraftr::policy::Policy, ScopeArgs) {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.permissive_packet.apply_to(&mut policy);
        self.source_spoofing.apply_to(&mut policy);
        self.destination_allowlist.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        (policy, self.scope)
    }
}

impl PolicyOptions for HostnamePolicyArgs {
    fn into_base_policy(self) -> (packetcraftr::policy::Policy, ScopeArgs) {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.hostname_resolution.apply_to(&mut policy);
        self.destination_allowlist.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        (policy, self.scope)
    }
}
