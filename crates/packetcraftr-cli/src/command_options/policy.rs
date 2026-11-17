// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Read;
use std::path::Path;

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
    #[arg(long, value_name = "PATH", value_parser = load_scope)]
    scope_file: Option<packetcraftr::policy::Scope>,
}

impl ScopeArgs {
    pub(crate) fn apply_to(self, policy: &mut packetcraftr::policy::Policy) {
        if let Some(scope) = self.scope_file {
            *policy = scope.narrow(policy);
        }
    }

    pub(crate) fn scope(&self) -> Option<&packetcraftr::policy::Scope> {
        self.scope_file.as_ref()
    }
}

fn load_scope(path: &str) -> Result<packetcraftr::policy::Scope, String> {
    let path = Path::new(path);
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("cannot read scope file {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "scope file {} is not a regular file",
            path.display()
        ));
    }
    let file = std::fs::File::open(path)
        .map_err(|error| format!("cannot read scope file {}: {error}", path.display()))?;
    let limit = packetcraftr::policy::MAX_SCOPE_DOCUMENT_BYTES;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read scope file {}: {error}", path.display()))?;
    packetcraftr::policy::Scope::parse(&bytes).map_err(|error| error.to_string())
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

/// Identification uses numeric endpoints and constructs reviewed requests.
#[derive(Clone, Debug, Args)]
pub(crate) struct IdentificationPolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    destination_allowlist: DestinationAllowlistArgs,
    #[command(flatten)]
    pub(crate) budgets: TrafficBudgetArgs,
    #[command(flatten)]
    scope: ScopeArgs,
}

impl IdentificationPolicyArgs {
    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.destination_allowlist.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        self.scope.apply_to(&mut policy);
        policy
    }
}

impl NumericPolicyArgs {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        self.budgets.resources_with_scope(settings, &self.scope);
    }
}

impl IdentificationPolicyArgs {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        self.budgets.resources_with_scope(settings, &self.scope);
    }
}

impl HostnameResolutionArgs {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        declare!(settings, self, [max_resolved_addresses: Count @ Operation]);
    }
}

impl TrafficBudgetArgs {
    pub(crate) fn resources_with_scope(&self, settings: &mut Settings<'_>, scope: &ScopeArgs) {
        let Some(scope) = scope.scope() else {
            self.resources(settings);
            return;
        };
        let max_packets = scope
            .max_packets
            .map_or(self.max_packets, |ceiling| self.max_packets.min(ceiling));
        let max_bytes = scope
            .max_bytes
            .map_or(self.max_bytes, |ceiling| self.max_bytes.min(ceiling));
        settings.declare(crate::resources::Field {
            id: "max_packets",
            value: crate::resources::SettingValue::setting_value(&max_packets),
            unit: crate::resources::Unit::Count,
            stage: crate::resources::Stage::Operation,
            enabled: crate::resources::Enabled::Fixed(true),
            preset: None,
        });
        settings.declare(crate::resources::Field {
            id: "max_bytes",
            value: crate::resources::SettingValue::setting_value(&max_bytes),
            unit: crate::resources::Unit::Bytes,
            stage: crate::resources::Stage::Operation,
            enabled: crate::resources::Enabled::Fixed(true),
            preset: None,
        });
    }

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
        self.budgets.resources_with_scope(settings, &self.scope);
    }
}

impl HostnamePolicyArgs {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        self.hostname_resolution.resources(settings);
        self.budgets.resources_with_scope(settings, &self.scope);
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

impl SendPolicyArgs {
    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.hostname_resolution.apply_to(&mut policy);
        self.permissive_packet.apply_to(&mut policy);
        self.source_spoofing.apply_to(&mut policy);
        self.destination_allowlist.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        self.scope.apply_to(&mut policy);
        policy
    }
}

impl NumericPolicyArgs {
    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.permissive_packet.apply_to(&mut policy);
        self.source_spoofing.apply_to(&mut policy);
        self.destination_allowlist.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        self.scope.apply_to(&mut policy);
        policy
    }
}

impl HostnamePolicyArgs {
    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.hostname_resolution.apply_to(&mut policy);
        self.destination_allowlist.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        self.scope.apply_to(&mut policy);
        policy
    }
}
