// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::marker::PhantomData;

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

pub(crate) trait Budget: Clone + fmt::Debug + Default {
    const PACKETS_HELP: &'static str;
    const BYTES_HELP: &'static str;
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Transmitted;

impl Budget for Transmitted {
    const PACKETS_HELP: &'static str =
        "Maximum transmitted packets or bounded socket traffic units authorized";
    const BYTES_HELP: &'static str =
        "Maximum wire or socket application bytes authorized for one operation";
}

// clap shares one `default_value_t` static across every `TrafficBudgetArgs<B>`,
// so these defaults cannot vary by `B`.
#[derive(Clone, Debug, Args)]
pub(crate) struct TrafficBudgetArgs<B: Budget> {
    #[arg(
        long,
        default_value_t = packetcraftr::policy::DEFAULT_MAX_PACKETS_PER_OPERATION,
        help = B::PACKETS_HELP
    )]
    max_packets: u64,
    #[arg(
        long,
        default_value_t = packetcraftr::policy::DEFAULT_MAX_BYTES_PER_OPERATION,
        help = B::BYTES_HELP
    )]
    max_bytes: u64,
    #[arg(skip)]
    budget: PhantomData<B>,
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
    budgets: TrafficBudgetArgs<Transmitted>,
}

/// `fuzz` and `replay`: packets addressed numerically, so no hostname
/// resolution.
#[derive(Clone, Debug, Args)]
pub(crate) struct NumericPolicyArgs<B: Budget> {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    permissive_packet: PermissivePacketArgs,
    #[command(flatten)]
    source_spoofing: SourceSpoofingArgs,
    #[command(flatten)]
    destination_allowlist: DestinationAllowlistArgs,
    #[command(flatten)]
    budgets: TrafficBudgetArgs<B>,
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
    budgets: TrafficBudgetArgs<Transmitted>,
}

impl HostnameResolutionArgs {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        declare!(settings, self, [max_resolved_addresses: Count @ Operation]);
    }
}

impl<B: Budget> TrafficBudgetArgs<B> {
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

impl<B: Budget> NumericPolicyArgs<B> {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
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

impl<B: Budget> TrafficBudgetArgs<B> {
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
        policy
    }
}

impl<B: Budget> NumericPolicyArgs<B> {
    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.permissive_packet.apply_to(&mut policy);
        self.source_spoofing.apply_to(&mut policy);
        self.destination_allowlist.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
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
        policy
    }
}

#[cfg(test)]
mod tests {

    use clap::Parser as _;

    use crate::cli::Cli;
    use crate::commands::CommandLine;
    use packetcraftr::policy::{
        DEFAULT_MAX_BYTES_PER_OPERATION, DEFAULT_MAX_PACKETS_PER_OPERATION,
    };

    #[test]
    fn destination_allowlists_parse_and_reject_malformed_entries() {
        let cli = Cli::try_parse_from([
            "packetcraftr",
            "scan",
            "192.0.2.1",
            "--ports",
            "80",
            "--allow-destination",
            "192.0.2.0/24",
            "--allow-destination",
            "2001:db8::1",
        ])
        .expect("allowlist entries parse");
        let CommandLine::Scan(scan) = cli.command else {
            panic!("scan command")
        };
        assert_eq!(scan.policy.into_policy().allowed_destinations.len(), 2);

        for bad in ["192.0.2.1/24", "10.0.0.0/33", "not-an-address"] {
            assert!(
                Cli::try_parse_from([
                    "packetcraftr",
                    "scan",
                    "192.0.2.1",
                    "--ports",
                    "80",
                    "--allow-destination",
                    bad,
                ])
                .is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    fn budgets_for(arguments: &[&str]) -> (u64, u64) {
        let cli = Cli::try_parse_from(arguments).expect("command must parse with defaults");
        let policy = match cli.command {
            CommandLine::Send(send) => send.send.policy.into_policy(),
            CommandLine::Exchange(exchange) => exchange.send.policy.into_policy(),
            CommandLine::Scan(scan) => scan.policy.into_policy(),
            CommandLine::Fuzz(fuzz) => fuzz.policy.into_policy(),
            CommandLine::Replay(replay) => replay.policy.into_policy(),
            CommandLine::Capture(capture) => capture.budgets.into_policy(),
            other => panic!("unbudgeted command {other:?}"),
        };
        (
            policy.max_packets_per_operation,
            policy.max_bytes_per_operation,
        )
    }

    #[test]
    fn every_budgeted_command_starts_from_the_shared_defaults() {
        let shared = (
            DEFAULT_MAX_PACKETS_PER_OPERATION,
            DEFAULT_MAX_BYTES_PER_OPERATION,
        );
        for arguments in [
            &["packetcraftr", "send", "--packet", "raw(hex=00)"][..],
            &["packetcraftr", "exchange", "--packet", "raw(hex=00)"],
            &["packetcraftr", "scan", "192.0.2.1"],
            &["packetcraftr", "fuzz", "--packet", "raw(hex=00)"],
            &[
                "packetcraftr",
                "replay",
                "capture.pcapng",
                "--interface",
                "7",
            ],
            &["packetcraftr", "capture", "--interface", "7"],
        ] {
            assert_eq!(budgets_for(arguments), shared, "{arguments:?}");
        }
    }
}
