// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy opt-ins and budgets, as clap groups.
//!
//! Every command builds its policy from the same leaf groups below, so one
//! flag means one thing everywhere. The command-shaped groups at the bottom
//! are the combinations the commands actually flatten.

use std::fmt;
use std::marker::PhantomData;

use clap::Args;
use packetcraftr::analysis::pcap as capture;
use packetcraftr::netio as net;

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

/// What `--max-packets` and `--max-bytes` default to, and what they are called,
/// for one kind of operation.
///
/// Replay starts from far larger defaults than a hand-built send, and a
/// receive-only command's help must not mention transmission.
pub(crate) trait Budget: Clone + fmt::Debug + Default {
    fn max_packets() -> u64;
    fn max_bytes() -> u64;
    const PACKETS_HELP: &'static str;
    const BYTES_HELP: &'static str;
}

/// Packets this operation puts on the wire itself.
#[derive(Clone, Debug, Default)]
pub(crate) struct Transmitted;

/// Packets one hand-built operation may put on the wire before the policy
/// stops it.
pub(crate) const DEFAULT_TRANSMITTED_PACKETS: u64 = 10_000;

/// The byte ceiling the capture defaults publish, as the policy counts it.
fn default_limit_bytes() -> u64 {
    u64::try_from(net::capture::Limits::default().max_bytes).expect("default max bytes fits u64")
}

impl Budget for Transmitted {
    fn max_packets() -> u64 {
        DEFAULT_TRANSMITTED_PACKETS
    }

    fn max_bytes() -> u64 {
        default_limit_bytes()
    }

    const PACKETS_HELP: &'static str =
        "Maximum transmitted packets or bounded socket traffic units authorized";
    const BYTES_HELP: &'static str =
        "Maximum wire or socket application bytes authorized for one operation";
}

/// Frames read from a capture file and replayed onto the wire, which run to
/// far larger counts than a hand-built operation.
#[derive(Clone, Debug, Default)]
pub(crate) struct Streamed;

impl Budget for Streamed {
    fn max_packets() -> u64 {
        capture::DEFAULT_STREAM_FRAMES
    }

    fn max_bytes() -> u64 {
        capture::DEFAULT_STREAM_BYTES
    }

    const PACKETS_HELP: &'static str = "Maximum packets authorized for one operation";
    const BYTES_HELP: &'static str = "Maximum wire bytes this operation is authorized to transmit";
}

/// Frames this operation only receives.
#[derive(Clone, Debug, Default)]
pub(crate) struct Captured;

/// Frames one capture may keep; independent of the transmitted ceiling.
pub(crate) const DEFAULT_CAPTURED_FRAMES: u64 = 10_000;

impl Budget for Captured {
    fn max_packets() -> u64 {
        DEFAULT_CAPTURED_FRAMES
    }

    fn max_bytes() -> u64 {
        default_limit_bytes()
    }

    const PACKETS_HELP: &'static str = "Maximum frames this capture is authorized to keep";
    const BYTES_HELP: &'static str = "Maximum captured bytes this capture is authorized to keep";
}

#[derive(Clone, Debug, Args)]
pub(crate) struct TrafficBudgetArgs<B: Budget> {
    #[arg(long, default_value_t = B::max_packets(), help = B::PACKETS_HELP)]
    max_packets: u64,
    #[arg(long, default_value_t = B::max_bytes(), help = B::BYTES_HELP)]
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
    budgets: TrafficBudgetArgs<Transmitted>,
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
    budgets: TrafficBudgetArgs<Transmitted>,
}

/// `plan`: passive, so it has no budget to spend.
#[derive(Clone, Debug, Args)]
pub(crate) struct RoutePolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    hostname_resolution: HostnameResolutionArgs,
}

/// `fuzz`: mutated packets, addressed numerically, so no hostname resolution.
#[derive(Clone, Debug, Args)]
pub(crate) struct FuzzPolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    permissive_packet: PermissivePacketArgs,
    #[command(flatten)]
    source_spoofing: SourceSpoofingArgs,
    #[command(flatten)]
    budgets: TrafficBudgetArgs<Transmitted>,
}

/// `replay`: captured frames sent as they were captured, sources included.
#[derive(Clone, Debug, Args)]
pub(crate) struct ReplayPolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    permissive_packet: PermissivePacketArgs,
    #[command(flatten)]
    source_spoofing: SourceSpoofingArgs,
    #[command(flatten)]
    budgets: TrafficBudgetArgs<Streamed>,
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
        self.budgets.apply_to(&mut policy);
        policy
    }
}

impl HostnamePolicyArgs {
    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.hostname_resolution.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        policy
    }
}

impl RoutePolicyArgs {
    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.hostname_resolution.apply_to(&mut policy);
        policy
    }
}

impl FuzzPolicyArgs {
    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.permissive_packet.apply_to(&mut policy);
        self.source_spoofing.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        policy
    }
}

impl ReplayPolicyArgs {
    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.permissive_packet.apply_to(&mut policy);
        self.source_spoofing.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        policy
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use clap::Parser as _;

    use super::*;
    use crate::cli::Cli;
    use crate::commands::Command;

    /// The budget a command ends up with is the one the policy enforces, so
    /// this walks the real clap parse rather than reading the trait back.
    fn budgets_for(arguments: &[&str]) -> (u64, u64) {
        let cli = Cli::try_parse_from(arguments).expect("command must parse with defaults");
        let policy = match cli.command {
            Command::Send(send) => send.policy.into_policy(),
            Command::Exchange(exchange) => exchange.send.policy.into_policy(),
            Command::Scan(scan) => scan.policy.into_policy(),
            Command::Fuzz(fuzz) => fuzz.policy.into_policy(),
            Command::Replay(replay) => replay.policy.into_policy(),
            Command::Capture(capture) => capture.budgets.into_policy(),
            other => panic!("unbudgeted command {:?}", other.kind()),
        };
        (
            policy.max_packets_per_operation,
            policy.max_bytes_per_operation,
        )
    }

    #[test]
    fn each_command_starts_from_the_budget_its_operation_calls_for() {
        let transmitted = (Transmitted::max_packets(), Transmitted::max_bytes());
        let captured = (Captured::max_packets(), Captured::max_bytes());

        assert_eq!(
            budgets_for(&[
                "packetcraftr",
                "replay",
                "capture.pcapng",
                "--interface",
                "7"
            ]),
            (
                capture::DEFAULT_STREAM_FRAMES,
                capture::DEFAULT_STREAM_BYTES
            ),
        );
        assert_eq!(
            budgets_for(&["packetcraftr", "send", "--packet", "raw(hex=00)"]),
            transmitted,
        );
        assert_eq!(
            budgets_for(&["packetcraftr", "exchange", "--packet", "raw(hex=00)"]),
            transmitted,
        );
        assert_eq!(
            budgets_for(&["packetcraftr", "scan", "192.0.2.1"]),
            transmitted,
        );
        assert_eq!(
            budgets_for(&["packetcraftr", "fuzz", "--packet", "raw(hex=00)"]),
            transmitted,
        );
        assert_eq!(
            budgets_for(&["packetcraftr", "capture", "--interface", "7"]),
            captured,
        );
        assert_eq!(captured, (DEFAULT_CAPTURED_FRAMES, transmitted.1));
    }

    #[test]
    fn replay_source_spoofing_requires_its_explicit_policy_opt_in() {
        let default = Cli::try_parse_from([
            "packetcraftr",
            "replay",
            "capture.pcapng",
            "--interface",
            "7",
        ])
        .expect("replay defaults parse");
        let Command::Replay(default) = default.command else {
            panic!("replay command")
        };
        assert!(!default.policy.into_policy().allow_source_spoofing);

        let opted_in = Cli::try_parse_from([
            "packetcraftr",
            "replay",
            "capture.pcapng",
            "--interface",
            "7",
            "--allow-source-spoofing",
        ])
        .expect("replay source-spoofing opt-in parses");
        let Command::Replay(opted_in) = opted_in.command else {
            panic!("replay command")
        };
        assert!(opted_in.policy.into_policy().allow_source_spoofing);
    }

    /// `plan` never transmits, so the flags that would authorize traffic are
    /// not offered at all.
    #[test]
    fn plan_offers_no_traffic_budget_flags() {
        Cli::try_parse_from(["packetcraftr", "plan", "--packet", "raw(hex=00)"])
            .expect("plan must parse without budget flags");

        for flag in ["--max-packets", "--max-bytes"] {
            let rejected =
                Cli::try_parse_from(["packetcraftr", "plan", "--packet", "raw(hex=00)", flag, "1"]);
            assert!(rejected.is_err(), "plan must reject {flag}");
        }
    }
}
