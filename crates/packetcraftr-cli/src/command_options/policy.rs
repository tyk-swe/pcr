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
/// The two flags are one pair of budgets with one meaning — the ceiling the
/// policy enforces for this operation — but a command that replays a captured
/// stream starts from different numbers than one that sends a single packet,
/// and a command that only receives should not be told about transmission.
pub(crate) trait Budget: Clone + fmt::Debug + Default {
    fn max_packets() -> u64;
    fn max_bytes() -> u64;
    const PACKETS_HELP: &'static str;
    const BYTES_HELP: &'static str;
}

/// Packets this operation puts on the wire itself.
#[derive(Clone, Debug, Default)]
pub(crate) struct Transmitted;

impl Budget for Transmitted {
    fn max_packets() -> u64 {
        10_000
    }

    fn max_bytes() -> u64 {
        u64::try_from(net::capture::Limits::default().max_bytes)
            .expect("default max bytes fits u64")
    }

    const PACKETS_HELP: &'static str = "Maximum packets authorized for one operation";
    const BYTES_HELP: &'static str = "Maximum packet bytes authorized for one operation";
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
    const BYTES_HELP: &'static str = "Maximum wire bytes authorized for one operation";
}

/// Frames this operation only receives.
#[derive(Clone, Debug, Default)]
pub(crate) struct Captured;

impl Budget for Captured {
    fn max_packets() -> u64 {
        Transmitted::max_packets()
    }

    fn max_bytes() -> u64 {
        Transmitted::max_bytes()
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
        self.budgets.apply_to(&mut policy);
        policy
    }
}
