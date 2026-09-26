// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::{
    Budget, CaptureReaderBoundsArgs, DestinationAllowlistArgs, LinkMode, PermissivePacketArgs,
    PublicDestinationArgs, SourceSpoofingArgs, TrafficBudgetArgs,
};
use clap::ValueEnum;

pub(crate) const AFTER_LONG_HELP: &str = r"Replay is policy-gated and may require native features, dependencies, and privileges.

Frames a --filter rejects are skipped before authorization, so they are never policy-checked or transmitted, but they still count against the operation's frame budget. With original/scaled timing, the delay before a kept frame spans any skipped frames in between.

--bps counts exact submitted frame bytes, with no synthetic link overhead. The first selected frame is immediate; subsequent targets use the cumulative bytes already sent. Filtered frames do not consume bit-rate timing. Scheduled duration and transmitted bytes describe the run; the requested bit rate is not a throughput guarantee.

Examples:
  packetcraftr replay capture.pcapng --interface eth0 --timing immediate
  packetcraftr replay capture.pcap --interface 2 --rate 100
  packetcraftr replay capture.pcap --interface 2 --bps 8000000
  packetcraftr replay capture.pcap --interface eth0 --filter 'udp && ip.dst == 10.0.0.2'";

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum Timing {
    #[default]
    Original,
    Immediate,
}

impl From<Timing> for packetcraftr::replay::Timing {
    fn from(value: Timing) -> Self {
        match value {
            Timing::Original => Self::Original,
            Timing::Immediate => Self::Immediate,
        }
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Compress binary capture output; independent of the input's detected format.
    #[arg(long, value_enum, default_value_t = crate::command_options::Compression::None)]
    pub(crate) compression: crate::command_options::Compression,

    /// Classic PCAP or PCAPNG input path.
    pub(crate) path: PathBuf,
    /// Fallback output interface; mapping-only runs may omit it.
    #[arg(long, value_name = "NAME_OR_INDEX", required_unless_present_any = ["interface_maps", "filter_maps"])]
    pub(crate) interface: Option<String>,
    /// Map a capture-global input interface ID (classic PCAP uses 0).
    #[arg(long = "map-interface", value_name = "SOURCE_ID=OUTPUT_INTERFACE")]
    pub(crate) interface_maps: Vec<String>,
    /// Map matching frames; conflicting matches are rejected before transmission.
    #[arg(long = "map-filter", value_name = "EXPR=>OUTPUT_INTERFACE")]
    pub(crate) filter_maps: Vec<String>,
    /// Finite capture passes under one read/transmit/time budget.
    #[arg(long, default_value_t = 1)]
    pub(crate) repeat: u32,
    /// Additional minimum pause between passes, in milliseconds.
    #[arg(long, default_value_t = 0)]
    pub(crate) inter_pass_delay_ms: u64,
    /// Automatic, Layer 2, or raw Layer 3 replay intent.
    #[arg(long, value_enum, default_value_t = LinkMode::Auto)]
    pub(crate) link_mode: LinkMode,
    /// Preserve captured intervals or send immediately.
    #[arg(long, value_enum, default_value_t = Timing::Original)]
    pub(crate) timing: Timing,
    /// Positive multiplier for captured replay speed (2 means twice as fast).
    #[arg(long, conflicts_with = "rate")]
    pub(crate) speed: Option<f64>,
    /// Positive fixed frame rate in frames per second, overriding captured
    /// intervals; unlike the live commands' `--rate` ceiling, replay sends at
    /// exactly this rate.
    #[arg(long, conflicts_with = "speed")]
    pub(crate) rate: Option<f64>,
    /// Positive integer bit rate, counting submitted frame bytes without
    /// synthetic media overhead. Scheduling is best effort; first frame is immediate.
    #[arg(long, conflicts_with_all = ["rate", "speed"], value_parser = clap::value_parser!(u64).range(1..))]
    pub(crate) bps: Option<u64>,
    /// Maximum replay run time in milliseconds, which also bounds the cumulative
    /// scheduled delay.
    #[arg(long, default_value_t = 3_600_000)]
    pub(crate) max_duration_ms: u64,
    #[command(flatten)]
    pub(crate) reader: CaptureReaderBoundsArgs,
    /// Per-operation opt-in required for a permissively built or malformed live frame.
    #[arg(long, alias = "allow-malformed-live")]
    pub(crate) allow_permissive_live: bool,
    /// Replay only frames matching a display filter; skipped frames are never
    /// authorized or transmitted.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    #[command(flatten)]
    pub(crate) policy: PolicyArgs,
}

/// Frames read from a capture file and replayed onto the wire, which run to
/// far larger counts than a hand-built operation.
#[derive(Clone, Debug, Default)]
pub(crate) struct Streamed;

impl Budget for Streamed {
    fn max_packets() -> u64 {
        packetcraftr_core::capture_file::DEFAULT_STREAM_FRAMES
    }

    fn max_bytes() -> u64 {
        packetcraftr_core::capture_file::DEFAULT_STREAM_BYTES
    }

    const PACKETS_HELP: &'static str = "Maximum packets authorized for one operation";
    const BYTES_HELP: &'static str = "Maximum wire bytes this operation is authorized to transmit";
}

/// `replay`: captured frames sent as they were captured, sources included.
#[derive(Clone, Debug, clap::Args)]
pub(crate) struct PolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    permissive_packet: PermissivePacketArgs,
    #[command(flatten)]
    source_spoofing: SourceSpoofingArgs,
    #[command(flatten)]
    destination_allowlist: DestinationAllowlistArgs,
    #[command(flatten)]
    budgets: TrafficBudgetArgs<Streamed>,
}

impl PolicyArgs {
    pub(crate) fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        self.budgets.resources(settings);
    }

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
