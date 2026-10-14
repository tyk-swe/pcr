// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::command_options::InterfaceSelector;
use crate::command_options::{
    CaptureLimitsArgs, CompressionArgs, DecodeArgs, LongTimeoutArgs, TrafficBudgetArgs, TreeArgs,
};
use packetcraftr_netio::capture::{TimestampPrecision, TimestampSource};

pub(crate) const AFTER_LONG_HELP: &str = r"Live capture may require native features, dependencies, and privileges.

--capture-filter <BPF> runs resolver-free numeric libpcap/Npcap BPF before the
capture queue and budgets; --filter <EXPR> runs the display filter after capture
(rejected frames still spend queue and operation budgets).

Repeat --interface to capture multiple sources under shared queue/operation
bounds; frame.interface is the zero-based selected-interface ID. --write saves
PCAPNG (required for --output json) with optional --rotate-bytes,
--rotate-interval-ms, --rotate-files (1..=64), and --retention stop|ring.
--dissect, --tree, and --field decode matched frames on emission.

Examples:
  packetcraftr network capture --interface 1 --timeout-ms 1000
  packetcraftr --output ndjson network capture --interface 1 --interface 2
  packetcraftr --output json network capture --interface 1 --write trace.pcapng.gz \
    --compression gzip --rotate-bytes 1048576 --rotate-files 4
  packetcraftr network capture --interface 1 --write ring.pcapng \
    --rotate-interval-ms 1000 --rotate-files 3 --retention ring
  packetcraftr network capture --interface 1 --promiscuous \
    --capture-filter 'udp port 53' \
    --filter 'udp.source_port == 53'";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    #[command(flatten)]
    pub(crate) compression: CompressionArgs,

    /// Interface names or numeric indexes; repeat to capture an explicit set.
    #[arg(
        long,
        value_name = "NAME_OR_INDEX",
        value_parser = crate::command_options::interface_selector,
        required = true
    )]
    pub(crate) interface: Vec<crate::command_options::Selector<InterfaceSelector>>,
    /// Save PCAPNG files; existing paths are never overwritten.
    #[arg(long)]
    pub(crate) write: Option<std::path::PathBuf>,
    /// Maximum uncompressed capture bytes per file, including headers and metadata.
    #[arg(long)]
    pub(crate) rotate_bytes: Option<u64>,
    /// Rotate between frames after this monotonic interval.
    #[arg(long)]
    pub(crate) rotate_interval_ms: Option<u64>,
    /// Maximum retained files (1..=64); numbering is inserted before the last extension.
    #[arg(long, default_value_t = 1)]
    pub(crate) rotate_files: usize,
    /// Stop at the file limit, or reuse only files created by this operation.
    #[arg(long, value_enum, default_value_t = Retention::Stop)]
    pub(crate) retention: Retention,
    /// Enable promiscuous capture mode.
    #[arg(long)]
    pub(crate) promiscuous: bool,
    /// Kernel/driver capture-buffer size in bytes, applied per interface before
    /// activation. Unset keeps the backend default; this is not the PacketcraftR
    /// capture queue, which --max-queue-frames/--max-captured-bytes bound.
    #[arg(long, value_name = "BYTES")]
    pub(crate) capture_buffer_bytes: Option<usize>,
    /// Packet timestamp source, applied per interface before activation; the
    /// interfaces command lists the types an interface advertises. Only sources
    /// synchronized with the system clock are selectable.
    #[arg(long, value_enum)]
    pub(crate) timestamp_source: Option<TimestampSourceArg>,
    /// Packet timestamp fraction precision delivered by the backend.
    #[arg(long, value_enum)]
    pub(crate) timestamp_precision: Option<TimestampPrecisionArg>,
    #[command(flatten)]
    pub(crate) timeout: LongTimeoutArgs,
    /// Resolver-free core libpcap/Npcap BPF, applied before capture.
    #[arg(long, value_name = "BPF")]
    pub(crate) capture_filter: Option<String>,
    /// Keep only frames matching PacketcraftR's post-capture display filter.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    /// Decode each emitted frame and include its layer stack and diagnostics.
    #[arg(long)]
    pub(crate) dissect: bool,
    #[command(flatten)]
    pub(crate) tree: TreeArgs,
    /// Select a registered field per matched frame; repeat to preserve column order.
    #[arg(long = "field", value_name = "PATH", conflicts_with = "dissect")]
    pub(crate) fields: Vec<String>,
    /// Maximum encoded projection data bytes across all rows (excluding envelopes).
    #[arg(long, default_value_t = 16*1024*1024)]
    pub(crate) max_projection_bytes: usize,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) budgets: TrafficBudgetArgs,
}

/// The timestamp sources the capture contract can represent, spelled the same
/// as the libpcap type names discovery reports.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum TimestampSourceArg {
    /// Host-provided timestamps of unspecified characteristics (the default).
    #[value(name = "host", alias = "host-default")]
    Host,
    /// Low-precision host timestamps synchronized with the system clock.
    #[value(name = "host_lowprec", alias = "host-lowprec")]
    HostLowPrec,
    /// High-precision host timestamps synchronized with the system clock.
    #[value(name = "host_hiprec", alias = "host-hiprec")]
    HostHighPrec,
    /// Adapter-provided high-precision timestamps synchronized with the
    /// system clock.
    #[value(name = "adapter")]
    Adapter,
}

impl From<TimestampSourceArg> for TimestampSource {
    fn from(value: TimestampSourceArg) -> Self {
        match value {
            TimestampSourceArg::Host => Self::Host,
            TimestampSourceArg::HostLowPrec => Self::HostLowPrec,
            TimestampSourceArg::HostHighPrec => Self::HostHighPrec,
            TimestampSourceArg::Adapter => Self::Adapter,
        }
    }
}

/// The timestamp fraction precisions a backend can deliver.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum TimestampPrecisionArg {
    /// Microsecond fractions (the default).
    #[value(name = "micro")]
    Micro,
    /// Nanosecond fractions.
    #[value(name = "nano")]
    Nano,
}

impl From<TimestampPrecisionArg> for TimestampPrecision {
    fn from(value: TimestampPrecisionArg) -> Self {
        match value {
            TimestampPrecisionArg::Micro => Self::Micro,
            TimestampPrecisionArg::Nano => Self::Nano,
        }
    }
}

/// The `--retention` selector for [`crate::output::capture::Retention`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Retention {
    Stop,
    Ring,
}

impl crate::resources::SettingValue for Retention {
    fn setting_value(&self) -> Option<crate::output::resources::Value> {
        crate::resources::policy_value(self)
    }
}

impl From<Retention> for crate::output::capture::Retention {
    fn from(value: Retention) -> Self {
        match value {
            Retention::Stop => Self::Stop,
            Retention::Ring => Self::Ring,
        }
    }
}
