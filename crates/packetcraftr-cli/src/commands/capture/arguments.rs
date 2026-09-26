// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::command_options::{CaptureLimitsArgs, Captured, DecodeArgs, TrafficBudgetArgs};
use packetcraftr_netio::capture::{TimestampPrecision, TimestampSource};

pub(crate) const AFTER_LONG_HELP: &str = r"Live capture may require native features, dependencies, and privileges.

--capture-filter <BPF> uses the stable resolver-free core of libpcap/Npcap BPF syntax and narrows what reaches PacketcraftR. Frames it rejects never enter PacketcraftR's capture queue and do not consume queue capacity or operation frame and byte budgets.

Use core BPF keywords and numeric address, network, port, and protocol operands. Other symbolic tokens are rejected before native compilation so capture filters cannot perform hidden hostname or name-database resolution.

--filter <EXPR> uses PacketcraftR's display-filter language after capture. Frames it rejects have already occupied PacketcraftR's capture queue and passed the native BPF filter, so they still consume operation frame and byte budgets.

The two filters use different languages and may be combined.

Repeat --interface for an explicit set. Queue frame/byte limits are shared across
sources, and each source must have room for one full snapshot. All sources pass
readiness before delivery; shutdown and loss are reported per interface. Output
frame.interface values are zero-based capture IDs in selected-interface order;
the completion report maps them to native names/indexes. Frames retain capture
timestamps and fair delivery order; cross-interface timestamp ordering is not promised.

--capture-buffer-bytes sizes the kernel/driver capture buffer per interface,
which is separate from the PacketcraftR queue that --max-queue-frames and
--max-captured-bytes bound. --timestamp-source selects a timestamp type the
interface advertises (`interfaces --timestamp-types` lists them); only types
synchronized with the system clock are selectable. --timestamp-precision asks
for microsecond or nanosecond timestamp fractions. Every explicit setting is
applied before the backend activates or the capture fails with a typed error;
reports distinguish requested, applied, and confirmed-effective values.

--write saves PCAPNG while text/JSON/NDJSON report progress and completion. JSON
requires --write. --rotate-bytes counts uncompressed capture bytes including all
headers; frames never split across files. --rotate-interval-ms rotates between
frames using elapsed monotonic time. --rotate-files bounds retained files (1..=64).
The default --retention stop ends at that bound. Explicit --retention ring reuses
only handles for files created by this operation. Existing paths are preserved.
All files receive complete metadata and compression finalization. Failure output
includes partial capture/file evidence. A boundary can consume one matched frame
without writing it when no next file is permitted; source counters expose this.
Operation frame/byte/time limits remain shared across every source and file.

Text and NDJSON frame records use the one-based post-BPF source frame position.
Display-filter rejection does not renumber later source_frame values; NDJSON envelope
sequence remains the zero-based emitted-record position.

--dissect decodes each emitted frame once and publishes its layer stack and
decode diagnostics: NDJSON frame records gain a decoded object while text
prints the layer list beside the frame. --field selects registered field paths
per matched frame instead of frame records; rows stream as NDJSON fields
events or text columns bounded by --max-projection-bytes. Both share the
--filter/--decode-as registry and decode a frame at most once per selection
and emission; decoded state never accumulates across frames.

Examples:
  packetcraftr capture --interface 1 --timeout-ms 1000
  packetcraftr --output ndjson capture --interface 1 --interface 2
  packetcraftr --output json capture --interface 1 --write trace.pcapng.gz \
    --compression gzip --rotate-bytes 1048576 --rotate-files 4
  packetcraftr capture --interface 1 --write ring.pcapng \
    --rotate-interval-ms 1000 --rotate-files 3 --retention ring
  packetcraftr capture --interface 1 --promiscuous \
    --capture-filter 'udp port 53' \
    --filter 'udp.source_port == 53'";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Compress binary stdout or saved PCAPNG files.
    #[arg(long, value_enum, default_value_t = crate::command_options::Compression::None)]
    pub(crate) compression: crate::command_options::Compression,

    /// Interface names or numeric indexes; repeat to capture an explicit set.
    #[arg(long, value_name = "NAME_OR_INDEX", required = true)]
    pub(crate) interface: Vec<String>,
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
    /// Overall capture window in milliseconds.
    #[arg(long, default_value_t = 3_000)]
    pub(crate) timeout_ms: u64,
    /// Resolver-free core libpcap/Npcap BPF, applied before capture.
    #[arg(long, value_name = "BPF")]
    pub(crate) capture_filter: Option<String>,
    /// Keep only frames matching PacketcraftR's post-capture display filter.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    /// Decode each emitted frame and include its layer stack and diagnostics.
    #[arg(long)]
    pub(crate) dissect: bool,
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
    pub(crate) budgets: TrafficBudgetArgs<Captured>,
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

impl From<Retention> for crate::output::capture::Retention {
    fn from(value: Retention) -> Self {
        match value {
            Retention::Stop => Self::Stop,
            Retention::Ring => Self::Ring,
        }
    }
}
