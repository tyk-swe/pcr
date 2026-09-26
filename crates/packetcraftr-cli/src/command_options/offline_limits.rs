// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::{Args, ValueEnum};
use packetcraftr_core::analysis;
use packetcraftr_core::capture_file as capture;

use super::{MaxDurationArgs, RunTime};
use crate::output::resources::Value;
use crate::resources::{Enabled, SettingValue, Settings, declare, policy_value};

/// How conflicting bytes in overlapping IP fragments are handled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum IpOverlap {
    /// Reject the datagram when overlapping bytes conflict.
    #[default]
    Reject,
    /// Preserve the conflicting bytes received first.
    First,
    /// Replace conflicting bytes with those received last.
    Last,
}

impl From<IpOverlap> for analysis::reassembly::ip::OverlapPolicy {
    fn from(value: IpOverlap) -> Self {
        match value {
            IpOverlap::Reject => Self::Reject,
            IpOverlap::First => Self::First,
            IpOverlap::Last => Self::Last,
        }
    }
}

impl SettingValue for IpOverlap {
    fn setting_value(&self) -> Option<Value> {
        policy_value(self)
    }
}

fn default_ip_idle_expiry_ms() -> u64 {
    u64::try_from(analysis::Limits::default().ip.idle_expiry.as_millis()).unwrap_or(u64::MAX)
}

fn default_tcp_idle_expiry_ms() -> u64 {
    u64::try_from(analysis::Limits::default().tcp.idle_expiry.as_millis()).unwrap_or(u64::MAX)
}

/// Capture-reader bounds shared by offline commands.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct OfflineCaptureLimitsArgs {
    /// Maximum physical input frames, including frames rejected by the filter.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_FRAMES)]
    pub(crate) max_frames: u64,
    /// Maximum aggregate captured payload bytes read from the input; a reader
    /// bound, unrelated to the live traffic budget of the same name.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    pub(crate) max_bytes: u64,
    #[command(flatten)]
    pub(crate) reader: CaptureReaderBoundsArgs,
}

/// Per-item bounds a capture reader is opened under, shared by every command
/// that reads a capture file so the defaults cannot diverge.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct CaptureReaderBoundsArgs {
    /// Maximum source bytes, bounding compressed headers, members, and skipped frames.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    pub(crate) max_encoded_bytes: u64,

    /// Maximum decoded capture bytes, including metadata and compression expansion.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    pub(crate) max_decoded_bytes: u64,

    /// Maximum bytes accepted from any one captured frame or PCAPNG block.
    #[arg(long, default_value_t = packetcraftr_core::frame::DEFAULT_SIZE_LIMIT)]
    pub(crate) max_frame_bytes: usize,
    /// Maximum interface descriptions per input PCAPNG section, including unused
    /// interfaces. A separate capture-wide input ceiling of 65,536 also applies.
    /// With read --normalize, this also limits the selected output interfaces.
    #[arg(long, default_value_t = capture::DEFAULT_INTERFACE_LIMIT)]
    pub(crate) max_interfaces: usize,
}

impl CaptureReaderBoundsArgs {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        declare!(settings, self, [
            max_encoded_bytes: Bytes @ PhysicalInput preset(33554432, 536870912),
            max_decoded_bytes: Bytes @ PhysicalInput preset(33554432, 536870912),
            max_frame_bytes: Bytes @ PhysicalInput preset(1048576, 16777216),
            max_interfaces: Count @ IndexedMetadata preset(64, 1024),
        ]);
    }
}

impl OfflineCaptureLimitsArgs {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        declare!(settings, self, [
            max_frames: Count @ PhysicalInput preset(10000, 1000000),
            max_bytes: Bytes @ PhysicalInput preset(16777216, 268435456),
        ]);
        self.reader.resources(settings);
    }

    /// The ceiling on what an aggregate JSON document retains: the run's frame
    /// budget, so the document is bounded by a caller-set limit.
    pub(crate) fn retention_ceiling(self) -> usize {
        usize::try_from(self.max_frames).unwrap_or(usize::MAX)
    }
}

/// Which optional analysis stages an offline command runs, for its resource
/// diagnostics.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AnalysisStages {
    /// TCP stream reassembly.
    pub(crate) tcp: bool,
    /// The capture-global conversation index and IP reassembly.
    pub(crate) index: Enabled,
    /// Physical-frame provenance retention.
    pub(crate) provenance: bool,
}

impl AnalysisStages {
    /// Indexing and provenance always run; TCP reassembly as given.
    pub(crate) const fn with_tcp(tcp: bool) -> Self {
        Self {
            tcp,
            index: Enabled::Fixed(true),
            provenance: true,
        }
    }
}

/// Capture and analysis bounds shared by stats, expert, follow, and TLS.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct OfflineLimitsArgs {
    /// Maximum physical-frame provenance allocations retained by analysis consumers.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    pub(crate) max_provenance_bytes: usize,
    #[command(flatten)]
    pub(crate) capture: OfflineCaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) epoch: super::EpochBoundsArgs,
    /// Maximum capture-global distinct conversations per transport.
    /// Expiry does not release index entries; raising this increases retained metadata.
    #[arg(long, default_value_t = analysis::Limits::default().max_flows)]
    pub(crate) max_flows: usize,
    /// Maximum charged capture-scope and encapsulation metadata bytes.
    #[arg(long, default_value_t = analysis::Limits::default().max_scope_bytes)]
    pub(crate) max_scope_bytes: usize,
    /// Maximum retained TCP stream bytes in one direction.
    #[arg(long, default_value_t = analysis::Limits::default().tcp.max_bytes_per_flow)]
    pub(crate) max_tcp_bytes_per_flow: usize,
    /// Maximum retained TCP payload and metadata bytes.
    #[arg(
        long,
        default_value_t = analysis::Limits::default().tcp.max_aggregate_bytes
    )]
    pub(crate) max_tcp_reassembly_bytes: usize,
    /// Maximum pending out-of-order segments retained for one TCP direction.
    #[arg(
        long,
        default_value_t = analysis::Limits::default().tcp.max_segments_per_flow
    )]
    pub(crate) max_tcp_segments_per_flow: usize,
    /// TCP flow inactivity interval in capture-time milliseconds.
    #[arg(long, default_value_t = default_tcp_idle_expiry_ms())]
    pub(crate) tcp_idle_expiry_ms: u64,
    /// Policy for conflicting bytes in overlapping IPv4 or IPv6 fragments.
    #[arg(long, value_enum, default_value_t = IpOverlap::Reject)]
    pub(crate) ip_overlap: IpOverlap,
    /// Maximum incomplete IPv4 and IPv6 datagrams retained concurrently.
    #[arg(long, default_value_t = analysis::Limits::default().ip.max_datagrams)]
    pub(crate) max_ip_datagrams: usize,
    /// Maximum physical fragments accepted for one retained IP datagram.
    #[arg(
        long,
        default_value_t = analysis::Limits::default().ip.max_fragments_per_datagram
    )]
    pub(crate) max_ip_fragments_per_datagram: usize,
    /// Maximum fragmentable payload bytes accepted for one IP datagram.
    #[arg(
        long,
        default_value_t = analysis::Limits::default().ip.max_bytes_per_datagram
    )]
    pub(crate) max_ip_bytes_per_datagram: usize,
    /// Maximum retained IP, derived cascade, and metadata bytes.
    #[arg(
        long,
        default_value_t = analysis::Limits::default().ip.max_aggregate_bytes
    )]
    pub(crate) max_ip_reassembly_bytes: usize,
    /// Maximum per-datagram IP outcomes retained for aggregate reporting.
    #[arg(long, default_value_t = analysis::Limits::default().ip.max_retained_outcomes)]
    pub(crate) max_ip_outcomes: usize,
    /// IP datagram inactivity interval in capture-time milliseconds.
    #[arg(long, default_value_t = default_ip_idle_expiry_ms())]
    pub(crate) ip_idle_expiry_ms: u64,
    #[command(flatten)]
    pub(crate) duration: MaxDurationArgs<Analysis>,
}

/// One pass over a capture file.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Analysis;

impl RunTime for Analysis {
    const HELP: &'static str = "Maximum analysis run time in milliseconds";
}

impl super::Bounded for OfflineLimitsArgs {
    fn max_duration(&self) -> std::time::Duration {
        self.duration.max_duration()
    }
}

impl OfflineLimitsArgs {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>, stages: AnalysisStages) {
        let AnalysisStages {
            tcp,
            index,
            provenance,
        } = stages;
        self.capture.resources(settings);
        declare!(settings, self, [
            max_provenance_bytes: Bytes @ IndexedMetadata preset(2097152, 16777216) if provenance,
            max_flows: Count @ IndexedMetadata preset(1024, 8192) if index,
            max_scope_bytes: Bytes @ IndexedMetadata preset(2097152, 16777216) if index,
            max_tcp_bytes_per_flow: Bytes @ ActiveState preset(262144, 4194304) if tcp,
            max_tcp_reassembly_bytes: Bytes @ ActiveState preset(4194304, 33554432) if tcp,
            max_tcp_segments_per_flow: Count @ ActiveState preset(128, 1024) if tcp,
            tcp_idle_expiry_ms: Milliseconds @ ActiveState if tcp,
            ip_overlap: Policy @ ActiveState if index,
            max_ip_datagrams: Count @ ActiveState preset(256, 4096) if index,
            max_ip_fragments_per_datagram: Count @ ActiveState preset(64, 256) if index,
            max_ip_bytes_per_datagram: Bytes @ ActiveState preset(65535, 1048576) if index,
            max_ip_reassembly_bytes: Bytes @ ActiveState preset(4194304, 33554432) if index,
            max_ip_outcomes: Count @ ResultRetention preset(128, 1024) if index,
            ip_idle_expiry_ms: Milliseconds @ ActiveState if index,
        ]);
        self.duration.resources(settings);
    }
}
