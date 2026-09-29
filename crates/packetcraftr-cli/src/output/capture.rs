// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_netio::capture as native;
use serde::Serialize;

use super::envelope::{self, is_zero};
use super::frame::SourceFrame;
use super::network::InterfaceId;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Stats {
    pub received_frames: u64,
    pub received_bytes: u64,
    pub dropped_frames: u64,
    pub dropped_bytes: u64,
    pub overflow_events: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub receiver_dropped_frames: u64,
}

impl From<native::Stats> for Stats {
    fn from(value: native::Stats) -> Self {
        Self {
            received_frames: value.received_frames,
            received_bytes: value.received_bytes,
            dropped_frames: value.dropped_frames,
            dropped_bytes: value.dropped_bytes,
            overflow_events: value.overflow_events,
            receiver_dropped_frames: value.receiver_dropped_frames,
        }
    }
}

published_enum! {
    pub enum TimestampSource from native::TimestampSource {
        Host => "host",
        HostLowPrec => "host_lowprec",
        HostHighPrec => "host_hiprec",
        Adapter => "adapter",
    }
}

published_enum! {
    pub enum TimestampPrecision from native::TimestampPrecision {
        Micro => "micro",
        Nano => "nano",
    }
}

published_enum! { pub enum Direction from native::Direction { Both => "both", In => "in", Out => "out", } }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Realized<T> {
    pub requested: Option<T>,
    pub applied: Option<T>,
    pub effective: Option<T>,
}

impl<T, U: Into<T>> From<native::Realized<U>> for Realized<T> {
    fn from(value: native::Realized<U>) -> Self {
        Self {
            requested: value.requested.map(Into::into),
            applied: value.applied.map(Into::into),
            effective: value.effective.map(Into::into),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RealizedSettings {
    pub direction: Realized<Direction>,
    pub buffer_size: Realized<usize>,
    pub timestamp_source: Realized<TimestampSource>,
    pub timestamp_precision: Realized<TimestampPrecision>,
}

impl From<native::RealizedSettings> for RealizedSettings {
    fn from(value: native::RealizedSettings) -> Self {
        Self {
            direction: value.direction.into(),
            buffer_size: value.buffer_size.into(),
            timestamp_source: value.timestamp_source.into(),
            timestamp_precision: value.timestamp_precision.into(),
        }
    }
}

published_enum! {
    pub enum StopReason from packetcraftr::capture::StopReason {
        Window => "window",
        FrameBudget => "frame_budget",
        Sink => "sink",
        Failure => "failure",
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Retention {
    #[default]
    Stop,
    Ring,
}

published_enum! {
    pub enum Compression from packetcraftr_core::capture_file::compression::Format {
        None => "none",
        Gzip => "gzip",
        Zstd => "zstd",
    }
}

published_enum! {
    pub enum OverflowPolicy from native::OverflowPolicy {
        Fail => "fail",
        DropNewest => "drop_newest",
        DropOldest => "drop_oldest",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct File {
    pub path: String,
    pub slot: u32,
    pub generation: u64,
    pub frames: u64,
    pub capture_bytes: u64,
    pub encoded_bytes: Option<u64>,
    pub first_source_frame: Option<SourceFrame>,
    pub last_source_frame: Option<SourceFrame>,
    pub finalized: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Files {
    pub retention: Retention,
    pub compression: Compression,
    pub rotate_bytes: Option<u64>,
    pub rotate_interval_ms: Option<u64>,
    pub maximum_files: usize,
    pub files: Vec<File>,
    pub frames_written: u64,
    pub captured_bytes_written: u64,
    pub discarded_files: u64,
    pub discarded_frames: u64,
    pub discarded_capture_bytes: u64,
    pub stopped_at_retention_limit: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Source {
    pub capture_id: u32,
    pub native_interface: InterfaceId,
    pub link_type: u32,
    pub snap_length: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_settings: Option<RealizedSettings>,
    pub queue_frames: usize,
    pub queue_bytes: usize,
    pub overflow_policy: OverflowPolicy,
    pub metadata_valid: bool,
    pub ready: bool,
    pub shutdown_confirmed: bool,
    pub statistics_valid: bool,
    pub statistics: Stats,
    pub delivered_frames: u64,
    pub delivered_bytes: u64,
    pub admitted_frames: u64,
    pub matched_frames: u64,
    pub emitted_frames: u64,
    pub late_frames: u64,
}
impl From<&packetcraftr::capture::Source> for Source {
    fn from(source: &packetcraftr::capture::Source) -> Self {
        Self {
            capture_id: source.index as u32,
            native_interface: source.metadata.interface.clone().into(),
            link_type: source.metadata.link_type.0,
            snap_length: source.metadata.snap_length,
            capture_settings: source
                .metadata
                .native
                .reported()
                .then(|| source.metadata.native.into()),
            queue_frames: source.limits.max_frames,
            queue_bytes: source.limits.max_bytes,
            overflow_policy: source.limits.overflow_policy.into(),
            metadata_valid: source.metadata_valid,
            ready: source.ready,
            shutdown_confirmed: source.shutdown_confirmed,
            statistics_valid: source.statistics_valid,
            statistics: source.statistics.into(),
            delivered_frames: source.delivered_frames,
            delivered_bytes: source.delivered_bytes,
            admitted_frames: source.admitted_frames,
            matched_frames: source.matched_frames,
            emitted_frames: source.emitted_frames,
            late_frames: source.late_frames,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub requested_interfaces: Vec<InterfaceId>,
    pub sources: Vec<Source>,
    pub frames_delivered: u64,
    pub stop_reason: StopReason,
    pub capture_statistics_complete: bool,
    pub files: Option<Files>,
}
impl From<(&packetcraftr::capture::Report, Option<Files>)> for Summary {
    fn from((report, files): (&packetcraftr::capture::Report, Option<Files>)) -> Self {
        Self {
            requested_interfaces: report
                .requested_interfaces
                .iter()
                .cloned()
                .map(Into::into)
                .collect(),
            sources: report.sources.iter().map(Into::into).collect(),
            frames_delivered: report.frames_delivered,
            stop_reason: report.stop.into(),
            capture_statistics_complete: report.capture_statistics_complete,
            files,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub summary: Summary,
    pub stats: envelope::Stats,
}

impl From<(&packetcraftr::capture::Report, Option<Files>)> for Snapshot {
    fn from((report, files): (&packetcraftr::capture::Report, Option<Files>)) -> Self {
        Self {
            summary: (report, files).into(),
            stats: (&report.stats).into(),
        }
    }
}
