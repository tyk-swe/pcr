// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Offline-read and live-capture stream output.

use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::frame::Frame;
use serde::Serialize;

use super::contract::Error;
use super::frame::{Captured, SourceFrame, Stack};

/// One NDJSON event produced by `capture`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Event {
    Frame {
        source_frame: SourceFrame,
        frame: Captured,
        #[serde(skip_serializing_if = "Option::is_none")]
        decoded: Option<Stack>,
    },
}

impl Event {
    pub fn try_from_frame(source_frame: u64, frame: Frame) -> Result<Self, Error> {
        Ok(Self::Frame {
            source_frame: source_frame.try_into()?,
            frame: Captured::try_from_frame(frame)?,
            decoded: None,
        })
    }

    /// A frame record that also publishes its dissected stack and diagnostics.
    pub fn try_from_decoded(
        source_frame: u64,
        frame: Frame,
        decoded: &DecodedPacket,
    ) -> Result<Self, Error> {
        Ok(Self::Frame {
            source_frame: source_frame.try_into()?,
            frame: Captured::try_from_frame(frame)?,
            decoded: Some(Stack::from_decoded(decoded)),
        })
    }
}

impl crate::output::stream::StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Frame { .. } => "frame",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Retention {
    #[default]
    Stop,
    Ring,
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
    pub compression: String,
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
    pub native_interface: packetcraftr_netio::interface::Id,
    pub link_type: u32,
    pub snap_length: usize,
    /// The native driver-buffer/timestamp settings this source realized:
    /// requested values the backend applied, and — only where the backend can
    /// confirm — the effective value. `effective` null means unreported, never
    /// zero or default. Absent when the backend reported nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_settings: Option<packetcraftr_netio::capture::RealizedSettings>,
    pub queue_frames: usize,
    pub queue_bytes: usize,
    pub overflow_policy: String,
    pub metadata_valid: bool,
    pub ready: bool,
    pub shutdown_confirmed: bool,
    pub statistics_valid: bool,
    pub statistics: packetcraftr_netio::capture::Statistics,
    pub delivered_frames: u64,
    pub delivered_bytes: u64,
    pub admitted_frames: u64,
    pub matched_frames: u64,
    pub emitted_frames: u64,
    pub late_frames: u64,
}
/// The machine-output enum value, which spells words with underscores where
/// the `--overflow-policy` argument uses hyphens.
fn overflow_policy_name(policy: packetcraftr_netio::capture::OverflowPolicy) -> &'static str {
    use packetcraftr_netio::capture::OverflowPolicy;
    match policy {
        OverflowPolicy::Fail => "fail",
        OverflowPolicy::DropNewest => "drop_newest",
        OverflowPolicy::DropOldest => "drop_oldest",
    }
}
impl From<&packetcraftr::capture::Source> for Source {
    fn from(source: &packetcraftr::capture::Source) -> Self {
        let native = &source.capture;
        Self {
            capture_id: native.index as u32,
            native_interface: native.metadata.interface.clone(),
            link_type: native.metadata.link_type.0,
            snap_length: native.metadata.snap_length,
            capture_settings: native
                .metadata
                .native
                .reported()
                .then_some(native.metadata.native),
            queue_frames: native.limits.max_frames,
            queue_bytes: native.limits.max_bytes,
            overflow_policy: overflow_policy_name(native.limits.overflow_policy).to_owned(),
            metadata_valid: native.metadata_valid,
            ready: native.ready,
            shutdown_confirmed: native.shutdown_confirmed,
            statistics_valid: native.statistics_valid,
            statistics: native.statistics,
            delivered_frames: native.delivered_frames,
            delivered_bytes: native.delivered_bytes,
            admitted_frames: source.admitted_frames,
            matched_frames: source.matched_frames,
            emitted_frames: source.emitted_frames,
            late_frames: source.late_frames,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub requested_interfaces: Vec<packetcraftr_netio::interface::Id>,
    pub sources: Vec<Source>,
    pub frames_delivered: u64,
    pub stop_reason: packetcraftr::capture::StopReason,
    pub capture_statistics_complete: bool,
    pub files: Option<Files>,
}
impl Summary {
    pub fn from_capture(report: &packetcraftr::capture::Report, files: Option<Files>) -> Self {
        Self {
            requested_interfaces: report.requested_interfaces.clone(),
            sources: report.sources.iter().map(Into::into).collect(),
            frames_delivered: report.frames_delivered,
            stop_reason: report.stop,
            capture_statistics_complete: report.capture_statistics_complete,
            files,
        }
    }
}
/// Partial capture evidence retained even when a consumer or cleanup fails.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub summary: Summary,
    pub stats: packetcraftr::Stats,
}
