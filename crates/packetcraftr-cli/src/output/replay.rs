// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use serde::Serialize;

use packetcraftr::replay as library;
use packetcraftr_netio::link::Mode as NetworkLinkMode;

use super::contract::Error;
use super::envelope::Stats;
use super::frame::Captured;
// The schema resolves both replay interface fields to `$defs.interfaceId` and
// both link-mode fields to `$defs.linkMode`.
use super::network::{InterfaceId, LinkMode};

published_enum! {
    /// The capture file format a replay read.
    pub enum SourceFormat from packetcraftr_core::capture_file::Format {
        Pcap => "pcap",
        PcapNg => "pcap_ng",
    }
}

/// How a replay spaced its transmissions.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub enum Timing {
    #[serde(rename = "original")]
    Original,
    #[serde(rename = "scaled")]
    Scaled(f64),
    #[serde(rename = "fixed_rate")]
    FixedRate(f64),
    #[serde(rename = "bit_rate")]
    BitRate(u64),
    #[serde(rename = "immediate")]
    Immediate,
}

impl TryFrom<library::Timing> for Timing {
    type Error = Error;

    fn try_from(value: library::Timing) -> Result<Self, Error> {
        match value {
            library::Timing::Original => Ok(Self::Original),
            library::Timing::Scaled(factor) => Ok(Self::Scaled(factor)),
            library::Timing::FixedRate(rate) => Ok(Self::FixedRate(rate)),
            library::Timing::BitRate(rate) => Ok(Self::BitRate(rate)),
            library::Timing::Immediate => Ok(Self::Immediate),
            _ => Err(Error::Unpublished {
                value: "replay timing",
            }),
        }
    }
}

/// A replay publishes its source frames as packet operations: every frame
/// read was attempted, every frame transmitted completed.
impl From<(&library::Report, Duration)> for Stats {
    fn from((summary, elapsed): (&library::Report, Duration)) -> Self {
        Self {
            packets_attempted: summary.frames_read,
            packets_completed: summary.frames_transmitted,
            bytes: summary.bytes_transmitted,
            elapsed,
            capture: Default::default(),
        }
    }
}

/// Aggregate result of `replay`; per-frame evidence is emitted separately.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Report {
    pub source_format: SourceFormat,
    pub timing: Timing,
    pub requested_interface: Option<InterfaceId>,
    pub interfaces_used: Vec<InterfaceId>,
    pub passes_completed: u32,
    pub requested_link_mode: LinkMode,
    #[serde(rename = "frames_attempted")]
    pub frames_read: u64,
    #[serde(rename = "frames_completed")]
    pub frames_transmitted: u64,
    #[serde(rename = "bytes_completed")]
    pub bytes_transmitted: u64,
    pub scheduled_duration: Duration,
    pub frames: Vec<Frame>,
}

/// A replay summary with the interface and link mode the caller requested
/// and the per-frame evidence retained for the aggregate.
impl<I: Into<InterfaceId>> TryFrom<(library::Report, Option<I>, NetworkLinkMode, Vec<Frame>)>
    for Report
{
    type Error = Error;

    fn try_from(
        (summary, requested_interface, requested_link_mode, frames): (
            library::Report,
            Option<I>,
            NetworkLinkMode,
            Vec<Frame>,
        ),
    ) -> Result<Self, Error> {
        Ok(Self {
            source_format: summary.source_format.into(),
            timing: summary.timing.try_into()?,
            requested_interface: requested_interface.map(Into::into),
            interfaces_used: summary
                .interfaces_used
                .into_iter()
                .map(Into::into)
                .collect(),
            passes_completed: summary.passes_completed,
            requested_link_mode: requested_link_mode.into(),
            frames_read: summary.frames_read,
            frames_transmitted: summary.frames_transmitted,
            bytes_transmitted: summary.bytes_transmitted,
            scheduled_duration: summary.scheduled_duration,
            frames,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Frame {
    pub pass: u32,
    #[serde(rename = "source_sequence")]
    pub source_index: u64,
    pub interface: InterfaceId,
    pub link_mode: LinkMode,
    pub scheduled_delay: Duration,
    pub bytes_sent: u64,
    pub frame: Captured,
}

impl TryFrom<library::FrameEvidence> for Frame {
    type Error = Error;

    fn try_from(evidence: library::FrameEvidence) -> Result<Self, Error> {
        Ok(Self {
            source_index: evidence.source_index,
            pass: evidence.pass,
            interface: (&evidence.transmission().interface).into(),
            link_mode: evidence.link_mode.into(),
            scheduled_delay: evidence.scheduled_delay,
            bytes_sent: u64::try_from(evidence.transmission().report.bytes_sent())
                .unwrap_or(u64::MAX),
            frame: evidence.frame.try_into()?,
        })
    }
}

impl crate::output::stream::StreamRecord for Frame {
    fn event_name(&self) -> &'static str {
        "frame"
    }
}
