// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured capture-replay output.

use std::time::Duration;

use serde::Serialize;

use packetcraftr_netio::{interface::Id as NetworkInterfaceId, link::Mode as NetworkLinkMode};

use super::contract::Error;
use super::frame::Captured;

use packetcraftr::replay::Timing;
use packetcraftr_core::analysis::pcap::Format as SourceFormat;
// The schema resolves both replay interface fields to `$defs.interfaceId` and
// both link-mode fields to `$defs.linkMode`.
use packetcraftr_netio::interface::Id as InterfaceId;
use packetcraftr_netio::link::Mode as LinkMode;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Report {
    pub source_format: SourceFormat,
    pub timing: Timing,
    pub requested_interface: InterfaceId,
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

impl Report {
    pub fn from_summary(
        summary: packetcraftr::replay::Summary,
        requested_interface: NetworkInterfaceId,
        requested_link_mode: NetworkLinkMode,
        frames: Vec<Frame>,
    ) -> Self {
        Self {
            source_format: summary.source_format,
            timing: summary.timing,
            requested_interface,
            requested_link_mode,
            frames_read: summary.frames_read,
            frames_transmitted: summary.frames_transmitted,
            bytes_transmitted: summary.bytes_transmitted,
            scheduled_duration: summary.scheduled_duration,
            frames,
        }
    }
}

/// One frame record produced by streaming `replay` output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Frame {
    #[serde(rename = "source_sequence")]
    pub source_index: u64,
    pub interface: InterfaceId,
    pub link_mode: LinkMode,
    pub scheduled_delay: Duration,
    pub bytes_sent: u64,
    pub frame: Captured,
}

impl Frame {
    pub fn try_from_evidence(evidence: packetcraftr::replay::FrameEvidence) -> Result<Self, Error> {
        Ok(Self {
            source_index: evidence.source_index,
            interface: evidence.transmission().interface.clone(),
            link_mode: evidence.link_mode,
            scheduled_delay: evidence.scheduled_delay,
            bytes_sent: u64::try_from(evidence.transmission().report.bytes_sent())
                .unwrap_or(u64::MAX),
            frame: Captured::try_from_frame(evidence.frame)?,
        })
    }
}

impl crate::output::stream::StreamRecord for Frame {
    fn event_name(&self) -> &'static str {
        "frame"
    }
}
