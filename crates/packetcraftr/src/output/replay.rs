// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured capture-replay output.

use std::time::Duration;

use serde::Serialize;

use packetcraftr_netio::{interface::Id as InterfaceId, link::Mode as NetworkLinkMode};

use super::contract::Error;
use super::frame::Captured;

pub use crate::replay::Timing;
pub use packetcraftr_core::analysis::pcap::Format as SourceFormat;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Interface {
    pub name: String,
    pub index: u32,
}

impl From<InterfaceId> for Interface {
    fn from(value: InterfaceId) -> Self {
        Self {
            name: value.name,
            index: value.index,
        }
    }
}

mirror_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum LinkMode from NetworkLinkMode {
        Auto = Auto,
        Layer2 = Layer2,
        Layer3 = Layer3,
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Result {
    pub source_format: SourceFormat,
    pub timing: Timing,
    pub requested_interface: Interface,
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

impl Result {
    pub fn from_summary(
        summary: crate::replay::Summary,
        requested_interface: InterfaceId,
        requested_link_mode: NetworkLinkMode,
        frames: Vec<Frame>,
    ) -> Self {
        Self {
            source_format: summary.source_format,
            timing: summary.timing,
            requested_interface: requested_interface.into(),
            requested_link_mode: requested_link_mode.into(),
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
    pub interface: Interface,
    pub link_mode: LinkMode,
    pub scheduled_delay: Duration,
    pub bytes_sent: u64,
    pub frame: Captured,
    pub transmitted: bool,
}

impl Frame {
    pub fn try_from_evidence(
        evidence: crate::replay::FrameEvidence,
    ) -> std::result::Result<Self, Error> {
        Ok(Self {
            source_index: evidence.source_index,
            interface: evidence.transmission().interface.clone().into(),
            link_mode: evidence.link_mode.into(),
            scheduled_delay: evidence.scheduled_delay,
            bytes_sent: u64::try_from(evidence.transmission().report.bytes_sent())
                .unwrap_or(u64::MAX),
            frame: Captured::try_from_frame(evidence.frame)?,
            transmitted: true,
        })
    }
}
