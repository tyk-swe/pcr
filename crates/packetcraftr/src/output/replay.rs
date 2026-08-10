// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured capture-replay output.

use std::time::Duration;

use serde::Serialize;

use packetcraftr_live::replay::{FrameEvidence as ReplayFrameEvidence, Summary as ReplaySummary};
use packetcraftr_network::{interface::Id as InterfaceId, link::Mode as NetworkLinkMode};

use super::contract::Error;
pub use super::frame::Captured;

/// Aggregate or terminal result of `replay`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFormat {
    Pcap,
    PcapNg,
}

impl From<packetcraftr_analysis::pcap::Format> for SourceFormat {
    fn from(value: packetcraftr_analysis::pcap::Format) -> Self {
        match value {
            packetcraftr_analysis::pcap::Format::Pcap => Self::Pcap,
            packetcraftr_analysis::pcap::Format::PcapNg => Self::PcapNg,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Timing {
    Original,
    Scaled(f64),
    FixedRate(f64),
    Immediate,
}

impl From<packetcraftr_live::replay::Timing> for Timing {
    fn from(value: packetcraftr_live::replay::Timing) -> Self {
        match value {
            packetcraftr_live::replay::Timing::Original => Self::Original,
            packetcraftr_live::replay::Timing::Scaled(scale) => Self::Scaled(scale),
            packetcraftr_live::replay::Timing::FixedRate(rate) => Self::FixedRate(rate),
            packetcraftr_live::replay::Timing::Immediate => Self::Immediate,
            // See the `field::Kind` conversion: the v1 schema pins this value
            // set, so an added timing policy needs a schema revision.
            _ => unreachable!("replay timing {value:?} has no v1 output representation"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NonmonotonicTimestampPolicy {
    Reject,
    Clamp,
}

impl From<packetcraftr_live::replay::NonmonotonicTimestampPolicy> for NonmonotonicTimestampPolicy {
    fn from(value: packetcraftr_live::replay::NonmonotonicTimestampPolicy) -> Self {
        match value {
            packetcraftr_live::replay::NonmonotonicTimestampPolicy::Reject => Self::Reject,
            packetcraftr_live::replay::NonmonotonicTimestampPolicy::Clamp => Self::Clamp,
            _ => unreachable!("nonmonotonic timestamp policy has no v1 output representation"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TimestampAdjustment {
    NonmonotonicClamped { backward_by: Duration },
}

impl From<packetcraftr_live::replay::TimestampAdjustment> for TimestampAdjustment {
    fn from(value: packetcraftr_live::replay::TimestampAdjustment) -> Self {
        match value {
            packetcraftr_live::replay::TimestampAdjustment::NonmonotonicClamped { backward_by } => {
                Self::NonmonotonicClamped { backward_by }
            }
            _ => unreachable!("timestamp adjustment has no v1 output representation"),
        }
    }
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkMode {
    Auto,
    Layer2,
    Layer3,
}

impl From<NetworkLinkMode> for LinkMode {
    fn from(value: NetworkLinkMode) -> Self {
        match value {
            NetworkLinkMode::Auto => Self::Auto,
            NetworkLinkMode::Layer2 => Self::Layer2,
            NetworkLinkMode::Layer3 => Self::Layer3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Result {
    pub source_format: SourceFormat,
    pub timing: Timing,
    pub nonmonotonic_timestamps: NonmonotonicTimestampPolicy,
    pub requested_interface: Interface,
    pub requested_link_mode: LinkMode,
    pub frames_attempted: u64,
    pub frames_completed: u64,
    pub bytes_completed: u64,
    pub scheduled_duration: Duration,
    pub timestamp_adjustments: u64,
    pub frames: Vec<Frame>,
}

impl Result {
    pub fn from_summary(
        summary: ReplaySummary,
        requested_interface: InterfaceId,
        requested_link_mode: NetworkLinkMode,
        frames: Vec<Frame>,
    ) -> Self {
        Self {
            source_format: summary.source_format.into(),
            timing: summary.timing.into(),
            nonmonotonic_timestamps: summary.nonmonotonic_timestamps.into(),
            requested_interface: requested_interface.into(),
            requested_link_mode: requested_link_mode.into(),
            frames_attempted: summary.frames_attempted,
            frames_completed: summary.frames_completed,
            bytes_completed: summary.bytes_completed,
            scheduled_duration: summary.scheduled_duration,
            timestamp_adjustments: summary.timestamp_adjustments,
            frames,
        }
    }
}

/// One frame record produced by streaming `replay` output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Frame {
    /// Zero-based position in the source capture.
    pub source_index: u64,
    pub interface: Interface,
    pub link_mode: LinkMode,
    pub scheduled_delay: Duration,
    pub timestamp_adjustment: Option<TimestampAdjustment>,
    pub bytes_sent: u64,
    pub frame: Captured,
    pub transmitted: bool,
}

impl Frame {
    pub fn try_from_evidence(evidence: ReplayFrameEvidence) -> std::result::Result<Self, Error> {
        Ok(Self {
            source_index: evidence.source_index,
            interface: evidence.transmission().interface.clone().into(),
            link_mode: evidence.link_mode.into(),
            scheduled_delay: evidence.scheduled_delay,
            timestamp_adjustment: evidence.timestamp_adjustment.map(Into::into),
            bytes_sent: evidence.transmission().report.bytes_sent() as u64,
            frame: Captured::try_from_frame(evidence.frame)?,
            transmitted: true,
        })
    }
}
