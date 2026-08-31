// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// Failure from a bounded replay operation.
use std::time::Duration;

use packetcraftr_core::analysis::pcap::Error as CaptureError;
use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};
use packetcraftr_netio::{Error as LiveIoError, link::Mode as LinkMode};
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid replay limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: &'static str,
    },
    #[error("replay duration {value:?} is invalid; maximum is {maximum:?}")]
    InvalidDuration { value: Duration, maximum: Duration },
    #[error("invalid replay timing: invalid replay {mode} value {value}")]
    InvalidTiming { mode: &'static str, value: f64 },
    #[error(
        "replay timing failed at source index {source_index}: invalid replay {mode} value {value}"
    )]
    Timing {
        source_index: u64,
        mode: &'static str,
        value: f64,
    },
    #[error(
        "replay {mode} timing requires a timestamp at source index {source_index}, but none is available"
    )]
    TimestampUnavailable {
        source_index: u64,
        mode: &'static str,
    },
    #[error("capture read failed at source index {source_index}: {source}")]
    Capture {
        source_index: u64,
        #[source]
        source: CaptureError,
    },
    #[error(
        "replay frame count {actual} exceeds the configured limit of {limit} at source index {source_index}"
    )]
    SourceFrameLimit {
        source_index: u64,
        actual: u64,
        limit: u64,
    },
    #[error(
        "replay byte count {actual} exceeds the configured limit of {limit} at source index {source_index}"
    )]
    TransmittedByteLimit {
        source_index: u64,
        actual: u64,
        limit: u64,
    },
    #[error(
        "source index {source_index} contains {actual} bytes, exceeding the per-frame limit of {limit}"
    )]
    FrameSizeLimit {
        source_index: u64,
        actual: usize,
        limit: usize,
    },
    #[error(
        "replay schedule {actual:?} exceeds the configured duration of {limit:?} at source index {source_index}"
    )]
    DurationLimit {
        source_index: u64,
        actual: Duration,
        limit: Duration,
    },
    #[error(
        "capture link type {link_type} is not supported for live replay at source index {source_index}"
    )]
    UnsupportedLinkType { source_index: u64, link_type: u32 },
    #[error(
        "capture link type {link_type} is incompatible with requested {requested:?} replay at source index {source_index}"
    )]
    LinkModeMismatch {
        source_index: u64,
        link_type: u32,
        requested: LinkMode,
    },
    #[error("replay frame selection failed at source index {source_index}: {source}")]
    Selection {
        source_index: u64,
        #[source]
        source: crate::BoundaryError,
    },
    #[error("replay policy denied source index {source_index}: {source}")]
    Authorization {
        source_index: u64,
        #[source]
        source: crate::BoundaryError,
    },
    #[error("replay transmission failed at source index {source_index}: {source}")]
    Transmission {
        source_index: u64,
        #[source]
        source: LiveIoError,
    },
    #[error(
        "replay transmitter returned invalid evidence at source index {source_index}: {message}"
    )]
    InvalidEvidence { source_index: u64, message: String },
    #[error("replay clock failed at source index {source_index}")]
    Clock {
        source_index: u64,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("replay output failed at source index {source_index}: {message}")]
    Output { source_index: u64, message: String },
}

impl Error {
    pub fn output_at_source_index(source_index: u64, message: impl Into<String>) -> Self {
        Self::Output {
            source_index,
            message: message.into(),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        let source_index = match self {
            Self::Timing { source_index, .. }
            | Self::TimestampUnavailable { source_index, .. }
            | Self::Capture { source_index, .. }
            | Self::SourceFrameLimit { source_index, .. }
            | Self::TransmittedByteLimit { source_index, .. }
            | Self::FrameSizeLimit { source_index, .. }
            | Self::DurationLimit { source_index, .. }
            | Self::UnsupportedLinkType { source_index, .. }
            | Self::LinkModeMismatch { source_index, .. }
            | Self::Selection { source_index, .. }
            | Self::Authorization { source_index, .. }
            | Self::Transmission { source_index, .. }
            | Self::InvalidEvidence { source_index, .. }
            | Self::Clock { source_index, .. }
            | Self::Output { source_index, .. } => *source_index,
            Self::InvalidLimit { .. }
            | Self::InvalidDuration { .. }
            | Self::InvalidTiming { .. } => {
                return None;
            }
        };
        Some(Coordinate::SourceFrame(source_index.saturating_add(1)))
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidLimit { .. }
            | Self::InvalidDuration { .. }
            | Self::InvalidTiming { .. } => Classification::new(
                "cli.replay_limit",
                Kind::Cli,
                Some("use finite non-zero replay limits and a valid positive timing value"),
            ),
            Self::Capture { source, .. } => source.classification(),
            Self::SourceFrameLimit { .. }
            | Self::TransmittedByteLimit { .. }
            | Self::DurationLimit { .. } => Classification::new(
                "policy.replay_limit",
                Kind::Policy,
                Some("reduce the replay input or deliberately raise the finite operation budget"),
            ),
            Self::FrameSizeLimit { .. } => Classification::new(
                "packet.capture_size",
                Kind::Packet,
                Some(
                    "reduce the captured frame size or deliberately raise the bounded frame limit",
                ),
            ),
            Self::Timing { .. } => Classification::new(
                "packet.replay_timing",
                Kind::Packet,
                Some("reduce the captured interval or select a bounded replay timing"),
            ),
            Self::TimestampUnavailable { .. } => Classification::new(
                "packet.timestamp_unavailable",
                Kind::Packet,
                Some("select bounded fixed-rate or immediate replay timing"),
            ),
            Self::UnsupportedLinkType { .. } | Self::LinkModeMismatch { .. } => {
                Classification::new(
                    "capability.replay_link_type",
                    Kind::Capability,
                    Some(
                        "replay complete Ethernet frames through Layer 2 or raw IPv4/IPv6 datagrams through Layer 3",
                    ),
                )
            }
            Self::Selection { source, .. } | Self::Authorization { source, .. } => {
                source.classification()
            }
            Self::Transmission { source, .. } => source.classification(),
            Self::InvalidEvidence { .. } => Classification::new(
                "internal.replay_evidence",
                Kind::Internal,
                Some(
                    "treat the operation as incomplete; the backend did not confirm the exact submitted bytes",
                ),
            ),
            Self::Clock { .. } | Self::Output { .. } => Classification::new(
                "io.replay",
                Kind::Io,
                Some(
                    "inspect the replay timer or output sink and account for frames already transmitted",
                ),
            ),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        Error::context(self)
    }

    /// Walked from the retained `#[source]` chain rather than hand-written.
    /// The two boundary-sourced variants delegate instead: a [`BoundaryError`]
    /// carries a captured `causes` snapshot its own source chain no longer
    /// holds.
    ///
    /// [`BoundaryError`]: crate::BoundaryError
    fn causes(&self) -> Vec<String> {
        match self {
            Self::Selection { source, .. } | Self::Authorization { source, .. } => source.causes(),
            error => packetcraftr_core::error::source_chain(error),
        }
    }
}
