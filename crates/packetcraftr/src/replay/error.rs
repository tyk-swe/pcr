// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// Failure from a bounded replay operation.
use std::time::Duration;

use packetcraftr_core::analysis::pcap::Error as CaptureError;
use packetcraftr_core::error::{Classification, Classified, Kind};
use packetcraftr_netio::{Error as LiveIoError, link::Mode as LinkMode};
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReplayError {
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
    #[error("replay timing failed at source frame {sequence}: invalid replay {mode} value {value}")]
    Timing {
        sequence: u64,
        mode: &'static str,
        value: f64,
    },
    #[error(
        "replay {mode} timing requires a timestamp at source frame {sequence}, but none is available"
    )]
    TimestampUnavailable { sequence: u64, mode: &'static str },
    #[error("capture read failed at source frame {sequence}: {source}")]
    Capture {
        sequence: u64,
        #[source]
        source: CaptureError,
    },
    #[error(
        "replay frame count {actual} exceeds the configured limit of {limit} at source frame {sequence}"
    )]
    FrameLimit {
        sequence: u64,
        actual: u64,
        limit: u64,
    },
    #[error(
        "replay byte count {actual} exceeds the configured limit of {limit} at source frame {sequence}"
    )]
    ByteLimit {
        sequence: u64,
        actual: u64,
        limit: u64,
    },
    #[error(
        "source frame {sequence} contains {actual} bytes, exceeding the per-frame limit of {limit}"
    )]
    FrameSizeLimit {
        sequence: u64,
        actual: usize,
        limit: usize,
    },
    #[error(
        "replay schedule {actual:?} exceeds the configured duration of {limit:?} at source frame {sequence}"
    )]
    DurationLimit {
        sequence: u64,
        actual: Duration,
        limit: Duration,
    },
    #[error(
        "capture link type {link_type} is not supported for live replay at source frame {sequence}"
    )]
    UnsupportedLinkType { sequence: u64, link_type: u32 },
    #[error(
        "capture link type {link_type} is incompatible with requested {requested:?} replay at source frame {sequence}"
    )]
    LinkModeMismatch {
        sequence: u64,
        link_type: u32,
        requested: LinkMode,
    },
    #[error("replay frame selection failed at source frame {sequence}: {source}")]
    Selection {
        sequence: u64,
        #[source]
        source: crate::BoundaryError,
    },
    #[error("replay policy denied source frame {sequence}: {source}")]
    Authorization {
        sequence: u64,
        #[source]
        source: crate::BoundaryError,
    },
    #[error("replay transmission failed at source frame {sequence}: {source}")]
    Transmission {
        sequence: u64,
        #[source]
        source: LiveIoError,
    },
    #[error("replay transmitter returned invalid evidence at source frame {sequence}: {message}")]
    InvalidEvidence { sequence: u64, message: String },
    #[error("replay clock failed at source frame {sequence}: {message}")]
    Clock { sequence: u64, message: String },
    #[error("replay output failed at source frame {sequence}: {message}")]
    Output { sequence: u64, message: String },
}

impl ReplayError {
    pub fn output(sequence: u64, message: impl Into<String>) -> Self {
        Self::Output {
            sequence,
            message: message.into(),
        }
    }

    pub fn sequence(&self) -> Option<u64> {
        match self {
            Self::Capture { sequence, .. }
            | Self::FrameLimit { sequence, .. }
            | Self::ByteLimit { sequence, .. }
            | Self::FrameSizeLimit { sequence, .. }
            | Self::DurationLimit { sequence, .. }
            | Self::UnsupportedLinkType { sequence, .. }
            | Self::LinkModeMismatch { sequence, .. }
            | Self::Timing { sequence, .. }
            | Self::TimestampUnavailable { sequence, .. }
            | Self::Selection { sequence, .. }
            | Self::Authorization { sequence, .. }
            | Self::Transmission { sequence, .. }
            | Self::InvalidEvidence { sequence, .. }
            | Self::Clock { sequence, .. }
            | Self::Output { sequence, .. } => Some(*sequence),
            _ => None,
        }
    }
}

impl Classified for ReplayError {
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
            Self::FrameLimit { .. } | Self::ByteLimit { .. } | Self::DurationLimit { .. } => {
                Classification::new(
                    "policy.replay_limit",
                    Kind::Policy,
                    Some(
                        "reduce the replay input or deliberately raise the finite operation budget",
                    ),
                )
            }
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

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Selection { source, .. } | Self::Authorization { source, .. } => source.causes(),
            Self::Transmission { source, .. } => source.causes(),
            Self::Capture { source, .. } => vec![source.to_string()],
            Self::InvalidTiming { mode, value } | Self::Timing { mode, value, .. } => {
                vec![format!("invalid replay {mode} value {value}")]
            }
            _ => Vec::new(),
        }
    }
}
