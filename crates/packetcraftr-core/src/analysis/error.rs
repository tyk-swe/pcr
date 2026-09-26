// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;
use thiserror::Error;

use crate::capture_file::Error as CaptureError;

use crate::error::{Classification, Classified, Kind};

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Provenance(#[from] crate::analysis::provenance::Error),
    #[error(transparent)]
    Cancelled(#[from] crate::budget::Cancelled),
    #[error("invalid analysis limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: Constraint,
    },
    #[error("capture read failed at frame {number}")]
    Capture {
        number: u64,
        #[source]
        source: CaptureError,
    },
    #[error("dissection failed at frame {number}")]
    Decode {
        number: u64,
        #[source]
        source: crate::decode::Error,
    },
    #[error("derived IP datagram construction failed at frame {number}")]
    DerivedFrame {
        number: u64,
        #[source]
        source: crate::frame::Error,
    },
    #[error("derived IP datagram dissection failed at frame {number}")]
    DerivedDecode {
        number: u64,
        #[source]
        source: crate::decode::Error,
    },
    #[error("display filter failed at frame {number}")]
    Filter {
        number: u64,
        #[source]
        source: crate::filter::Error,
    },
    #[error(
        "capture-global conversation index reached its limit of {limit} distinct conversations per transport at frame {number}"
    )]
    StreamLimit { number: u64, limit: usize },
    #[error("capture scope indexing failed at frame {number}")]
    Scope {
        number: u64,
        #[source]
        source: crate::analysis::scope::Error,
    },
    #[error("TCP reassembly failed at frame {number}")]
    Reassembly {
        number: u64,
        #[source]
        source: crate::analysis::reassembly::tcp::Error,
    },
    #[error("IP reassembly failed at frame {number}")]
    IpReassembly {
        number: u64,
        #[source]
        source: crate::analysis::reassembly::ip::Error,
    },
    #[error("analysis ran {actual:?}, exceeding the configured duration of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("capture timestamp at frame {number} exceeds the monotonic analysis clock range")]
    TimestampRange { number: u64 },
    #[error("capture frame {number} has no timestamp required by offline analysis")]
    TimestampUnavailable { number: u64 },
    #[error("analysis consumer failed at frame {number}")]
    Sink {
        number: u64,
        #[source]
        source: crate::error::BoundaryError,
    },
    /// A [`Session`](super::Session) collector's `finish` or its trailing
    /// event drain failed after the run completed.
    #[error(transparent)]
    Collector(crate::error::BoundaryError),
}

/// The rule an [`Error::InvalidLimit`] value breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Constraint {
    NonZero,
    /// The per-frame byte limit cannot exceed the total byte limit.
    AtMostMaxBytes,
    /// A TCP per-flow window must stay below the serial-number half-space.
    BelowSerialHalfSpace,
    /// A duration must fit the platform monotonic clock.
    WithinClockRange,
    /// A TLS buffer must hold one direction's largest handshake.
    AtLeastTlsDirectionBuffer,
    /// A duration cannot exceed the one-hour invocation ceiling.
    AtMostOneHour,
}

impl std::fmt::Display for Constraint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonZero => formatter.write_str("must be non-zero"),
            Self::AtMostMaxBytes => formatter.write_str("cannot exceed max_bytes"),
            Self::BelowSerialHalfSpace => {
                formatter.write_str("reaches the TCP serial-number half-space")
            }
            Self::WithinClockRange => {
                formatter.write_str("exceeds the platform monotonic-clock range")
            }
            Self::AtLeastTlsDirectionBuffer => write!(
                formatter,
                "cannot be below the per-direction handshake buffer of {} bytes",
                super::tls::MAX_DIRECTION_BUFFER
            ),
            Self::AtMostOneHour => formatter.write_str("exceeds the one-hour ceiling"),
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Cancelled(source) => source.classification(),
            Self::Provenance(source) => source.classification(),
            Self::DurationLimit { .. } => Classification::new(
                "policy.duration_limit",
                Kind::Policy,
                Some("reduce input or raise the finite invocation duration"),
            ),
            Self::InvalidLimit { .. } => Classification::new(
                "cli.analysis_limit",
                Kind::Usage,
                Some("use finite non-zero analysis frame, byte, flow, and duration limits"),
            ),
            Self::Capture { source, .. } => source.classification(),
            // Refusals for exceeding a configured finite budget are resource
            // conditions, not malformed input.
            Self::Decode {
                source:
                    crate::decode::Error::PacketSizeLimit { .. }
                    | crate::decode::Error::LayerLimit { .. },
                ..
            }
            | Self::DerivedDecode {
                source:
                    crate::decode::Error::PacketSizeLimit { .. }
                    | crate::decode::Error::LayerLimit { .. },
                ..
            }
            | Self::StreamLimit { .. } => resource_limit(GENERAL_RESOURCE_REMEDIATION),
            // Malformed bytes dissect as diagnosed layers, so a decode error is
            // a registry or codec-contract condition the error names itself.
            Self::Decode { source, .. } | Self::DerivedDecode { source, .. } => {
                source.classification()
            }
            Self::DerivedFrame { .. } => Classification::new(
                "internal.derived_frame",
                Kind::Internal,
                Some("report the capture and command as an internal reconstruction failure"),
            ),
            Self::TimestampRange { .. } => Classification::new(
                "packet.timestamp",
                Kind::Packet,
                Some("repair the capture timestamp that exceeds the platform clock range"),
            ),
            Self::TimestampUnavailable { .. } => Classification::new(
                "packet.timestamp_unavailable",
                Kind::Packet,
                Some("use timestamped packet blocks for time-dependent offline analysis"),
            ),
            Self::Filter { source, .. } => source.classification(),
            Self::Scope { source, .. } => source.classification(),
            Self::Reassembly { source, .. } => source.classification(),
            Self::IpReassembly { source, .. } => source.classification(),
            Self::Sink { source, .. } | Self::Collector(source) => source.classification(),
        }
    }

    /// Walked from the retained `#[source]` chain rather than hand-written.
    /// The consumer variant delegates instead: a [`BoundaryError`] carries a
    /// captured `causes` snapshot that its own source chain no longer holds.
    ///
    /// [`BoundaryError`]: crate::error::BoundaryError
    fn causes(&self) -> Vec<String> {
        match self {
            Self::Sink { source, .. } => source.as_causes(),
            Self::Collector(source) => source.causes(),
            error => crate::error::source_chain(error),
        }
    }
}

crate::budget::deadline_error_conversions!(Error);

pub(super) const GENERAL_RESOURCE_REMEDIATION: &str = "trim the capture before analysis or deliberately raise the finite budget; display filters do not reduce physical input, conversation-index, or scope costs";
pub(super) fn resource_limit(remediation: &'static str) -> Classification {
    Classification::new(
        "policy.analysis_resource_limit",
        Kind::Policy,
        Some(remediation),
    )
}

/// Reassembly fails for two distinct reasons: a finite budget was exhausted,
/// or the capture itself carries conflicting data. Only the former is
/// answered by raising budgets, so the latter has its own classification.
pub(super) fn malformed_reassembly() -> Classification {
    Classification::new(
        "packet.reassembly",
        Kind::Packet,
        Some(
            "the capture carries conflicting or malformed reassembly data; inspect the flow \
             rather than raising budgets",
        ),
    )
}
