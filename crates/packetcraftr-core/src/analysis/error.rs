// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Failure from a bounded offline analysis run.

use std::time::Duration;
use thiserror::Error;

use crate::analysis::pcap::Error as CaptureError;
use crate::analysis::reassembly::tcp::Error as TcpError;

use crate::error::{Classification, Classified, Kind};

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid analysis limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: &'static str,
    },
    #[error("capture read failed at frame {number}: {source}")]
    Capture {
        number: u64,
        #[source]
        source: CaptureError,
    },
    #[error("dissection failed at frame {number}: {source}")]
    Decode {
        number: u64,
        #[source]
        source: crate::decode::Error,
    },
    #[error("display filter failed at frame {number}: {source}")]
    Filter {
        number: u64,
        #[source]
        source: crate::filter::Error,
    },
    #[error("conversation table reached the configured limit of {limit} flows at frame {number}")]
    StreamLimit { number: u64, limit: usize },
    #[error("capture scope indexing failed at frame {number}: {source}")]
    Scope {
        number: u64,
        #[source]
        source: crate::analysis::scope::Error,
    },
    #[error("TCP reassembly failed at frame {number}: {source}")]
    Reassembly {
        number: u64,
        #[source]
        source: crate::analysis::reassembly::tcp::Error,
    },
    #[error("analysis ran {actual:?}, exceeding the configured duration of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("capture timestamp at frame {number} exceeds the monotonic analysis clock range")]
    TimestampRange { number: u64 },
    #[error("capture frame {number} has no timestamp required by offline analysis")]
    TimestampUnavailable { number: u64 },
    #[error("analysis consumer failed at frame {number}: {source}")]
    Sink {
        number: u64,
        #[source]
        source: crate::error::BoundaryError,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidLimit { .. } => Classification::new(
                "cli.analysis_limit",
                Kind::Cli,
                Some("use finite non-zero analysis frame, byte, flow, and duration limits"),
            ),
            Self::Capture { source, .. } => source.classification(),
            // A frame refused for exceeding the configured per-frame budget
            // is a resource condition, not malformed input.
            Self::Decode {
                source: crate::decode::Error::PacketSizeLimit { .. },
                ..
            } => resource_limit(),
            Self::Decode { .. } => Classification::new(
                "packet.decode",
                Kind::Packet,
                Some("repair the frame or raise the per-frame byte limit it was read under"),
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
            Self::Filter {
                source: crate::filter::Error::TimestampUnavailable,
                ..
            } => Classification::new(
                "packet.timestamp_unavailable",
                Kind::Packet,
                Some("remove frame.time_epoch from the filter or use timestamped packet blocks"),
            ),
            Self::Filter { .. } => {
                Classification::new("cli.filter", Kind::Cli, Some("repair the display filter"))
            }
            Self::StreamLimit { .. } | Self::Scope { .. } | Self::DurationLimit { .. } => {
                resource_limit()
            }
            // Reassembly fails for two distinct reasons: a finite budget was
            // exhausted, or the capture itself carries conflicting data. Only
            // the former is answered by raising budgets.
            Self::Reassembly { source, .. } => match source {
                TcpError::FlowLimit { .. }
                | TcpError::SegmentLimit { .. }
                | TcpError::FlowByteLimit { .. }
                | TcpError::AggregateByteLimit { .. }
                | TcpError::AllocationFailed { .. }
                | TcpError::InvalidWindowLimit { .. } => resource_limit(),
                _ => malformed_reassembly(),
            },
            Self::Sink { source, .. } => source.classification(),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Capture { source, .. } => vec![source.to_string()],
            Self::Decode { source, .. } => vec![source.to_string()],
            Self::Filter { source, .. } => vec![source.to_string()],
            Self::Scope { source, .. } => vec![source.to_string()],
            Self::Reassembly { source, .. } => vec![source.to_string()],
            Self::Sink { source, .. } => source.causes(),
            _ => Vec::new(),
        }
    }
}

fn resource_limit() -> Classification {
    Classification::new(
        "policy.analysis_resource_limit",
        Kind::Policy,
        Some("narrow the input with a filter or deliberately raise the finite analysis budget"),
    )
}

fn malformed_reassembly() -> Classification {
    Classification::new(
        "packet.reassembly",
        Kind::Packet,
        Some(
            "the capture carries conflicting or malformed reassembly data; inspect the flow \
             rather than raising budgets",
        ),
    )
}
