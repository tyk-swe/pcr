// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Failure from a bounded offline analysis run.

use super::{CaptureError, Classification, Classified, DecodeError, Duration, Error, Kind};
use packetcraftr_session::tcp::Error as TcpError;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AnalysisError {
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
        source: DecodeError,
    },
    #[error("conversation table reached the configured limit of {limit} flows at frame {number}")]
    StreamLimit { number: u64, limit: usize },
    #[error("TCP reassembly failed at frame {number}: {source}")]
    Reassembly {
        number: u64,
        #[source]
        source: packetcraftr_session::tcp::Error,
    },
    #[error("analysis ran {actual:?}, exceeding the configured duration of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("capture timestamp at frame {number} exceeds the monotonic analysis clock range")]
    TimestampRange { number: u64 },
    #[error("analysis consumer failed at frame {number}: {source}")]
    Sink {
        number: u64,
        #[source]
        source: crate::BoundaryError,
    },
}

impl Classified for AnalysisError {
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
                source: DecodeError::PacketSizeLimit { .. },
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
            Self::StreamLimit { .. } | Self::DurationLimit { .. } => resource_limit(),
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
