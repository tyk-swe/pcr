// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::error::{Classification, Classified, Kind};

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("executor returned evidence for a different execution permit")]
    PermitMismatch,
    #[error("expected {expected} sent receipts, received {receipts}")]
    SentCardinality { expected: usize, receipts: usize },
    #[error("matched response references a request outside the executed step")]
    ResponseOutsideBatch,
    #[error("executor capture frame-count accounting overflowed")]
    CapturedFrameCountOverflow,
    #[error("executor returned {actual} captured frames beyond max_evidence_frames={limit}")]
    CapturedFrameLimitExceeded { actual: usize, limit: usize },
    #[error("executor capture byte accounting overflowed")]
    CapturedByteCountOverflow,
    #[error("executor returned {actual} captured bytes beyond max_evidence_bytes={limit}")]
    CapturedByteLimitExceeded { actual: usize, limit: usize },
    #[error("sent packet does not preserve the requested destination and probe identity")]
    SentPacketMismatch { request_index: usize },
    #[error("sent frame byte accounting overflowed")]
    SentByteCountOverflow,
    #[error("successful exchange reported {reported} sent bytes for {actual} exact frame bytes")]
    SentByteCountMismatch { reported: u64, actual: u64 },
    #[error("executor returned {evidence} without a timestamp")]
    TimestampUnavailable { evidence: &'static str },
    #[error("matched response latency {latency:?} exceeds timeout {timeout:?}")]
    ResponseAfterTimeout {
        latency: Duration,
        timeout: Duration,
    },
    #[error("{message}")]
    InvalidCaptureStatistics { message: String },
    #[error("successful exchange statistics do not account for every request")]
    IncompleteStatistics,
}

impl Error {
    pub(crate) const fn request_index(&self) -> Option<usize> {
        match self {
            Self::SentPacketMismatch { request_index } => Some(*request_index),
            _ => None,
        }
    }

    pub(crate) fn describe(&self, step: &str, workflow: &str) -> String {
        match self {
            Self::ResponseOutsideBatch => {
                format!("matched response references a request outside the {step}")
            }
            Self::SentPacketMismatch { .. } => {
                format!(
                    "sent packet does not preserve the {workflow} destination and probe identity"
                )
            }
            Self::IncompleteStatistics => {
                format!("successful exchange statistics do not account for every {workflow} probe")
            }
            error => error.to_string(),
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        Classification::new(
            "internal.live_io_invariant",
            Kind::Internal,
            Some(
                "report the inconsistent provider result; do not reinterpret it as a successful operation",
            ),
        )
    }
}
