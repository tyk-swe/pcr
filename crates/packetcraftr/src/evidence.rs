// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_core::error::{Classification, Classified, Kind};
use packetcraftr_core::{build::BuiltPacket, diagnostic::Diagnostic, frame::Frame};
use packetcraftr_netio::{
    Error as LiveIoError,
    transmit::{Report as TransmissionReport, SendEvidenceFault, Timing as TransmissionTiming},
};

/// What a workflow retains as evidence: matched/unmatched frames and their bytes, and undecoded frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    #[serde(rename = "max_evidence_frames")]
    pub max_frames: usize,
    #[serde(rename = "max_evidence_bytes")]
    pub max_bytes: usize,
    pub max_undecoded: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frames: packetcraftr_netio::capture::MAX_CAPTURE_QUEUE_FRAMES,
            max_bytes: packetcraftr_netio::capture::MAX_CAPTURE_QUEUE_BYTES,
            max_undecoded: crate::scan::DEFAULT_MAX_UNDECODED_FRAMES,
        }
    }
}

impl Limits {
    pub(crate) fn validate<E>(
        &self,
        invalid: impl Fn(&'static str, u64, String) -> E,
    ) -> Result<(), E> {
        crate::execution::limits::check_limits(
            &[
                (
                    "max_evidence_frames",
                    self.max_frames,
                    packetcraftr_netio::capture::MAX_CAPTURE_QUEUE_FRAMES,
                ),
                (
                    "max_evidence_bytes",
                    self.max_bytes,
                    packetcraftr_netio::capture::MAX_CAPTURE_QUEUE_BYTES,
                ),
            ],
            &[(
                "max_undecoded",
                self.max_undecoded,
                self.max_frames,
                "cannot exceed max_evidence_frames",
            )],
            invalid,
        )
    }
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExecutionPermit(u64);

impl ExecutionPermit {
    /// The 64-bit counter cannot wrap within a process lifetime, so no overflow branch exists.
    pub(crate) fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

#[derive(Debug, Default)]
pub(crate) struct DiagnosticLog {
    entries: Vec<Diagnostic>,
    published: usize,
}

impl DiagnosticLog {
    pub(crate) fn push_once(&mut self, diagnostic: Diagnostic) {
        packetcraftr_core::diagnostic::push_once(&mut self.entries, diagnostic);
    }

    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[Diagnostic] {
        &self.entries
    }

    /// A failing `publish` leaves its entry unpublished rather than skipping the remainder.
    pub(crate) fn publish_new<E>(
        &mut self,
        mut publish: impl FnMut(Diagnostic) -> Result<(), E>,
    ) -> Result<(), E> {
        while let Some(diagnostic) = self.entries.get(self.published).cloned() {
            publish(diagnostic)?;
            self.published = self.published.saturating_add(1);
        }
        Ok(())
    }
}

/// Shared by exchange statistics and the evidence validator, so they never disagree on the total.
pub(crate) fn total_bytes_sent<'a>(sent: impl IntoIterator<Item = &'a SentPacket>) -> Option<u64> {
    sent.into_iter().try_fold(0_u64, |total, sent| {
        total.checked_add(u64::try_from(sent.bytes_sent()).unwrap_or(u64::MAX))
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetentionError {
    FrameCountOverflow,
    FrameLimit,
    ByteCountOverflow,
    ByteLimit,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct RetentionBudget {
    retained_frames: usize,
    retained_bytes: usize,
}

impl RetentionBudget {
    pub(crate) fn reserve(
        &mut self,
        additional_bytes: usize,
        max_frames: usize,
        max_bytes: usize,
    ) -> Result<(), RetentionError> {
        let next_frames = self
            .retained_frames
            .checked_add(1)
            .ok_or(RetentionError::FrameCountOverflow)?;
        if next_frames > max_frames {
            return Err(RetentionError::FrameLimit);
        }
        let next_bytes = self
            .retained_bytes
            .checked_add(additional_bytes)
            .ok_or(RetentionError::ByteCountOverflow)?;
        if next_bytes > max_bytes {
            return Err(RetentionError::ByteLimit);
        }
        self.retained_frames = next_frames;
        self.retained_bytes = next_bytes;
        Ok(())
    }

    pub(crate) fn replace(
        &mut self,
        previous_bytes: Option<usize>,
        additional_bytes: usize,
        max_frames: usize,
        max_bytes: usize,
    ) -> Result<(), RetentionError> {
        let mut next = *self;
        if let Some(bytes) = previous_bytes {
            next.release(bytes);
        }
        next.reserve(additional_bytes, max_frames, max_bytes)?;
        *self = next;
        Ok(())
    }

    pub(crate) fn bytes(&self) -> usize {
        self.retained_bytes
    }

    pub(crate) fn release(&mut self, bytes: usize) {
        let frames = self
            .retained_frames
            .checked_sub(1)
            .expect("released frame was retained");
        let bytes = self
            .retained_bytes
            .checked_sub(bytes)
            .expect("released bytes were retained");
        self.retained_frames = frames;
        self.retained_bytes = bytes;
    }
}

/// Opaque evidence tying a build and route to the exact bytes one provider call accepted.
#[derive(Clone, Debug)]
pub struct SentPacket {
    built: BuiltPacket,
    route: crate::route::Materialized,
    report: TransmissionReport,
    frame: Frame,
}

impl SentPacket {
    pub fn try_new(
        built: BuiltPacket,
        route: crate::route::Materialized,
        report: TransmissionReport,
    ) -> Result<Self, LiveIoError> {
        report.validate_exact(&built.bytes)?;
        let link_type = route.plan.wire_link_type()?;
        let frame = Frame::new(
            report.timing().freshness_marker().wall_clock(),
            link_type,
            report.wire_bytes().clone(),
        )
        .map_err(|source| LiveIoError::InvalidSendEvidence {
            fault: SendEvidenceFault::from(source),
        })?;
        Ok(Self {
            built,
            route,
            report,
            frame,
        })
    }

    pub fn built(&self) -> &BuiltPacket {
        &self.built
    }

    pub fn route(&self) -> &crate::route::Materialized {
        &self.route
    }

    pub fn wire_bytes(&self) -> &bytes::Bytes {
        self.report.wire_bytes()
    }

    pub fn bytes_sent(&self) -> usize {
        self.report.bytes_sent()
    }

    pub fn timing(&self) -> TransmissionTiming {
        self.report.timing()
    }

    pub fn frame(&self) -> &Frame {
        &self.frame
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn frame_limit_and_overflow_leave_counters_untouched() {
        let mut budget = RetentionBudget {
            retained_frames: 1,
            retained_bytes: 3,
        };
        assert_eq!(budget.reserve(1, 1, 10), Err(RetentionError::FrameLimit));
        assert_eq!((budget.retained_frames, budget.retained_bytes), (1, 3));

        budget.retained_frames = usize::MAX;
        assert_eq!(
            budget.reserve(1, usize::MAX, 10),
            Err(RetentionError::FrameCountOverflow)
        );
        assert_eq!(
            (budget.retained_frames, budget.retained_bytes),
            (usize::MAX, 3)
        );
    }

    #[test]
    fn byte_limit_and_overflow_leave_counters_untouched() {
        let mut budget = RetentionBudget {
            retained_frames: 1,
            retained_bytes: 9,
        };
        assert_eq!(budget.reserve(2, 10, 10), Err(RetentionError::ByteLimit));
        assert_eq!((budget.retained_frames, budget.retained_bytes), (1, 9));

        budget.retained_bytes = usize::MAX;
        assert_eq!(
            budget.reserve(1, 10, usize::MAX),
            Err(RetentionError::ByteCountOverflow)
        );
        assert_eq!(
            (budget.retained_frames, budget.retained_bytes),
            (1, usize::MAX)
        );
    }

    #[test]
    fn workflow_limits_serialize_the_evidence_ceilings_at_the_top_level() {
        let value = serde_json::to_value(crate::scan::Limits::default()).unwrap();
        let object = value.as_object().unwrap();
        for key in ["max_evidence_frames", "max_evidence_bytes", "max_undecoded"] {
            assert!(object.contains_key(key), "{key}");
        }
        assert!(!object.contains_key("evidence"));
        let round_trip: crate::scan::Limits = serde_json::from_value(value).unwrap();
        assert_eq!(round_trip, crate::scan::Limits::default());
    }
}
