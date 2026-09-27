// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Evidence every live workflow shares: the exact [`SentPacket`] a
//! transmission produced, and the [`Error`] for evidence an executor returned
//! that is inconsistent with the step it was granted.

use std::time::Duration;

use packetcraftr_core::error::{Classification, Classified, Kind};
use packetcraftr_core::{build::BuiltPacket, diagnostic::Diagnostic, frame::Frame};
use packetcraftr_netio::{
    Error as LiveIoError, SendEvidenceFault,
    transmit::{Report as TransmissionReport, Timing as TransmissionTiming},
};

/// Why the evidence an executor returned for one step is inconsistent with
/// the step it was granted: the exact sent packets and bytes, the captured
/// responses and their timing, capture statistics, or evidence limits.
///
/// Workflows report it at the step it concerns, in their own error.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The evidence is bound to a different execution permit than the one
    /// the step was granted.
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
    /// The packet at `request_index` does not carry the destination and
    /// probe identity the step requested.
    #[error("sent packet does not preserve the requested destination and probe identity")]
    SentPacketMismatch { request_index: usize },
    #[error("sent frame byte accounting overflowed")]
    SentByteCountOverflow,
    #[error("successful exchange reported {reported} sent bytes for {actual} exact frame bytes")]
    SentByteCountMismatch { reported: u64, actual: u64 },
    #[error("executor returned {evidence} without a timestamp")]
    TimestampUnavailable { evidence: &'static str },
    #[error("{message}")]
    InvalidMatchedResponse { message: String },
    #[error("matched response latency {latency:?} exceeds timeout {timeout:?}")]
    ResponseAfterTimeout {
        latency: Duration,
        timeout: Duration,
    },
    #[error("{message}")]
    InvalidUnsolicitedResponse { message: String },
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

    /// The message a workflow reports, naming what one executed step is
    /// (`step`, such as "hop batch") and the workflow (`workflow`) where the
    /// neutral [`Display`](std::fmt::Display) text leaves them generic.
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

/// Inconsistent evidence breaks the executor's contract with the workflow;
/// each workflow reports it at the step it concerns with its own code.
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
    /// Issues a process-unique permit. The 64-bit counter cannot wrap within
    /// the lifetime of a process, so no overflow branch exists.
    pub(crate) fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

/// Append-only diagnostics with a publication cursor, so callers receive only
/// entries added since their last read.
#[derive(Debug, Default)]
pub(crate) struct DiagnosticLog {
    entries: Vec<Diagnostic>,
    published: usize,
}

impl DiagnosticLog {
    pub(crate) fn push_once(&mut self, diagnostic: Diagnostic) {
        packetcraftr_core::diagnostic::push_once(&mut self.entries, diagnostic);
    }

    /// Every diagnostic recorded so far, published or not.
    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[Diagnostic] {
        &self.entries
    }

    /// Hands `publish` each diagnostic recorded since the previous call and
    /// advances the cursor past it.
    ///
    /// The cursor advances one entry at a time, so a failing `publish` leaves
    /// the entry it failed on unpublished rather than skipping the remainder.
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

/// Total wire bytes across trusted send receipts, or [`None`] when the sum
/// overflows.
///
/// The single fold behind both the statistics an exchange publishes and the
/// evidence validator that re-checks them, so the two can never disagree about
/// how the total is computed.
pub(crate) fn total_bytes_sent<'a>(sent: impl IntoIterator<Item = &'a SentPacket>) -> Option<u64> {
    sent.into_iter().try_fold(0_u64, |total, sent| {
        total.checked_add(u64::try_from(sent.bytes_sent()).unwrap_or(u64::MAX))
    })
}

/// Why a frame could not be retained: a retention limit was reached or a
/// counter would overflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetentionError {
    FrameCountOverflow,
    FrameLimit,
    ByteCountOverflow,
    ByteLimit,
}

/// The retention budget: frames and bytes of evidence kept so far, charged
/// against a workflow's evidence limits.
#[derive(Default)]
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
}

/// Opaque evidence tying a semantic build and route to the exact bytes and
/// timing accepted by one transmission provider call.
#[derive(Clone, Debug)]
pub struct SentPacket {
    built: BuiltPacket,
    route: crate::route::Materialized,
    report: TransmissionReport,
    frame: Frame,
}

impl SentPacket {
    /// Validates a provider receipt against the exact built bytes and route,
    /// then creates trusted sent evidence.
    ///
    /// # Errors
    ///
    /// Returns an I/O contract error when the receipt does not confirm the
    /// complete exact transmission or the route has no resolved link mode.
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
    use bytes::Bytes;
    use packetcraftr_core::{layer::Raw, packet::Packet};
    use packetcraftr_netio::transmit::Submission;

    use super::*;

    #[test]
    fn a_diagnostic_log_publishes_each_entry_once_and_deduplicates_repeats() {
        let mut log = DiagnosticLog::default();
        let mut published: Vec<String> = Vec::new();

        log.push_once(Diagnostic::warning("test.one", "first"));
        log.push_once(Diagnostic::warning("test.one", "first"));
        log.publish_new::<()>(|diagnostic| {
            published.push(diagnostic.code.to_string());
            Ok(())
        })
        .expect("publishing cannot fail");
        assert_eq!(published, vec!["test.one".to_owned()]);

        log.publish_new::<()>(|_| panic!("already-published entries are never republished"))
            .expect("publishing cannot fail");

        log.push_once(Diagnostic::warning("test.two", "second"));
        log.publish_new::<()>(|diagnostic| {
            published.push(diagnostic.code.to_string());
            Ok(())
        })
        .expect("publishing cannot fail");
        assert_eq!(
            published,
            vec!["test.one".to_owned(), "test.two".to_owned()]
        );
        assert_eq!(log.as_slice().len(), 2);
    }

    #[test]
    fn a_failed_publication_leaves_its_entry_unpublished() {
        let mut log = DiagnosticLog::default();
        log.push_once(Diagnostic::warning("test.one", "first"));
        log.push_once(Diagnostic::warning("test.two", "second"));

        let mut seen = 0_usize;
        assert_eq!(
            log.publish_new(|_| {
                seen += 1;
                Err::<(), _>("sink closed")
            }),
            Err("sink closed")
        );
        assert_eq!(seen, 1);

        let mut retried: Vec<String> = Vec::new();
        log.publish_new::<()>(|diagnostic| {
            retried.push(diagnostic.code.to_string());
            Ok(())
        })
        .expect("publishing cannot fail");
        assert_eq!(retried, vec!["test.one".to_owned(), "test.two".to_owned()]);
    }

    #[test]
    fn sent_receipt_rejects_semantic_build_with_different_accepted_bytes() {
        let mut packet = Packet::new();
        packet.push(Raw::new(Bytes::from_static(&[1, 2, 3])));
        let fixture = crate::test_support::sent_packet(packet);
        let built = fixture.built.clone();
        let route = fixture.route.clone();
        let report = Submission::start().complete(3, Bytes::from_static(&[3, 2, 1]));

        assert!(matches!(
            SentPacket::try_new(built, route, report),
            Err(LiveIoError::InvalidSendEvidence { .. })
        ));
    }

    #[test]
    fn reservation_commits_both_counters_only_when_every_bound_fits() {
        let mut budget = RetentionBudget {
            retained_frames: 1,
            retained_bytes: 10,
        };
        assert_eq!(budget.reserve(5, 2, 15), Ok(()));
        assert_eq!((budget.retained_frames, budget.retained_bytes), (2, 15));
    }

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
}
