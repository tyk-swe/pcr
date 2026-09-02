// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded response/result state for one armed exchange.

use std::{collections::HashSet, sync::Arc, time::Instant};

use packetcraftr_core::{
    Packet,
    decode::{DecodedPacket, Dissector},
    diagnostic::Diagnostic,
    frame::Frame,
    registry::Registry,
};
use packetcraftr_netio::capture::RecordIdentity;

use super::model::Options;
use crate::evidence::{Budget, BudgetError, DiagnosticLog};
use crate::materialize::PreparedPacket;

#[derive(Clone, Copy)]
pub(super) struct UnsolicitedFreshness {
    pub(super) received_at: Instant,
    pub(super) eligible_requests: usize,
}

pub(super) struct UnsolicitedEvidence {
    pub(super) decoded: DecodedPacket,
    pub(super) freshness: Option<UnsolicitedFreshness>,
}

pub(crate) type WorkflowResponseMatcher<'a> =
    dyn FnMut(usize, &Packet, &DecodedPacket) -> bool + 'a;
pub(crate) type WorkflowStopPredicate<'a> = dyn FnMut(usize, &Packet, &DecodedPacket) -> bool + 'a;

pub(crate) struct Accumulator {
    pub(super) unsolicited: Vec<UnsolicitedEvidence>,
    pub(super) pending_events: Vec<super::model::Event>,
    pub(crate) diagnostics: DiagnosticLog,
    pub(super) evidence_budget: Budget,
    pub(crate) response_counts: Vec<usize>,
    pub(super) response_count: usize,
    pub(super) retained_unmatched: usize,
    pub(super) correlation_deadline_expired: bool,
    pub(super) retained_record_identities: HashSet<RecordIdentity>,
}

#[derive(Clone, Copy)]
pub(crate) struct ProcessContext<'a> {
    pub(crate) registry: &'a Registry,
    pub(crate) dissector: &'a Dissector,
    pub(crate) prepared: &'a [PreparedPacket],
    pub(crate) sent: &'a [Arc<crate::SentPacket>],
    pub(crate) deadline: Instant,
    pub(crate) options: &'a super::model::Options,
}

/// The capture provider handed back an ingress record it had already
/// delivered. Nothing about the operation can be trusted after that, so it is
/// a failure rather than one more outcome to keep processing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DuplicateRecord;

impl DuplicateRecord {
    /// The single wording both the blocking collection loop and the zero-time
    /// drain report for this failure.
    pub(crate) fn into_error(self) -> packetcraftr_netio::Error {
        packetcraftr_netio::Error::Capture {
            message: "capture provider returned the same ingress record more than once".to_owned(),
            source: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessOutcome {
    Continue,
    CorrelationDeadlineExpired,
    StopCapture,
}

impl Accumulator {
    pub(crate) fn new(requests: usize) -> Self {
        Self {
            unsolicited: Vec::new(),
            pending_events: Vec::new(),
            diagnostics: DiagnosticLog::default(),
            evidence_budget: Budget::default(),
            response_counts: vec![0; requests],
            response_count: 0,
            retained_unmatched: 0,
            correlation_deadline_expired: false,
            retained_record_identities: HashSet::new(),
        }
    }

    pub(super) fn can_retain_record(&self, identity: RecordIdentity) -> bool {
        !self.retained_record_identities.contains(&identity)
    }

    pub(super) fn mark_record_retained(&mut self, identity: RecordIdentity) {
        self.retained_record_identities.insert(identity);
    }

    pub(super) fn drain_events(&mut self) -> std::vec::Drain<'_, super::model::Event> {
        self.pending_events.drain(..)
    }
}

impl Accumulator {
    pub(super) fn reserve_decoded_evidence(
        &mut self,
        additional: usize,
        options: &Options,
    ) -> bool {
        let error = match self.evidence_budget.reserve(
            additional,
            options.capture.max_frames,
            options.capture.max_bytes,
        ) {
            Ok(()) => return true,
            Err(error) => error,
        };
        let (code, message) = match error {
            BudgetError::FrameCountOverflow => (
                "exchange.capture_frame_limit",
                "retained capture frame accounting overflowed; frame was not retained".to_owned(),
            ),
            BudgetError::FrameLimit => (
                "exchange.capture_frame_limit",
                format!(
                    "aggregate retained capture frame limit {} reached; later frames were not retained",
                    options.capture.max_frames
                ),
            ),
            BudgetError::ByteCountOverflow => (
                "exchange.capture_byte_limit",
                "retained capture byte accounting overflowed; frame was not retained".to_owned(),
            ),
            BudgetError::ByteLimit => (
                "exchange.capture_byte_limit",
                format!(
                    "retained capture byte limit {} reached; later frames were not retained",
                    options.capture.max_bytes
                ),
            ),
        };
        self.diagnostics
            .push_once(Diagnostic::warning(code, message));
        false
    }

    /// The one retention gate every unattributed capture record passes: the
    /// unsolicited/undecoded frame ceiling, then the aggregate evidence budget.
    ///
    /// Both retention paths reach the ceiling under the same condition, so both
    /// report it with the same words. They previously published the same
    /// `exchange.unsolicited_limit` code with two different messages, and
    /// `push_once` deduplicates by code, so whichever path hit the limit first
    /// decided what the operator saw.
    fn reserve_unattributed(
        &mut self,
        identity: RecordIdentity,
        frame_bytes: usize,
        options: &Options,
    ) -> bool {
        if self.retained_unmatched >= options.max_unmatched_frames {
            self.diagnostics.push_once(Diagnostic::warning(
                "exchange.unsolicited_limit",
                format!(
                    "unsolicited/undecoded frame limit {} reached; later frames were not retained",
                    options.max_unmatched_frames
                ),
            ));
            return false;
        }
        if !self.reserve_decoded_evidence(frame_bytes, options) {
            return false;
        }
        self.mark_record_retained(identity);
        #[expect(
            clippy::arithmetic_side_effects,
            reason = "the early return above keeps `retained_unmatched` below \
                      `max_unmatched_frames`, so the increment cannot overflow"
        )]
        {
            self.retained_unmatched += 1;
        }
        true
    }

    pub(super) fn retain_unsolicited(
        &mut self,
        identity: RecordIdentity,
        decoded: DecodedPacket,
        options: &Options,
        freshness: Option<super::accumulator::UnsolicitedFreshness>,
    ) {
        if self.reserve_unattributed(identity, decoded.original.len(), options) {
            self.unsolicited
                .push(UnsolicitedEvidence { decoded, freshness });
        }
    }

    pub(super) fn retain_undecoded(
        &mut self,
        identity: RecordIdentity,
        frame: Frame,
        options: &Options,
    ) {
        if self.reserve_unattributed(identity, frame.bytes().len(), options) {
            self.pending_events
                .push(super::model::Event::Undecoded { frame });
        }
    }
}
