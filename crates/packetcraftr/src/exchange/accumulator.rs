// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{collections::HashSet, sync::Arc, time::Instant};

use packetcraftr_core::{
    decode::{DecodedPacket, Dissector},
    diagnostic::Diagnostic,
    frame::Frame,
    packet::Packet,
    registry::Registry,
};
use packetcraftr_netio::capture::RecordIdentity;

use super::{Collection, Window};
use crate::evidence::{DiagnosticLog, RetentionBudget, RetentionError};

#[derive(Clone, Copy)]
pub(super) struct UnsolicitedFreshness {
    pub(super) received_at: Instant,
    pub(super) eligible_requests: usize,
}

pub(super) struct UnsolicitedEvidence {
    pub(super) decoded: DecodedPacket,
    pub(super) freshness: Option<UnsolicitedFreshness>,
}

/// A fresh frame that a limit refused to retain, handed back so a workflow matcher can judge it.
pub(super) struct RefusedCandidate {
    pub(super) decoded: DecodedPacket,
    pub(super) freshness: UnsolicitedFreshness,
    pub(super) limit: &'static str,
}

pub(crate) type WorkflowResponseMatcher<'a> =
    dyn FnMut(usize, &Packet, &DecodedPacket) -> bool + 'a;
pub(crate) type WorkflowStopPredicate<'a> = dyn FnMut(usize, &Packet, &DecodedPacket) -> bool + 'a;

pub(crate) struct Accumulator {
    pub(super) unsolicited: Vec<UnsolicitedEvidence>,
    pub(super) pending_events: Vec<super::Event>,
    /// Ingress markers and correlation state for unsolicited events, in publication order.
    pub(crate) unsolicited_ingress: Vec<super::evidence::UnsolicitedIngress>,
    pub(crate) diagnostics: DiagnosticLog,
    pub(super) evidence_budget: RetentionBudget,
    pub(crate) response_counts: Vec<usize>,
    pub(super) response_count: usize,
    /// Requests that have no retained response yet.
    pending_requests: usize,
    /// The first limit that refused a reply uniquely attributed to the request, by correlation
    /// or by the workflow matcher.
    pub(super) refused_replies: Vec<Option<&'static str>>,
    pub(super) retained_unmatched: usize,
    pub(super) correlation_deadline_expired: bool,
    pub(super) retained_record_identities: HashSet<RecordIdentity>,
}

#[derive(Clone, Copy)]
pub(crate) struct ProcessContext<'a> {
    pub(crate) registry: &'a Registry,
    pub(crate) dissector: &'a Dissector,
    pub(crate) request_count: usize,
    pub(crate) sent: &'a [Arc<crate::evidence::SentPacket>],
    pub(crate) window: &'a Window,
    pub(crate) collection: &'a Collection,
}

/// A re-delivered ingress record means nothing about the operation can be trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DuplicateRecord;

impl DuplicateRecord {
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
            unsolicited_ingress: Vec::new(),
            diagnostics: DiagnosticLog::default(),
            evidence_budget: RetentionBudget::default(),
            response_counts: vec![0; requests],
            response_count: 0,
            pending_requests: requests,
            refused_replies: vec![None; requests],
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

    pub(super) fn drain_events(&mut self) -> std::vec::Drain<'_, super::Event> {
        self.pending_events.drain(..)
    }

    /// `held_back` frame slots stay free for later matched replies. A refusal carries the
    /// diagnostic code that names the limit.
    pub(super) fn reserve_decoded_evidence(
        &mut self,
        additional: usize,
        held_back: usize,
        collection: &Collection,
    ) -> Result<(), &'static str> {
        let effective_frames = collection.capture.max_frames.saturating_sub(held_back);
        let error = match self.evidence_budget.reserve(
            additional,
            effective_frames,
            collection.capture.max_bytes,
        ) {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        let (code, message) = match error {
            RetentionError::FrameCountOverflow => (
                "exchange.capture_frame_limit",
                "retained capture frame accounting overflowed; frame was not retained".to_owned(),
            ),
            RetentionError::FrameLimit if held_back == 0 => (
                "exchange.capture_frame_limit",
                format!(
                    "aggregate retained capture frame limit {} reached; later frames were not retained",
                    collection.capture.max_frames
                ),
            ),
            RetentionError::FrameLimit => (
                "exchange.capture_frame_limit",
                format!(
                    "aggregate retained capture frame limit {effective_frames} reached ({max_frames} configured, {held_back} held for pending replies); later frames were not retained",
                    max_frames = collection.capture.max_frames
                ),
            ),
            RetentionError::ByteCountOverflow => (
                "exchange.capture_byte_limit",
                "retained capture byte accounting overflowed; frame was not retained".to_owned(),
            ),
            RetentionError::ByteLimit => (
                "exchange.capture_byte_limit",
                format!(
                    "retained capture byte limit {} reached; later frames were not retained",
                    collection.capture.max_bytes
                ),
            ),
        };
        self.diagnostics
            .push_once(Diagnostic::warning(code, message));
        Err(code)
    }

    /// Frame slots that unrelated frames must leave for the requests still awaiting a reply.
    fn held_back_for_replies(&self, collection: &Collection) -> usize {
        self.pending_requests
            .min(collection.max_responses.saturating_sub(self.response_count))
    }

    pub(super) fn record_response(&mut self, request_index: usize) {
        if self.response_counts[request_index] == 0 {
            self.pending_requests -= 1;
        }
        self.response_counts[request_index] += 1;
        self.response_count += 1;
    }

    pub(super) fn refuse_reply(&mut self, request_index: usize, limit: &'static str) {
        self.refused_replies[request_index].get_or_insert(limit);
    }

    /// A refused reply is not evidence of absence, so its request is not listed.
    pub(super) fn unanswered(&self, sent: usize) -> Vec<usize> {
        self.response_counts
            .iter()
            .zip(&self.refused_replies)
            .take(sent)
            .enumerate()
            .filter_map(|(index, (count, refused))| {
                (*count == 0 && refused.is_none()).then_some(index)
            })
            .collect()
    }

    pub(super) fn first_refused_reply(&self, sent: usize) -> Option<(usize, &'static str)> {
        self.response_counts
            .iter()
            .zip(&self.refused_replies)
            .take(sent)
            .enumerate()
            .find_map(|(index, (count, refused))| {
                refused.filter(|_| *count == 0).map(|limit| (index, limit))
            })
    }

    /// Both retention paths share the diagnostic code for `push_once` deduplication.
    fn reserve_unattributed(
        &mut self,
        identity: RecordIdentity,
        frame_bytes: usize,
        collection: &Collection,
    ) -> Result<(), &'static str> {
        if self.retained_unmatched >= collection.max_unmatched_frames {
            let code = "exchange.unsolicited_limit";
            self.diagnostics.push_once(Diagnostic::warning(
                code,
                format!(
                    "unsolicited/undecoded frame limit {} reached; later frames were not retained",
                    collection.max_unmatched_frames
                ),
            ));
            return Err(code);
        }
        let held_back = self.held_back_for_replies(collection);
        self.reserve_decoded_evidence(frame_bytes, held_back, collection)?;
        self.mark_record_retained(identity);
        self.retained_unmatched += 1;
        Ok(())
    }

    /// A refused frame is returned only when it was fresh enough for a workflow to promote.
    pub(super) fn retain_unsolicited(
        &mut self,
        identity: RecordIdentity,
        decoded: DecodedPacket,
        collection: &Collection,
        freshness: Option<UnsolicitedFreshness>,
    ) -> Option<RefusedCandidate> {
        match self.reserve_unattributed(identity, decoded.frame.bytes().len(), collection) {
            Ok(()) => {
                self.unsolicited
                    .push(UnsolicitedEvidence { decoded, freshness });
                None
            }
            Err(limit) => freshness.map(|freshness| RefusedCandidate {
                decoded,
                freshness,
                limit,
            }),
        }
    }

    pub(super) fn retain_undecoded(
        &mut self,
        identity: RecordIdentity,
        frame: Frame,
        collection: &Collection,
    ) {
        if self
            .reserve_unattributed(identity, frame.bytes().len(), collection)
            .is_ok()
        {
            self.pending_events.push(super::Event::Undecoded { frame });
        }
    }
}
