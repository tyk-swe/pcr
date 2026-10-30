// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
//! Reply attribution, evidence retention, and probe settlement.

use super::correlation::{Best, definitive, indexed_candidates, indexed_settled};
use super::{Descriptor, Pipeline, limit};
use crate::{
    Stats,
    clock::Clock,
    evidence::RetentionError,
    evidence::response::candidate_precedes,
    probe::Evidence,
    providers::PacketProviders,
    scan::{Attribution, Reply, executor::PipelineEvent},
};
use packetcraftr_core::{
    diagnostic::{Diagnostic, Severity},
    error::BoundaryError,
    frame::Frame,
};
use packetcraftr_netio::capture;

impl<P: PacketProviders, K: Clock> Pipeline<'_, P, K> {
    /// Completes the probes past their timeout once the capture queues have
    /// been drained, and reports whether they are still being drained.
    pub(super) fn settle_expired(&mut self) -> Result<bool, BoundaryError> {
        if self.deadlines.notice_expired(self.executor.client.now()) {
            self.capture_drain_remaining = self.capture_drain_limit;
        }
        // A callback can consume another probe's timeout while its reply is
        // already queued. Keep due probes until the bounded queues are drained.
        let draining_captures = self.deadlines.is_draining() && self.capture_drain_remaining > 0;
        if !draining_captures {
            while let Some(index) = self.deadlines.pop_expired() {
                self.complete(index)?;
            }
            self.capture_drain_remaining = self.capture_drain_limit;
        }
        Ok(draining_captures)
    }

    pub(super) fn retire_recent(&mut self) -> bool {
        let Some((index, _, charge)) = self.recent.pop_front() else {
            return false;
        };
        self.candidates.remove(index);
        self.recent_sent.remove(&index);
        self.retire_description(index);
        self.retained -= charge;
        true
    }

    pub(super) fn retire_description(&mut self, index: usize) {
        drop(self.descriptions.remove(&index));
    }

    pub(super) fn ingest(&mut self, captured: capture::Captured) -> Result<(), BoundaryError> {
        self.ingress_unknown |= captured.received_at.is_none();
        if !self.seen.insert(captured.identity()) {
            return Ok(());
        }
        let source = captured.source;
        let raw = captured.frame.clone();
        let decoded = match self
            .decoder
            .decode(captured.frame, self.executor.collection.decode.clone())
        {
            Ok(decoded) => decoded,
            Err(error) => {
                if self.diagnostics.insert("decode") {
                    self.output
                        .event(PipelineEvent::Diagnostic(Diagnostic::new(
                            Severity::Warning,
                            "scan.decode_error",
                            packetcraftr_core::error::render(&error),
                        )))?;
                }
                self.output.event(PipelineEvent::Undecoded { frame: raw })?;
                return Ok(());
            }
        };
        if decoded
            .diagnostics
            .iter()
            .any(Diagnostic::is_checksum_failure)
        {
            if self.diagnostics.insert("integrity") {
                self.output
                    .event(PipelineEvent::Diagnostic(Diagnostic::new(
                        Severity::Warning,
                        "scan.integrity_rejected",
                        "checksum-invalid capture was not correlated",
                    )))?;
            }
            return Ok(());
        }
        let Some(received) = captured.received_at else {
            if self.diagnostics.insert("ingress") {
                self.output
                    .event(PipelineEvent::Diagnostic(Diagnostic::new(
                        Severity::Warning,
                        "capture.ingress_time_unavailable",
                        "capture lacks a monotonic ingress marker and was not correlated",
                    )))?;
            }
            return Ok(());
        };
        let possible = self.candidates.lookup(source, &decoded.packet);
        let mut candidates = indexed_candidates(
            &possible,
            &self.pending,
            |index| self.descriptions.get(&index).map(Descriptor::probe),
            &self.executor.operation.registry,
            &decoded,
            &self.plan.interfaces[source],
            received,
        );

        if candidates.is_empty() {
            // Pending probes whose window closed have not settled yet, but
            // a frame after their deadline cannot be their outcome either.
            let settled = indexed_settled(
                &possible,
                |index| {
                    self.pending
                        .get(&index)
                        .filter(|entry| received > entry.deadline)
                        .map(|entry| &entry.sent)
                        .or_else(|| self.recent_sent.get(&index))
                },
                |index| self.descriptions.get(&index).map(Descriptor::probe),
                &self.executor.operation.registry,
                &decoded,
                &self.plan.interfaces[source],
                received,
            );
            return match settled.as_slice() {
                [] => Ok(()),
                [index] => self.unattributed(raw, Attribution::Late, Some(*index)),
                _ => self.unattributed(raw, Attribution::Ambiguous, None),
            };
        }
        if candidates.len() > 1 {
            if self.diagnostics.insert("ambiguous") {
                self.output
                    .event(PipelineEvent::Diagnostic(Diagnostic::new(
                        Severity::Warning,
                        "scan.ambiguous_response",
                        "capture matched multiple pending probes and was not attributed",
                    )))?;
            }
            return self.unattributed(raw, Attribution::Ambiguous, None);
        }
        let (index, observation) = candidates.pop().expect("one candidate");
        if observation.response.reply == Reply::IpProtocolPayload
            && self.history.ambiguous(
                self.descriptions[&index].probe(),
                &decoded.packet,
                &self.plan.interfaces[source],
            )
        {
            if self.diagnostics.insert("ambiguous") {
                self.output.event(PipelineEvent::Diagnostic(Diagnostic::new(Severity::Warning,
                    "scan.ambiguous_response",
                    "identity-less capture also matched a previous transmission and was not attributed")))?;
            }
            return self.unattributed(raw, Attribution::Ambiguous, None);
        }
        let definitive = definitive(&observation);
        let entry = self.pending.get_mut(&index).expect("candidate is pending");
        let candidate = Best {
            rank: observation.rank(),
            responder: observation.response.responder,
            response: crate::exchange::Response {
                request_index: 0,
                response: decoded,
                latency: received
                    .duration_since(entry.sent.timing().freshness_marker().monotonic()),
            },
        };
        if entry
            .best
            .as_ref()
            .is_none_or(|current| candidate_precedes(&candidate.key(), &current.key()))
        {
            let previous_bytes = entry
                .best
                .as_ref()
                .map(|previous| previous.response.response.frame.bytes().len());
            // Buffered duplicates may use spare capacity, but a winner takes priority.
            while let Err(error) = self.evidence.replace(
                previous_bytes,
                raw.bytes().len(),
                self.options.max_evidence_frames,
                self.options.max_evidence_bytes,
            ) {
                let Some(discarded) = self
                    .pending
                    .values_mut()
                    .find_map(|entry| entry.passed.pop())
                else {
                    return Err(match error {
                        RetentionError::FrameCountOverflow | RetentionError::FrameLimit => {
                            limit("evidence frames", self.options.max_evidence_frames)
                        }
                        RetentionError::ByteCountOverflow | RetentionError::ByteLimit => {
                            limit("evidence bytes", self.options.max_evidence_bytes)
                        }
                    });
                };
                self.evidence
                    .release(discarded.response.frame.bytes().len());
                self.evidence_limit()?;
            }
            let entry = self.pending.get_mut(&index).expect("candidate is pending");
            if let Some(previous) = entry.best.replace(candidate) {
                self.buffer_duplicate(index, previous.response)?;
            }
        } else {
            self.buffer_duplicate(index, candidate.response)?;
        }
        if definitive {
            self.complete(index)?;
        }
        Ok(())
    }

    fn buffer_duplicate(
        &mut self,
        index: usize,
        response: crate::exchange::Response,
    ) -> Result<(), BoundaryError> {
        if self
            .evidence
            .reserve(
                response.response.frame.bytes().len(),
                self.options.max_evidence_frames,
                self.options.max_evidence_bytes,
            )
            .is_ok()
        {
            self.pending
                .get_mut(&index)
                .expect("candidate is pending")
                .passed
                .push(response);
            Ok(())
        } else {
            self.evidence_limit()
        }
    }

    fn evidence_limit(&mut self) -> Result<(), BoundaryError> {
        if self.diagnostics.insert("scan.evidence_limit") {
            self.output
                .event(PipelineEvent::Diagnostic(Diagnostic::new(
                    Severity::Warning,
                    "scan.evidence_limit",
                    "scan evidence retention limit reached; extra replies were omitted",
                )))?;
        }
        Ok(())
    }

    fn unattributed(
        &mut self,
        frame: Frame,
        attribution: Attribution,
        index: Option<usize>,
    ) -> Result<(), BoundaryError> {
        let sequence = index.and_then(|index| {
            self.descriptions
                .get(&index)
                .map(|description| description.probe().sequence)
        });
        self.output.event(PipelineEvent::Unattributed {
            frame,
            attribution,
            sequence,
        })
    }

    fn complete(&mut self, index: usize) -> Result<(), BoundaryError> {
        let entry = self
            .pending
            .get_mut(&index)
            .expect("completed pending probe");
        entry.last_response = entry
            .best
            .as_ref()
            .map(|best| best.response.response.frame.clone());
        self.failed_probe = Some(self.descriptions[&index].probe().clone());
        let stats = Stats {
            packets_attempted: 1,
            packets_completed: 1,
            bytes: entry.sent.bytes_sent() as u64,
            elapsed: entry.sent.timing().freshness_marker().monotonic().elapsed(),
            capture: Default::default(),
        };
        let mut responses: Vec<_> = entry
            .best
            .take()
            .map(|best| best.response)
            .into_iter()
            .collect();
        responses.append(&mut entry.passed);
        for response in &responses {
            self.evidence.release(response.response.frame.bytes().len());
        }
        let execution = Evidence {
            observation_quality: None,
            permit: self.descriptions[&index].batch.batch().permit,
            sent: vec![entry.sent.as_ref().clone()],
            responses,
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats,
        };
        self.output
            .event(PipelineEvent::Completed { index, execution })?;
        let entry = self
            .pending
            .remove(&index)
            .expect("completed pending probe");
        if self.recent.len() == self.options.max_in_flight {
            self.retire_recent();
        }
        self.deadlines.remove(entry.deadline, index);
        self.recent_sent.insert(index, entry.sent.clone());
        self.recent.push_back((index, entry.sent, entry.charge));
        if let Some(stream) = &mut self.streaming {
            stream.next_ready = None;
        }
        self.failed_probe = None;
        Ok(())
    }
}
