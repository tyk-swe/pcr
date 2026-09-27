// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Batch-evidence processing shared by every probe workflow: the permit check,
//! diagnostic recording and publishing order, response selection, retention of
//! winning and undecodable frames, and the per-probe emit order. Workflows
//! supply only a [`Classifier`].

use std::net::IpAddr;
use std::ops::ControlFlow;
use std::time::{Duration, SystemTime};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::packet::Packet;

use super::{Batch, Evidence, Sequenced};
use crate::evidence::SentPacket;
use crate::execution::Errors;
use crate::execution::evidence::{EvidenceSink, EvidenceState, ResponseSelector};
use crate::execution::limits::EvidenceLimits;
use crate::execution::validation::{
    validate_aggregate_evidence_limits, validate_capture_statistics_evidence,
    validate_response_frames_and_deadlines, validate_sent_byte_accounting,
};
use crate::probe::{Workflow, enforce_deadline};

/// The reason both probe workflows report for a probe without a winner.
pub(crate) const NO_RESPONSE_REASON: &str =
    "no checksum-valid, protocol-consistent response before the deadline";

/// The workflow-owned half of batch-evidence processing: how one response is
/// read against a sent probe and ranked, what a probe's evidence looks like,
/// and which events carry it.
pub(crate) trait Classifier {
    /// The planned probe a batch carries.
    type Probe: Sequenced;
    /// One correlated response as this workflow reads it.
    type Observation;
    /// The workflow's progressive event.
    type Event;

    /// Whether `sent` still carries `probe`'s destination and identity.
    fn sent_matches(&self, probe: &Self::Probe, sent: &Packet) -> bool;
    /// Reads one response against a sent probe; `None` leaves it uncorrelated.
    fn classify(
        &self,
        probe: &Self::Probe,
        sent: &SentPacket,
        response: &DecodedPacket,
    ) -> Option<Self::Observation>;
    /// Higher ranks win the candidate ordering.
    fn rank(&self, observation: &Self::Observation) -> u8;
    /// Breaks rank ties: the lower responder wins.
    fn responder(&self, observation: &Self::Observation) -> IpAddr;
    /// Builds the probe's final evidence event.
    fn evidence(
        &mut self,
        probe: &Self::Probe,
        sent: &SentPacket,
        outcome: Outcome<Self::Observation>,
    ) -> Self::Event;
    /// Wraps one retained undecodable frame. `probes` is the batch the frame
    /// arrived with. Only a pipelined workflow retains frames outside any
    /// batch and passes an empty slice; a serial-only workflow may rely on it.
    fn undecoded(&self, probes: &[Self::Probe], frame: Frame) -> Self::Event;
    fn diagnostic(&self, diagnostic: Diagnostic) -> Self::Event;
    /// Whether this probe event ends the operation once its batch finishes.
    fn ends_operation(&self, _event: &Self::Event) -> bool {
        false
    }
}

/// How one sent probe ended.
pub(crate) enum Outcome<O> {
    /// No classified response arrived within the probe's timeout.
    Timeout,
    /// The winning response under the shared candidate ordering.
    Reply(Reply<O>),
}

pub(crate) struct Reply<O> {
    pub(crate) observation: O,
    pub(crate) received_at: Option<SystemTime>,
    pub(crate) latency: Duration,
    /// A copy of the exact response frame, or `None` once the operation's
    /// evidence budget is spent.
    pub(crate) frame: Option<Frame>,
}

/// Operation-wide batch-evidence processing for one workflow, naming every
/// failure through the workflow's error adapter `G`.
pub(crate) struct BatchEvidence<K, F, G> {
    errors: G,
    limits: EvidenceLimits,
    state: EvidenceState,
    classifier: K,
    emit: F,
}

impl<K, F, G: Copy> BatchEvidence<K, F, G> {
    pub(crate) fn new(
        workflow: Workflow,
        errors: G,
        limits: EvidenceLimits,
        classifier: K,
        emit: F,
    ) -> Self {
        Self {
            errors,
            limits,
            state: EvidenceState::new(limits, workflow.evidence_diagnostics()),
            classifier,
            emit,
        }
    }

    pub(crate) const fn errors(&self) -> G {
        self.errors
    }

    pub(crate) fn into_classifier(self) -> K {
        self.classifier
    }
}

impl<K, F, G> BatchEvidence<K, F, G>
where
    K: Classifier,
    F: FnMut(K::Event, &Deadline) -> Result<(), G::Error>,
    G: Errors<Step = u64>,
{
    /// Checks one batch's executor evidence against its probes, its (clipped)
    /// timeout, and the evidence limits before anything is charged.
    pub(crate) fn validate(
        &self,
        batch: &Batch<K::Probe>,
        execution: &Evidence,
    ) -> Result<(), G::Error> {
        validate_batch_evidence(
            &self.errors,
            &batch.probes,
            batch.timeout,
            execution,
            self.limits,
            |probe, sent| self.classifier.sent_matches(probe, sent),
        )
    }

    /// Publishes a workflow event that is not batch evidence, such as a
    /// pipelined send confirmation.
    pub(crate) fn emit(&mut self, event: K::Event, deadline: &Deadline) -> Result<(), G::Error> {
        (self.emit)(event, deadline)
    }

    /// Consumes one validated batch: rejects evidence for another permit,
    /// publishes the executor's diagnostics, then for each probe selects the
    /// winning response, retains it, publishes the diagnostics that raised,
    /// and emits the probe's event; finally retains undecodable frames.
    /// [`ControlFlow::Break`] means a probe event ended the operation.
    pub(crate) fn process(
        &mut self,
        batch: &Batch<K::Probe>,
        execution: Evidence,
        deadline: &Deadline,
    ) -> Result<ControlFlow<()>, G::Error> {
        self.enforce(deadline)?;
        let Evidence {
            permit,
            sent,
            mut responses,
            unsolicited: _,
            undecoded,
            diagnostics,
            stats: _,
        } = execution;
        if permit != batch.permit {
            return Err(self
                .errors
                .invalid_evidence(batch.sequence, crate::evidence::Error::PermitMismatch));
        }
        self.record_diagnostics(diagnostics, deadline)?;
        self.enforce(deadline)?;
        let mut selector = ResponseSelector::new(&mut responses);
        let mut flow = ControlFlow::Continue(());
        for (request_index, (probe, sent)) in batch.probes.iter().zip(&sent).enumerate() {
            self.enforce(deadline)?;
            let Self {
                errors,
                state,
                classifier,
                emit,
                ..
            } = self;
            let best = selector.select(
                request_index,
                batch.timeout,
                |response| classifier.classify(probe, sent, response),
                |observation| classifier.rank(observation),
                |observation| classifier.responder(observation),
                || enforce_deadline(errors, deadline),
            )?;
            let outcome = match best {
                None => Outcome::Timeout,
                Some(candidate) => Outcome::Reply(Reply {
                    frame: state.retain_response(&candidate.decoded.frame),
                    received_at: candidate.decoded.frame.timestamp,
                    latency: candidate.latency,
                    observation: candidate.observation,
                }),
            };
            let event = classifier.evidence(probe, sent, outcome);
            state.publish_diagnostics(|diagnostic| {
                emit(classifier.diagnostic(diagnostic), deadline)
            })?;
            if classifier.ends_operation(&event) {
                flow = ControlFlow::Break(());
            }
            emit(event, deadline)?;
            self.enforce(deadline)?;
        }
        self.retain_undecoded(&batch.probes, undecoded, deadline)?;
        Ok(flow)
    }

    /// Emits undecodable frames and the diagnostics their retention raises in
    /// arrival order, stopping at the undecoded limit with its diagnostic.
    pub(crate) fn retain_undecoded(
        &mut self,
        probes: &[K::Probe],
        frames: Vec<Frame>,
        deadline: &Deadline,
    ) -> Result<(), G::Error> {
        let Self {
            errors,
            state,
            classifier,
            emit,
            ..
        } = self;
        state.retain_undecoded(
            frames,
            &mut Events {
                errors,
                classifier,
                emit,
                probes,
                deadline,
            },
        )
    }

    /// Records each diagnostic once and publishes every one not yet published.
    pub(crate) fn record_diagnostics(
        &mut self,
        diagnostics: Vec<Diagnostic>,
        deadline: &Deadline,
    ) -> Result<(), G::Error> {
        let Self {
            errors,
            state,
            classifier,
            emit,
            ..
        } = self;
        state.record_diagnostics(
            diagnostics,
            &mut Events {
                errors,
                classifier,
                emit,
                probes: &[],
                deadline,
            },
        )
    }

    fn enforce(&self, deadline: &Deadline) -> Result<(), G::Error> {
        enforce_deadline(&self.errors, deadline)
    }
}

/// Publishes what the evidence state keeps as the classifier's events.
/// `probes` is the batch undecodable frames arrived with.
struct Events<'e, K: Classifier, F, G> {
    errors: &'e G,
    classifier: &'e K,
    emit: &'e mut F,
    probes: &'e [K::Probe],
    deadline: &'e Deadline,
}

impl<K, F, G> EvidenceSink for Events<'_, K, F, G>
where
    K: Classifier,
    F: FnMut(K::Event, &Deadline) -> Result<(), G::Error>,
    G: Errors,
{
    type Error = G::Error;

    fn undecoded(&mut self, frame: Frame) -> Result<(), G::Error> {
        (self.emit)(self.classifier.undecoded(self.probes, frame), self.deadline)
    }

    fn diagnostic(&mut self, diagnostic: Diagnostic) -> Result<(), G::Error> {
        (self.emit)(self.classifier.diagnostic(diagnostic), self.deadline)
    }

    fn check(&mut self) -> Result<(), G::Error> {
        enforce_deadline(self.errors, self.deadline)
    }
}

fn validate_batch_exchange_evidence<P, F>(
    probes: &[P],
    timeout: Duration,
    execution: &Evidence,
    max_captured_frames: usize,
    max_captured_bytes: usize,
    mut sent_packet_matches: F,
) -> Result<(), crate::evidence::Error>
where
    F: FnMut(&P, &Packet) -> bool,
{
    if execution.sent.len() != probes.len() {
        return Err(crate::evidence::Error::SentCardinality {
            expected: probes.len(),
            receipts: execution.sent.len(),
        });
    }
    if execution
        .responses
        .iter()
        .any(|response| response.request_index >= probes.len())
    {
        return Err(crate::evidence::Error::ResponseOutsideBatch);
    }

    validate_aggregate_evidence_limits(
        &execution.responses,
        &execution.unsolicited,
        &execution.undecoded,
        max_captured_frames,
        max_captured_bytes,
    )?;

    for (request_index, (sent, probe)) in execution.sent.iter().zip(probes).enumerate() {
        if !sent_packet_matches(probe, &sent.built().packet) {
            return Err(crate::evidence::Error::SentPacketMismatch { request_index });
        }
    }

    validate_sent_byte_accounting(&execution.sent, execution.stats.bytes)?;
    validate_response_frames_and_deadlines(&execution.responses, &execution.unsolicited, timeout)?;
    validate_capture_statistics_evidence(execution.stats.capture)?;
    if execution.stats.packets_attempted != u64::try_from(probes.len()).unwrap_or(u64::MAX)
        || execution.stats.packets_completed != u64::try_from(probes.len()).unwrap_or(u64::MAX)
    {
        return Err(crate::evidence::Error::IncompleteStatistics);
    }
    Ok(())
}

/// Validates one batch's executor evidence under the workflow's limits and
/// reports any inconsistency at the sequence of the probe it concerns.
pub(crate) fn validate_batch_evidence<P: Sequenced, G: Errors<Step = u64>>(
    errors: &G,
    probes: &[P],
    timeout: Duration,
    execution: &Evidence,
    limits: EvidenceLimits,
    sent_packet_matches: impl FnMut(&P, &Packet) -> bool,
) -> Result<(), G::Error> {
    validate_batch_exchange_evidence(
        probes,
        timeout,
        execution,
        limits.max_frames,
        limits.max_bytes,
        sent_packet_matches,
    )
    .map_err(|error| {
        let sequence = error
            .request_index()
            .and_then(|index| probes.get(index))
            .or_else(|| probes.first())
            .map_or(0, Sequenced::sequence);
        errors.invalid_evidence(sequence, error)
    })
}

#[cfg(test)]
mod tests;
