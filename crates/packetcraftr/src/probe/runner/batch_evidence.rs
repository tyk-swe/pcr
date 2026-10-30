// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::ops::ControlFlow;
use std::time::{Duration, SystemTime};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::packet::Packet;

use super::{Batch, Evidence, Sequenced, UnsolicitedCapture};
use crate::engine::execution::validation::{
    validate_aggregate_evidence_limits, validate_capture_statistics_evidence,
    validate_response_frames_and_deadlines, validate_sent_byte_accounting,
};
use crate::evidence::Limits as EvidenceLimits;
use crate::evidence::SentPacket;
use crate::evidence::response::{Passed, ResponseSelector, Selected};
use crate::evidence::retention::{EvidenceSink, EvidenceState};
use crate::probe::{Workflow, enforce_deadline};

pub(crate) const NO_RESPONSE_REASON: &str =
    "no checksum-valid, protocol-consistent response before the deadline";

pub(crate) trait Classifier {
    type Probe: Sequenced;
    type Observation;
    type Event;

    fn observation_quality(
        &mut self,
        _quality: Option<packetcraftr_netio::capture::ObservationQuality>,
    ) {
    }

    fn sent_matches(&self, probe: &Self::Probe, sent: &Packet) -> bool;
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
    fn evidence(
        &mut self,
        probe: &Self::Probe,
        sent: &SentPacket,
        outcome: Outcome<Self::Observation>,
    ) -> Self::Event;
    fn undecoded(&self, probes: &[Self::Probe], frame: Frame) -> Self::Event;
    /// The event retaining a matched response that did not become the
    /// probe's outcome; the default discards such responses.
    fn passed(&self, _probe: &Self::Probe, _passed: Passed, _frame: Frame) -> Option<Self::Event> {
        None
    }
    fn canceled_responses(
        &self,
        _probe: &Self::Probe,
        _outcome: &Outcome<Self::Observation>,
    ) -> usize {
        0
    }
    /// Attributes unsolicited capture evidence without changing a probe's outcome.
    fn unsolicited(
        &self,
        _probe: &Self::Probe,
        _sent: &SentPacket,
        _capture: &UnsolicitedCapture,
        _has_response: bool,
    ) -> Option<Self::Event> {
        None
    }
    fn diagnostic(&self, diagnostic: Diagnostic) -> Self::Event;
    fn ends_operation(&self, _event: &Self::Event) -> bool {
        false
    }
}

pub(crate) enum Outcome<O> {
    Timeout,
    Reply(Reply<O>),
}

pub(crate) struct Reply<O> {
    pub(crate) observation: O,
    pub(crate) received_at: Option<SystemTime>,
    pub(crate) latency: Duration,
    pub(crate) frame: Option<Frame>,
}

pub(crate) struct BatchEvidence<K, F, E> {
    errors: fn(u64, crate::error::Failure) -> E,
    validation_limits: EvidenceLimits,
    state: EvidenceState,
    classifier: K,
    emit: F,
}

impl<K, F, E> BatchEvidence<K, F, E> {
    /// Valid executor captures keep their per-exchange ceilings even when earlier
    /// preparation has consumed part (or all) of the operation retention budget.
    pub(crate) fn new_with_retention_limits(
        workflow: Workflow,
        errors: fn(u64, crate::error::Failure) -> E,
        validation_limits: EvidenceLimits,
        retention_limits: EvidenceLimits,
        classifier: K,
        emit: F,
    ) -> Self {
        Self {
            errors,
            validation_limits,
            state: EvidenceState::new(retention_limits, workflow.evidence_diagnostics()),
            classifier,
            emit,
        }
    }

    pub(crate) const fn errors(&self) -> fn(u64, crate::error::Failure) -> E {
        self.errors
    }

    pub(crate) fn retained_evidence_bytes(&self) -> usize {
        self.state.retained_evidence_bytes()
    }

    pub(crate) fn reserve_responses(&mut self, count: usize, max_response_bytes: usize) {
        self.state.reserve_responses(count, max_response_bytes);
    }

    pub(crate) fn release_responses(&mut self, count: usize) {
        self.state.release_responses(count);
    }

    pub(crate) fn into_classifier(self) -> K {
        self.classifier
    }

    pub(crate) fn classifier_mut(&mut self) -> &mut K {
        &mut self.classifier
    }
}

impl<K, F, E> BatchEvidence<K, F, E>
where
    K: Classifier,
    F: FnMut(K::Event, &Deadline) -> Result<(), E>,
{
    pub(crate) fn validate(&self, batch: &Batch<K::Probe>, execution: &Evidence) -> Result<(), E> {
        validate_batch_evidence(
            self.errors,
            &batch.probes,
            batch.timeout,
            execution,
            self.validation_limits,
            |probe, sent| self.classifier.sent_matches(probe, sent),
        )
    }

    pub(crate) fn emit(&mut self, event: K::Event, deadline: &Deadline) -> Result<(), E> {
        (self.emit)(event, deadline)
    }

    /// [`ControlFlow::Break`] means a probe event ended the operation.
    pub(crate) fn process(
        &mut self,
        batch: &Batch<K::Probe>,
        execution: Evidence,
        deadline: &Deadline,
    ) -> Result<ControlFlow<()>, E> {
        self.enforce(deadline)?;
        let Evidence {
            observation_quality,
            permit,
            sent,
            mut responses,
            unsolicited,
            undecoded,
            diagnostics,
            stats: _,
        } = execution;
        if permit != batch.permit {
            return Err((self.errors)(
                batch.sequence,
                crate::error::Failure::InvalidEvidence(crate::evidence::Error::PermitMismatch),
            ));
        }
        self.classifier.observation_quality(observation_quality);
        self.record_diagnostics(diagnostics, deadline)?;
        self.enforce(deadline)?;
        let mut selector = ResponseSelector::new(&mut responses);
        let mut flow = ControlFlow::Continue(());
        let mut has_response = Vec::with_capacity(batch.probes.len());
        for (request_index, (probe, sent)) in batch.probes.iter().zip(&sent).enumerate() {
            self.enforce(deadline)?;
            let Self {
                errors,
                state,
                classifier,
                emit,
                ..
            } = self;
            let Selected { best, passed } = selector.select(
                request_index,
                batch.timeout,
                |response| classifier.classify(probe, sent, response),
                |observation| classifier.rank(observation),
                |observation| classifier.responder(observation),
                || enforce_deadline(*errors, deadline),
            )?;
            has_response.push(best.is_some());
            state.settle_response();
            let outcome = match best {
                None => Outcome::Timeout,
                Some(candidate) => Outcome::Reply(Reply {
                    frame: state.retain_response(&candidate.decoded.frame),
                    received_at: candidate.decoded.frame.timestamp,
                    latency: candidate.latency,
                    observation: candidate.observation,
                }),
            };
            state.release_responses(classifier.canceled_responses(probe, &outcome));
            let event = classifier.evidence(probe, sent, outcome);
            state.publish_diagnostics(|diagnostic| {
                emit(classifier.diagnostic(diagnostic), deadline)
            })?;
            if classifier.ends_operation(&event) {
                flow = ControlFlow::Break(());
            }
            emit(event, deadline)?;
            // Published after the outcome, as the pipelined path does.
            for (decoded, why) in passed {
                let Some(event) = classifier.passed(probe, why, decoded.frame.clone()) else {
                    continue;
                };
                if state.retain_unattributed(&decoded.frame).is_some() {
                    emit(event, deadline)?;
                }
                state.publish_diagnostics(|diagnostic| {
                    emit(classifier.diagnostic(diagnostic), deadline)
                })?;
            }
            self.enforce(deadline)?;
        }
        for capture in unsolicited {
            self.enforce(deadline)?;
            let mut matches = batch
                .probes
                .iter()
                .zip(&sent)
                .zip(&has_response)
                .filter_map(|((probe, sent), has_response)| {
                    self.classifier
                        .unsolicited(probe, sent, &capture, *has_response)
                });
            let Some(event) = matches.next() else {
                continue;
            };
            if matches.next().is_some() {
                continue;
            }
            if self
                .state
                .retain_unattributed(&capture.decoded.frame)
                .is_some()
            {
                self.emit(event, deadline)?;
            }
            self.state.publish_diagnostics(|diagnostic| {
                (self.emit)(self.classifier.diagnostic(diagnostic), deadline)
            })?;
        }
        self.retain_undecoded(&batch.probes, undecoded, deadline)?;
        Ok(flow)
    }

    /// Retains a frame no probe outcome carries, such as a reply after its
    /// probe settled, under the operation's evidence budget.
    pub(crate) fn retain_unattributed(
        &mut self,
        frame: &Frame,
        event: impl FnOnce(Frame) -> K::Event,
        deadline: &Deadline,
    ) -> Result<(), E> {
        let Self {
            state,
            classifier,
            emit,
            ..
        } = self;
        if let Some(frame) = state.retain_unattributed(frame) {
            emit(event(frame), deadline)?;
        }
        state.publish_diagnostics(|diagnostic| emit(classifier.diagnostic(diagnostic), deadline))
    }

    pub(crate) fn retain_undecoded(
        &mut self,
        probes: &[K::Probe],
        frames: Vec<Frame>,
        deadline: &Deadline,
    ) -> Result<(), E> {
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
                errors: *errors,
                classifier,
                emit,
                probes,
                deadline,
            },
        )
    }

    pub(crate) fn record_diagnostics(
        &mut self,
        diagnostics: Vec<Diagnostic>,
        deadline: &Deadline,
    ) -> Result<(), E> {
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
                errors: *errors,
                classifier,
                emit,
                probes: &[],
                deadline,
            },
        )
    }

    fn enforce(&self, deadline: &Deadline) -> Result<(), E> {
        enforce_deadline(self.errors, deadline)
    }
}

struct Events<'e, K: Classifier, F, E> {
    errors: fn(u64, crate::error::Failure) -> E,
    classifier: &'e K,
    emit: &'e mut F,
    probes: &'e [K::Probe],
    deadline: &'e Deadline,
}

impl<K, F, E> EvidenceSink for Events<'_, K, F, E>
where
    K: Classifier,
    F: FnMut(K::Event, &Deadline) -> Result<(), E>,
{
    type Error = E;

    fn undecoded(&mut self, frame: Frame) -> Result<(), E> {
        (self.emit)(self.classifier.undecoded(self.probes, frame), self.deadline)
    }

    fn diagnostic(&mut self, diagnostic: Diagnostic) -> Result<(), E> {
        (self.emit)(self.classifier.diagnostic(diagnostic), self.deadline)
    }

    fn check(&mut self) -> Result<(), E> {
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
        execution.unsolicited.iter().map(|capture| &capture.decoded),
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
    validate_response_frames_and_deadlines(
        &execution.responses,
        execution.unsolicited.iter().map(|capture| &capture.decoded),
        timeout,
    )?;
    validate_capture_statistics_evidence(execution.stats.capture)?;
    if execution.stats.packets_attempted != u64::try_from(probes.len()).unwrap_or(u64::MAX)
        || execution.stats.packets_completed != u64::try_from(probes.len()).unwrap_or(u64::MAX)
    {
        return Err(crate::evidence::Error::IncompleteStatistics);
    }
    Ok(())
}

pub(crate) fn validate_batch_evidence<P: Sequenced, E>(
    errors: fn(u64, crate::error::Failure) -> E,
    probes: &[P],
    timeout: Duration,
    execution: &Evidence,
    limits: EvidenceLimits,
    sent_packet_matches: impl FnMut(&P, &Packet) -> bool,
) -> Result<(), E> {
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
        (errors)(sequence, crate::error::Failure::InvalidEvidence(error))
    })
}
