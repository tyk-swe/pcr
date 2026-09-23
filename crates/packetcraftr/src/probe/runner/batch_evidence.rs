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

use super::{Batch, Execution, Sequenced};
use crate::SentPacket;
use crate::probe::evidence::{
    EvidenceLimits, EvidenceState, ResponseSelector, Retained, validate_batch_evidence,
};
use crate::probe::{Error, ErrorKind, Workflow, enforce_deadline};

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

/// Operation-wide batch-evidence processing for one workflow.
pub(crate) struct BatchEvidence<K, F> {
    workflow: Workflow,
    limits: EvidenceLimits,
    state: EvidenceState,
    classifier: K,
    emit: F,
}

impl<K, F> BatchEvidence<K, F> {
    pub(crate) fn new(workflow: Workflow, limits: EvidenceLimits, classifier: K, emit: F) -> Self {
        Self {
            workflow,
            limits,
            state: EvidenceState::default(),
            classifier,
            emit,
        }
    }

    pub(crate) const fn workflow(&self) -> Workflow {
        self.workflow
    }

    pub(crate) fn into_classifier(self) -> K {
        self.classifier
    }
}

impl<K, F> BatchEvidence<K, F>
where
    K: Classifier,
    F: FnMut(K::Event, &Deadline) -> Result<(), Error>,
{
    /// Checks one batch's executor evidence against its probes, its (clipped)
    /// timeout, and the evidence limits before anything is charged.
    pub(crate) fn validate(
        &self,
        batch: &Batch<K::Probe>,
        execution: &Execution,
    ) -> Result<(), Error> {
        validate_batch_evidence(
            self.workflow,
            &batch.probes,
            batch.timeout,
            execution,
            self.limits,
            |probe, sent| self.classifier.sent_matches(probe, sent),
        )
    }

    /// Publishes a workflow event that is not batch evidence, such as a
    /// pipelined send confirmation.
    pub(crate) fn emit(&mut self, event: K::Event, deadline: &Deadline) -> Result<(), Error> {
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
        execution: Execution,
        deadline: &Deadline,
    ) -> Result<ControlFlow<()>, Error> {
        self.enforce(deadline)?;
        let Execution {
            permit,
            sent,
            mut responses,
            unsolicited: _,
            undecoded,
            diagnostics,
            stats: _,
        } = execution;
        if permit != batch.permit {
            return Err(Error::new(
                self.workflow,
                ErrorKind::InvalidEvidence {
                    sequence: batch.sequence,
                    message: "executor returned evidence for a different execution permit"
                        .to_owned(),
                },
            ));
        }
        self.record_diagnostics(diagnostics, deadline)?;
        self.enforce(deadline)?;
        let mut selector = ResponseSelector::new(&mut responses);
        let mut flow = ControlFlow::Continue(());
        for (request_index, (probe, sent)) in batch.probes.iter().zip(&sent).enumerate() {
            self.enforce(deadline)?;
            let Self {
                workflow,
                limits,
                state,
                classifier,
                emit,
            } = self;
            let best = selector.select(
                request_index,
                batch.timeout,
                |response| classifier.classify(probe, sent, response),
                |observation| classifier.rank(observation),
                |observation| classifier.responder(observation),
                || enforce_deadline(*workflow, deadline),
            )?;
            let outcome = match best {
                None => Outcome::Timeout,
                Some(candidate) => Outcome::Reply(Reply {
                    frame: state.retain_response(
                        &candidate.decoded.frame,
                        *limits,
                        workflow.evidence_diagnostics(),
                    ),
                    received_at: candidate.decoded.frame.timestamp,
                    latency: candidate.latency,
                    observation: candidate.observation,
                }),
            };
            let event = classifier.evidence(probe, sent, outcome);
            state
                .diagnostics
                .publish_new(|diagnostic| emit(classifier.diagnostic(diagnostic), deadline))?;
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
    ) -> Result<(), Error> {
        let Self {
            workflow,
            limits,
            state,
            classifier,
            emit,
        } = self;
        state.retain_undecoded(
            frames,
            *limits,
            workflow.evidence_diagnostics(),
            |retained| {
                let event = match retained {
                    Retained::Frame(frame) => classifier.undecoded(probes, frame),
                    Retained::Diagnostic(diagnostic) => classifier.diagnostic(diagnostic),
                };
                emit(event, deadline)
            },
            || enforce_deadline(*workflow, deadline),
        )
    }

    /// Records each diagnostic once and publishes every one not yet published.
    pub(crate) fn record_diagnostics(
        &mut self,
        diagnostics: Vec<Diagnostic>,
        deadline: &Deadline,
    ) -> Result<(), Error> {
        let Self {
            state,
            classifier,
            emit,
            ..
        } = self;
        state.record_diagnostics(diagnostics, |diagnostic| {
            emit(classifier.diagnostic(diagnostic), deadline)
        })
    }

    fn enforce(&self, deadline: &Deadline) -> Result<(), Error> {
        enforce_deadline(self.workflow, deadline)
    }
}
