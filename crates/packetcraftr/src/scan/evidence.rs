// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Response selection, classification, and bounded scan evidence publication.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::{diagnostic::Diagnostic, frame::Frame, registry::Registry};

use crate::probe::evidence::{EvidenceState, ResponseSelector, Retained};
use crate::probe::{Error, ErrorKind, Execution, ProbeStatus, enforce_deadline};

use super::classification::classify_response;
use super::{Batch, Classification, Event, Limits, Probe, ProbeEvidence, WORKFLOW};

struct ProbeOutcome {
    status: ProbeStatus,
    classification: Classification,
    responder: Option<IpAddr>,
    sent_at: std::time::SystemTime,
    received_at: Option<std::time::SystemTime>,
    latency: Option<Duration>,
    response: Option<Frame>,
    reason: String,
    application: Option<super::profile::Evidence>,
}

pub(super) struct Processor<'a, F> {
    pub(super) registry: &'a Registry,
    pub(super) limits: Limits,
    pub(super) target: Arc<str>,
    pub(super) state: &'a mut EvidenceState,
    /// The winning classification per endpoint, so the summary reports counts
    /// without a collector.
    pub(super) winners: &'a mut HashMap<(IpAddr, Option<u16>), Classification>,
    /// Operation-level round-trip accounting across every probe event.
    pub(super) rtt: &'a mut super::report::RttAccumulator,
    pub(super) emit: &'a mut F,
}
impl<F> Processor<'_, F>
where
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    pub(super) fn process_batch(
        &mut self,
        batch: &Batch,
        exchange: Execution,
        deadline: &Deadline,
    ) -> Result<(), Error> {
        enforce_deadline(WORKFLOW, deadline)?;
        let Execution {
            permit,
            sent,
            mut responses,
            unsolicited: _,
            undecoded: batch_undecoded,
            diagnostics: batch_diagnostics,
            stats: _,
        } = exchange;
        if permit != batch.permit {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidEvidence {
                    sequence: batch.probe.sequence,
                    message: "executor returned evidence for a different execution permit"
                        .to_owned(),
                },
            ));
        }
        self.record_diagnostics(batch_diagnostics, deadline)?;
        enforce_deadline(WORKFLOW, deadline)?;
        let mut response_selector = ResponseSelector::new(&mut responses);
        for (request_index, (probe, sent)) in
            std::iter::once(&batch.probe).zip(sent.iter()).enumerate()
        {
            let evidence = self.classify_probe(
                probe,
                sent,
                request_index,
                batch.timeout,
                &mut response_selector,
                deadline,
            )?;
            self.publish_new_diagnostics(deadline)?;
            self.winners
                .entry((evidence.address, evidence.port))
                .or_insert(Classification::Timeout)
                .promote(evidence.classification);
            self.rtt.note_sent();
            if evidence.status == ProbeStatus::Response
                && let Some(latency) = evidence.latency
            {
                self.rtt.note_received(latency);
            }
            (self.emit)(
                Event::Probe {
                    target: Arc::clone(&self.target),
                    probe: evidence,
                },
                deadline,
            )?;
            enforce_deadline(WORKFLOW, deadline)?;
        }
        self.retain_undecoded(batch_undecoded, deadline)?;
        Ok(())
    }

    fn classify_probe(
        &mut self,
        probe: &Probe,
        sent: &crate::SentPacket,
        request_index: usize,
        timeout: Duration,
        response_selector: &mut ResponseSelector<'_>,
        deadline: &Deadline,
    ) -> Result<ProbeEvidence, Error> {
        enforce_deadline(WORKFLOW, deadline)?;
        let sent_at = sent.timing().freshness_marker().wall_clock();
        let best = response_selector.select(
            request_index,
            timeout,
            |response| {
                classify_response(
                    self.registry,
                    probe.endpoint.transport(),
                    &sent.built().packet,
                    response,
                )
                .map(|classified| {
                    (
                        classified,
                        super::profile::evidence(probe, &sent.built().packet, response),
                    )
                })
            },
            |observation| {
                observation.0.classification.rank() * 4
                    + observation
                        .1
                        .as_ref()
                        .map_or(2, super::profile::Evidence::rank)
            },
            |observation| observation.0.responder,
            || enforce_deadline(WORKFLOW, deadline),
        )?;
        let Some(candidate) = best else {
            return Ok(Self::probe_evidence(
                probe,
                ProbeOutcome {
                    status: ProbeStatus::Timeout,
                    classification: Classification::Timeout,
                    responder: None,
                    sent_at,
                    received_at: None,
                    latency: None,
                    response: None,
                    reason: "no checksum-valid, protocol-consistent response before the deadline"
                        .to_owned(),
                    application: probe
                        .udp_profile
                        .as_ref()
                        .map(|profile| profile.not_observed()),
                },
            ));
        };
        let response = self.state.retain_response(
            &candidate.decoded.frame,
            self.limits.evidence(),
            WORKFLOW.evidence_diagnostics(),
        );
        Ok(Self::probe_evidence(
            probe,
            ProbeOutcome {
                status: ProbeStatus::Response,
                classification: candidate.observation.0.classification,
                responder: Some(candidate.observation.0.responder),
                sent_at,
                received_at: candidate.decoded.frame.timestamp,
                latency: Some(candidate.latency),
                response,
                reason: candidate.observation.0.reason.to_owned(),
                application: candidate.observation.1,
            },
        ))
    }

    fn probe_evidence(probe: &Probe, outcome: ProbeOutcome) -> ProbeEvidence {
        ProbeEvidence {
            sequence: probe.sequence,
            address: probe.address,
            transport: probe.endpoint.transport(),
            port: probe.endpoint.port(),
            attempt: probe.attempt,
            status: outcome.status,
            classification: outcome.classification,
            responder: outcome.responder,
            sent_at: outcome.sent_at,
            received_at: outcome.received_at,
            latency: outcome.latency,
            response: outcome.response,
            reason: outcome.reason,
            application: outcome.application,
        }
    }

    pub(super) fn retain_undecoded(
        &mut self,
        frames: Vec<Frame>,
        deadline: &Deadline,
    ) -> Result<(), Error> {
        self.state.retain_undecoded(
            frames,
            self.limits.evidence(),
            WORKFLOW.evidence_diagnostics(),
            |retained| {
                let event = match retained {
                    Retained::Frame(frame) => Event::Undecoded { frame },
                    Retained::Diagnostic(diagnostic) => Event::Diagnostic(diagnostic),
                };
                (self.emit)(event, deadline)
            },
            || enforce_deadline(WORKFLOW, deadline),
        )
    }

    pub(super) fn record_diagnostics(
        &mut self,
        diagnostics: Vec<Diagnostic>,
        deadline: &Deadline,
    ) -> Result<(), Error> {
        let Self { state, emit, .. } = self;
        state.record_diagnostics(diagnostics, |diagnostic| {
            emit(Event::Diagnostic(diagnostic), deadline)
        })
    }

    fn publish_new_diagnostics(&mut self, deadline: &Deadline) -> Result<(), Error> {
        let Self { state, emit, .. } = self;
        state
            .diagnostics
            .publish_new(|diagnostic| emit(Event::Diagnostic(diagnostic), deadline))
    }
}
