// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    Stats,
    clock::Clock,
    evidence::ExecutionPermit,
    probe::{self, Batch, runner::BatchEvidence},
    scan::{
        self, Error, Event, Probe, Request,
        adaptive::{Controller, Outcome, Selection, Work},
        evidence::ProbeClassifier,
        executor::{PipelineBatch, PipelineEvent, PipelineFeed, PipelinePoll},
        plan::{Stage, packet::sent_probe_matches},
    },
    target::SelectedAddress,
};
use packetcraftr_core::{budget::Deadline, error::BoundaryError};
use std::{collections::BTreeMap, time::Instant};

struct Active {
    selection: Selection,
    permit: ExecutionPermit,
    sent: bool,
}

pub(super) struct StageInput<'a> {
    pub(super) targets: &'a [SelectedAddress],
    pub(super) endpoints: &'a [probe::Endpoint],
    pub(super) stage: Stage,
    pub(super) first_sequence: u64,
}

pub(super) struct Feed<'a, 'r, C, F> {
    request: &'a Request,
    targets: &'a [SelectedAddress],
    endpoints: &'a [probe::Endpoint],
    stage: Stage,
    deadline: &'a Deadline,
    clock: &'a C,
    evidence: &'a mut BatchEvidence<ProbeClassifier<'r>, F, Error>,
    controller: &'a mut Controller,
    work: Work,
    active: BTreeMap<usize, Active>,
    next_index: usize,
    active_sent: usize,
    pub(super) confirmed: Stats,
    pub(super) last_sent: Option<Instant>,
}

impl<'a, 'r, C: Clock, F> Feed<'a, 'r, C, F>
where
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    pub(super) fn new(
        request: &'a Request,
        input: StageInput<'a>,
        deadline: &'a Deadline,
        clock: &'a C,
        evidence: &'a mut BatchEvidence<ProbeClassifier<'r>, F, Error>,
        controller: &'a mut Controller,
    ) -> Self {
        let StageInput {
            targets,
            endpoints,
            stage,
            first_sequence,
        } = input;
        controller.begin_observation_stage();
        let work = controller.open_stage(
            targets,
            endpoints.len(),
            request.attempts,
            first_sequence,
            clock.now(),
        );
        Self {
            request,
            targets,
            endpoints,
            stage,
            deadline,
            clock,
            evidence,
            controller,
            work,
            active: BTreeMap::new(),
            next_index: 0,
            active_sent: 0,
            confirmed: Stats::default(),
            last_sent: None,
        }
    }

    fn batch(&self, active: &Active) -> Batch<Probe> {
        let selection = active.selection;
        let mut batch = Batch::single(
            scan::plan::planned_probe(
                self.request,
                selection.sequence,
                self.stage,
                &self.targets[selection.slot],
                self.endpoints[selection.endpoint],
                selection.attempt,
            ),
            selection.timeout,
        );
        batch.permit = active.permit;
        batch
    }

    fn invalid(index: usize) -> BoundaryError {
        BoundaryError::from_error(Error::InvalidEvidence {
            sequence: index as u64,
            message: "stream returned an invalid, repeated or incoherent attempt event".to_owned(),
        })
    }

    fn release_canceled(&mut self) {
        self.evidence
            .release_responses(self.controller.take_canceled_responses(&mut self.work));
    }

    pub(super) fn settled(&self) -> bool {
        self.active.is_empty() && self.work.done()
    }
}

impl<C: Clock, F> PipelineFeed for Feed<'_, '_, C, F>
where
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    fn poll(&mut self, capacity: usize, now: Instant) -> Result<PipelinePoll, BoundaryError> {
        self.deadline.enforce().map_err(BoundaryError::from_error)?;
        let end = now
            .checked_add(
                self.deadline
                    .remaining()
                    .map_err(BoundaryError::from_error)?,
            )
            .ok_or_else(|| Self::invalid(self.next_index))?;
        let capacity = capacity.min(self.controller.window().saturating_sub(self.active.len()));
        let wave = self.controller.select(&mut self.work, now, end, capacity);
        self.release_canceled();
        let mut batches = Vec::with_capacity(wave.selections.len());
        for selection in wave.selections {
            let index = self.next_index;
            self.next_index += 1;
            let batch = Batch::single(
                scan::plan::planned_probe(
                    self.request,
                    selection.sequence,
                    self.stage,
                    &self.targets[selection.slot],
                    self.endpoints[selection.endpoint],
                    selection.attempt,
                ),
                selection.timeout,
            );
            self.controller.admitted(&mut self.work, selection);
            self.active.insert(
                index,
                Active {
                    selection,
                    permit: batch.permit,
                    sent: false,
                },
            );
            batches.push(PipelineBatch {
                index,
                batch,
                host_deadline: Some(selection.host_deadline),
            });
        }
        Ok(PipelinePoll {
            batches,
            next_ready: wave.next_ready,
            done: wave.done,
        })
    }

    fn event(&mut self, event: PipelineEvent) -> Result<(), BoundaryError> {
        self.deadline.enforce().map_err(BoundaryError::from_error)?;
        match event {
            PipelineEvent::Sent { index, sent } => {
                let active = self
                    .active
                    .get(&index)
                    .ok_or_else(|| Self::invalid(index))?;
                let batch = self.batch(active);
                if active.sent || !sent_probe_matches(batch.probe()?, &sent.built().packet) {
                    return Err(Self::invalid(index));
                }
                let active = self
                    .active
                    .get_mut(&index)
                    .expect("validated stream attempt");
                active.sent = true;
                active.selection.host_limited |= sent
                    .timing()
                    .freshness_marker()
                    .monotonic()
                    .checked_add(active.selection.timeout)
                    .is_none_or(|end| end > active.selection.host_deadline);
                let now = self.clock.now();
                self.controller
                    .confirm_send(&mut self.work, active.selection, now);
                self.active_sent += 1;
                self.controller.observe_active(self.active_sent);
                self.last_sent = Some(now);
                self.confirmed.packets_attempted += 1;
                self.confirmed.packets_completed += 1;
                self.confirmed.bytes = self
                    .confirmed
                    .bytes
                    .checked_add(sent.bytes_sent() as u64)
                    .ok_or_else(|| Self::invalid(index))?;
                self.evidence
                    .emit(
                        Event::Sent(scan::SentProbe {
                            probe: batch.probe()?.clone(),
                            sent,
                        }),
                        self.deadline,
                    )
                    .map_err(BoundaryError::from_error)?;
            }
            PipelineEvent::Completed {
                index,
                mut execution,
            } => {
                let active = self
                    .active
                    .remove(&index)
                    .ok_or_else(|| Self::invalid(index))?;
                if !active.sent {
                    return Err(Self::invalid(index));
                }
                let batch = self.batch(&active);
                if active.selection.host_limited {
                    execution.observation_quality =
                        Some(packetcraftr_netio::capture::ObservationQuality::Unknown);
                    if execution.responses.is_empty() {
                        self.evidence
                            .record_diagnostics(
                                vec![packetcraftr_core::diagnostic::Diagnostic::warning(
                                    "scan.observation_shortened",
                                    format!(
                                        "probe {} observation ended at its local host ceiling",
                                        active.selection.sequence
                                    ),
                                )],
                                self.deadline,
                            )
                            .map_err(BoundaryError::from_error)?;
                    }
                }

                let _ = self
                    .evidence
                    .validate(&batch, &execution)
                    .and_then(|()| self.evidence.process(&batch, execution, self.deadline))
                    .map_err(BoundaryError::from_error)?;
                self.active_sent = self.active_sent.saturating_sub(1);
                let feedback = super::take_feedback(self.evidence)
                    .into_iter()
                    .filter(|feedback| feedback.sequence == active.selection.sequence)
                    .min_by_key(|feedback| feedback.received_at);
                let outcome = match feedback {
                    Some(feedback) => Outcome::Reply {
                        latency: feedback.latency,
                        responder: feedback.responder,
                        control: matches!(
                            feedback.reply,
                            scan::Reply::IcmpPortUnreachable
                                | scan::Reply::IcmpProtocolUnreachable
                                | scan::Reply::IcmpDestinationUnreachable
                                | scan::Reply::TcpReset
                                | scan::Reply::SctpAbort
                        ),
                    },
                    None if active.selection.host_limited => {
                        self.controller.mark_incomplete(active.selection.host);
                        Outcome::Aborted
                    }
                    None => Outcome::UnqualifiedSilence,
                };
                self.controller
                    .settle(&mut self.work, active.selection, outcome, self.clock.now());
                self.release_canceled();
            }
            PipelineEvent::Omitted { index } => {
                let active = self
                    .active
                    .remove(&index)
                    .ok_or_else(|| Self::invalid(index))?;
                if active.sent {
                    return Err(Self::invalid(index));
                }
                self.controller.mark_incomplete(active.selection.host);
                self.controller.settle(
                    &mut self.work,
                    active.selection,
                    Outcome::Omitted,
                    self.clock.now(),
                );
                self.release_canceled();
            }
            PipelineEvent::Qualification(qualification) => {
                super::super::pipelined::publish_aux(
                    PipelineEvent::Qualification(qualification),
                    self.evidence,
                    self.deadline,
                )?;
                self.controller.qualify_pending(qualification.coverage());
            }
            event => super::super::pipelined::publish_aux(event, self.evidence, self.deadline)?,
        }
        self.deadline.enforce().map_err(BoundaryError::from_error)
    }
}
