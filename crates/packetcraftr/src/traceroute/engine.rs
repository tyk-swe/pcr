// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Traceroute orchestration across authorization, hop execution, and results.

use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;

use crate::progress::Runtime;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::{diagnostic::Diagnostic, registry::Registry};

use crate::clock::Clock;
use crate::probe::evidence::{EvidenceState, ResponseSelector, Retained, validate_batch_evidence};
use crate::probe::runner::{ProbeLifecycle, run_batches, sink_observer};
use crate::target::{Authorizer, approve_operation, budgeted, resolve_selected};
use crate::{BoundaryError, SentPacket};

use super::MAX_PROBE_BYTES;
use super::WORKFLOW;
use super::classification::classify_response;
use super::model::{
    Batch, Completion, Event, Execution, Executor, Hop, Limits, Probe, ProbeEvidence, ProbeStatus,
    Report, Request, ResponseKind, Strategy, Summary, UndecodedEvidence,
};
use super::plan::{build_batches, worst_case_duration};
use super::probe::sent_probe_matches;
use crate::probe::{Error, ErrorKind};

/// Validates the request, authorizes every resolved target and the complete
/// operation budget before constructing probes, then executes hop batches until
/// checksum-valid evidence reaches the destination or reports it unreachable.
pub fn run<A, E, C>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
) -> Result<Report, Error>
where
    A: Authorizer,
    E: Executor<Probe>,
    C: Clock,
{
    let mut collector = Collector::default();
    let summary = run_observed(
        request,
        authorizer,
        registry,
        executor,
        clock,
        |event, _| {
            collector.observe(event);
            Ok(())
        },
    )?;
    Ok(collector.finish(summary))
}

/// Executes one approved trace and publishes each final probe outcome and
/// retained undecoded frame before starting a later hop. The callback runs on
/// a process-budgeted worker. `max_duration` bounds publisher waiting and live
/// I/O, not arbitrary callback execution. Confirmed sends in the current hop
/// are not undone, callback failure prevents later hops, and a callback may
/// finish after this function returns while holding its permit.
pub fn run_with_events<A, E, C, F>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    runtime: &Runtime,
    emit: F,
) -> Result<Summary, Error>
where
    A: Authorizer,
    E: Executor<Probe>,
    C: Clock,
    F: FnMut(Event) -> Result<(), BoundaryError> + Send + 'static,
{
    let observe = sink_observer(
        runtime,
        emit,
        |error| traceroute_duration_error(error.actual, error.limit),
        |source| Error::new(WORKFLOW, ErrorKind::Output { source }),
    )?;
    run_observed(request, authorizer, registry, executor, clock, observe)
}

fn run_observed<A, E, C, F>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    mut emit: F,
) -> Result<Summary, Error>
where
    A: Authorizer,
    E: Executor<Probe>,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    let mut deadline = Deadline::new(request.limits.max_duration);
    let approved = approve_traceroute(request, authorizer, &deadline)?;
    let batches = build_batches(request, approved.destination)?;
    enforce_deadline(&deadline)?;
    let mut state = TracerouteState::default();
    let stats = {
        let mut lifecycle = Lifecycle {
            executor,
            registry,
            limits: request.limits,
            target: Arc::from(approved.declared_target.as_str()),
            state: &mut state,
            emit: &mut emit,
        };
        run_batches(
            WORKFLOW,
            &batches,
            request.probes_per_second,
            &mut deadline,
            clock,
            &mut lifecycle,
        )
    };
    let stats = stats?;

    Ok(Summary {
        target: approved.declared_target,
        resolved_addresses: approved.resolved_addresses,
        destination: approved.destination,
        strategy: request.strategy,
        destination_port: request.destination_port,
        completion: state.completion,
        stats,
    })
}

#[derive(Default)]
pub(super) struct Collector {
    hops: Vec<Hop>,
    hop_indices: HashMap<u8, usize>,
    undecoded: Vec<UndecodedEvidence>,
    diagnostics: Vec<Diagnostic>,
}

impl Collector {
    pub(super) fn observe(&mut self, event: Event) {
        match event {
            Event::Probe { target: _, probe } => {
                let hop_index = match self.hop_indices.get(&probe.hop_limit) {
                    Some(index) => *index,
                    None => {
                        let index = self.hops.len();
                        self.hops.push(Hop {
                            hop_limit: probe.hop_limit,
                            probes: Vec::new(),
                        });
                        self.hop_indices.insert(probe.hop_limit, index);
                        index
                    }
                };
                #[expect(
                    clippy::indexing_slicing,
                    reason = "`hop_index` is either a live entry from `hop_indices` or the index \
                              of the hop just pushed, so it is below `hops.len()`"
                )]
                let hop = &mut self.hops[hop_index];
                hop.probes.push(probe);
            }
            Event::Undecoded(evidence) => self.undecoded.push(evidence),
            Event::Diagnostic(diagnostic) => self.diagnostics.push(diagnostic),
        }
    }

    pub(super) fn finish(self, summary: Summary) -> Report {
        Report {
            target: summary.target,
            resolved_addresses: summary.resolved_addresses,
            destination: summary.destination,
            strategy: summary.strategy,
            destination_port: summary.destination_port,
            hops: self.hops,
            undecoded: self.undecoded,
            completion: summary.completion,
            diagnostics: self.diagnostics,
            stats: summary.stats,
        }
    }
}

struct ApprovedTraceroute {
    declared_target: String,
    resolved_addresses: Vec<IpAddr>,
    destination: IpAddr,
}

fn approve_traceroute<A: Authorizer>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
) -> Result<ApprovedTraceroute, Error> {
    request.validate()?;
    let resolved = resolve_selected(
        authorizer,
        &request.target,
        request.address_family,
        deadline,
        &WORKFLOW,
    )?;
    let Some(&destination) = resolved.addresses.first() else {
        return Err(Error::new(
            WORKFLOW,
            ErrorKind::Family {
                family: request.address_family.label(),
            },
        ));
    };

    let total_probes = request.total_probe_count()?;
    validate_probe_plan(request, total_probes)?;
    let maximum_wire_bytes = u64::try_from(total_probes)
        .unwrap_or(u64::MAX)
        .checked_mul(MAX_PROBE_BYTES)
        .ok_or(Error::new(
            WORKFLOW,
            ErrorKind::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            },
        ))?;
    approve_operation(
        authorizer,
        budgeted(
            u64::try_from(total_probes).unwrap_or(u64::MAX),
            maximum_wire_bytes,
        ),
        deadline,
        &WORKFLOW,
    )?;
    Ok(ApprovedTraceroute {
        declared_target: resolved.declared,
        resolved_addresses: resolved.addresses,
        destination,
    })
}

fn validate_probe_plan(request: &Request, total_probes: usize) -> Result<(), Error> {
    if total_probes > request.limits.max_probes {
        return Err(Error::new(
            WORKFLOW,
            ErrorKind::InvalidLimit {
                field: "probes",
                value: u64::try_from(total_probes).unwrap_or(u64::MAX),
                reason: format!("exceeds max_probes={}", request.limits.max_probes),
            },
        ));
    }
    if let (Strategy::Udp, Some(base)) = (request.strategy, request.destination_port) {
        let last_offset = total_probes.saturating_sub(1);
        if usize::from(base)
            .checked_add(last_offset)
            .is_none_or(|last| last > usize::from(u16::MAX))
        {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidPort {
                    message: format!(
                        "base UDP port {base} plus {} unique probe(s) exceeds 65535",
                        total_probes
                    ),
                },
            ));
        }
    }
    let worst_case = worst_case_duration(request)?;
    if worst_case > request.limits.max_duration {
        return Err(Error::new(
            WORKFLOW,
            ErrorKind::DurationLimit {
                actual: worst_case,
                limit: request.limits.max_duration,
            },
        ));
    }
    Ok(())
}

struct TracerouteState {
    evidence: EvidenceState,
    completion: Completion,
}

impl Default for TracerouteState {
    fn default() -> Self {
        Self {
            evidence: EvidenceState::default(),
            completion: Completion::Timeout,
        }
    }
}

impl TracerouteState {
    fn observe_probe(&mut self, probe: &ProbeEvidence) {
        self.completion = match (self.completion, probe.response_kind, probe.status) {
            (_, Some(ResponseKind::DestinationReached), _) => Completion::DestinationReached,
            (Completion::DestinationReached, _, _) => Completion::DestinationReached,
            (_, Some(ResponseKind::Unreachable), _) => Completion::Unreachable,
            (Completion::Unreachable, _, _) => Completion::Unreachable,
            (_, _, ProbeStatus::Response) => Completion::MaximumHops,
            (completion, _, _) => completion,
        };
    }
}

struct Lifecycle<'a, E, F> {
    executor: &'a mut E,
    registry: &'a Registry,
    limits: Limits,
    target: Arc<str>,
    state: &'a mut TracerouteState,
    emit: &'a mut F,
}

impl<E, F> ProbeLifecycle<Probe> for Lifecycle<'_, E, F>
where
    E: Executor<Probe>,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        self.executor.execute(batch)
    }

    fn validate(&mut self, batch: &Batch, execution: &Execution) -> Result<(), Error> {
        validate_batch_evidence(
            WORKFLOW,
            batch,
            execution,
            self.limits.evidence(),
            sent_probe_matches,
        )
    }

    fn process(
        &mut self,
        batch: &Batch,
        execution: Execution,
        deadline: &Deadline,
    ) -> Result<ControlFlow<()>, Error> {
        self.process_batch(batch, execution, deadline)
    }
}

impl<E, F> Lifecycle<'_, E, F>
where
    E: Executor<Probe>,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    fn process_batch(
        &mut self,
        batch: &Batch,
        execution: Execution,
        deadline: &Deadline,
    ) -> Result<ControlFlow<()>, Error> {
        enforce_deadline(deadline)?;
        let Execution {
            permit,
            sent,
            mut responses,
            unsolicited: _,
            undecoded: batch_undecoded,
            diagnostics: batch_diagnostics,
            stats: _,
        } = execution;
        if permit != batch.permit {
            return Err(Error::new(
                WORKFLOW,
                ErrorKind::InvalidEvidence {
                    sequence: batch.sequence,
                    message: "executor returned evidence for a different execution permit"
                        .to_owned(),
                },
            ));
        }
        self.record_diagnostics(batch_diagnostics, deadline)?;
        enforce_deadline(deadline)?;
        let mut response_selector = ResponseSelector::new(&mut responses);
        let terminal = self.process_probes(batch, &sent, &mut response_selector, deadline)?;
        #[expect(
            clippy::indexing_slicing,
            reason = "every hop batch is built with at least one probe per hop limit"
        )]
        let hop_limit = batch.probes[0].hop_limit;
        self.retain_undecoded(batch_undecoded, hop_limit, deadline)?;
        Ok(terminal)
    }

    fn process_probes(
        &mut self,
        batch: &Batch,
        sent: &[SentPacket],
        response_selector: &mut ResponseSelector<'_>,
        deadline: &Deadline,
    ) -> Result<ControlFlow<()>, Error> {
        let mut terminal = ControlFlow::Continue(());
        for (request_index, (probe, sent)) in batch.probes.iter().zip(sent.iter()).enumerate() {
            let evidence = self.classify_probe(
                probe,
                sent,
                request_index,
                batch.timeout,
                response_selector,
                deadline,
            )?;
            self.publish_new_diagnostics(deadline)?;
            if matches!(
                evidence.response_kind,
                Some(ResponseKind::DestinationReached | ResponseKind::Unreachable)
            ) {
                terminal = ControlFlow::Break(());
            }
            self.state.observe_probe(&evidence);
            (self.emit)(
                Event::Probe {
                    target: Arc::clone(&self.target),
                    probe: evidence,
                },
                deadline,
            )?;
            enforce_deadline(deadline)?;
        }
        Ok(terminal)
    }

    fn classify_probe(
        &mut self,
        probe: &Probe,
        sent: &SentPacket,
        request_index: usize,
        timeout: Duration,
        response_selector: &mut ResponseSelector<'_>,
        deadline: &Deadline,
    ) -> Result<ProbeEvidence, Error> {
        enforce_deadline(deadline)?;
        let sent_at = sent.timing().freshness_marker().wall_clock();
        let best = response_selector.select(
            request_index,
            timeout,
            |response| {
                classify_response(
                    self.registry,
                    probe.target.transport(),
                    &sent.built().packet,
                    response,
                )
            },
            |observation| observation.kind.rank(),
            |observation| observation.responder,
            || enforce_deadline(deadline),
        )?;
        let Some(candidate) = best else {
            return Ok(ProbeEvidence {
                sequence: probe.sequence,
                hop_limit: probe.hop_limit,
                attempt: probe.attempt,
                destination: probe.address,
                strategy: probe.target.transport(),
                destination_port: probe.target.port(),
                status: ProbeStatus::Timeout,
                response_kind: None,
                responder: None,
                sent_at,
                received_at: None,
                latency: None,
                response: None,
                reason: "no checksum-valid, protocol-consistent response before the deadline"
                    .to_owned(),
            });
        };
        let response = self.state.evidence.retain_response(
            &candidate.decoded.frame,
            self.limits.evidence(),
            WORKFLOW.evidence_diagnostics(),
        );
        Ok(ProbeEvidence {
            sequence: probe.sequence,
            hop_limit: probe.hop_limit,
            attempt: probe.attempt,
            destination: probe.address,
            strategy: probe.target.transport(),
            destination_port: probe.target.port(),
            status: ProbeStatus::Response,
            response_kind: Some(candidate.observation.kind),
            responder: Some(candidate.observation.responder),
            sent_at,
            received_at: candidate.decoded.frame.timestamp,
            latency: Some(candidate.latency),
            response,
            reason: candidate.observation.reason.to_owned(),
        })
    }

    fn retain_undecoded(
        &mut self,
        frames: Vec<packetcraftr_core::frame::Frame>,
        hop_limit: u8,
        deadline: &Deadline,
    ) -> Result<(), Error> {
        self.state.evidence.retain_undecoded(
            frames,
            self.limits.evidence(),
            WORKFLOW.evidence_diagnostics(),
            |retained| {
                let event = match retained {
                    Retained::Frame(frame) => {
                        Event::Undecoded(UndecodedEvidence { hop_limit, frame })
                    }
                    Retained::Diagnostic(diagnostic) => Event::Diagnostic(diagnostic),
                };
                (self.emit)(event, deadline)
            },
            || enforce_deadline(deadline),
        )
    }

    fn record_diagnostics(
        &mut self,
        diagnostics: Vec<Diagnostic>,
        deadline: &Deadline,
    ) -> Result<(), Error> {
        let Self { state, emit, .. } = self;
        state
            .evidence
            .record_diagnostics(diagnostics, |diagnostic| {
                emit(Event::Diagnostic(diagnostic), deadline)
            })
    }

    fn publish_new_diagnostics(&mut self, deadline: &Deadline) -> Result<(), Error> {
        let Self { state, emit, .. } = self;
        state
            .evidence
            .diagnostics
            .publish_new(|diagnostic| emit(Event::Diagnostic(diagnostic), deadline))
    }
}

fn enforce_deadline(deadline: &Deadline) -> Result<(), Error> {
    crate::clock::check_deadline(deadline, traceroute_duration_error)
}

fn traceroute_duration_error(actual: Duration, limit: Duration) -> Error {
    Error::new(WORKFLOW, ErrorKind::DurationLimit { actual, limit })
}
