// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Traceroute orchestration across authorization, hop execution, and results.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::{diagnostic::Diagnostic, registry::Registry};

use crate::clock::Clock;
use crate::evidence::Budget;
use crate::probe::evidence::{ResponseSelector, retain_evidence, retain_undecoded_frames};
use crate::probe::runner::{ProbeBatch, ProbeLifecycle, ProbeRunConfig, run_batches};
use crate::target::{Authorizer, approve_operation, resolve_selected};
use crate::{BoundaryError, SentPacket};

use super::classification::classify_response;
use super::error::Error;
use super::evidence::validate_execution;
use super::model::{
    Batch, Completion, Event, Execution, Executor, Hop, Limits, Probe, ProbeEvidence, ProbeStatus,
    Request, ResponseKind, Result, Strategy, Summary, UndecodedEvidence,
};
use super::plan::{build_batches, worst_case_duration};
use super::{MAX_TRACEROUTE_PROBE_BYTES, TRACEROUTE_EVIDENCE_DIAGNOSTICS};

/// Validates the request, authorizes every resolved target and the complete
/// operation budget before constructing probes, then executes hop batches until
/// checksum-valid evidence reaches the destination or reports it unreachable.
pub fn run<A, E, C>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
) -> std::result::Result<Result, Error>
where
    A: Authorizer,
    E: Executor,
    C: Clock,
{
    let mut collector = Collector::default();
    let summary = run_with_events(request, authorizer, registry, executor, clock, |event| {
        collector.observe(event);
        Ok(())
    })?;
    Ok(collector.finish(summary))
}

/// Executes one approved trace and publishes each final probe outcome and
/// retained undecoded frame before starting a later hop.
pub fn run_with_events<A, E, C, F>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    mut emit: F,
) -> std::result::Result<Summary, Error>
where
    A: Authorizer,
    E: Executor,
    C: Clock,
    F: FnMut(Event) -> std::result::Result<(), BoundaryError>,
{
    let mut deadline = Deadline::new(request.limits.max_duration);
    let approved = approve_traceroute(request, authorizer, &deadline)?;
    let batches = build_batches(request, approved.destination)?;
    enforce_deadline(&deadline)?;
    let mut state = TracerouteState::default();
    let config = ProbeRunConfig {
        probes_per_second: request.probes_per_second,
        duration_limit: request.limits.max_duration,
        final_statistics_sequence: u64::try_from(approved.total_probes.saturating_sub(1))
            .unwrap_or(u64::MAX),
    };
    let run = {
        let mut lifecycle = Lifecycle {
            executor,
            registry,
            limits: request.limits,
            target: &approved.declared_target,
            destination: approved.destination,
            state: &mut state,
            emit: &mut emit,
        };
        run_batches(&batches, config, &mut deadline, clock, &mut lifecycle)
    };
    let run = run?;

    Ok(Summary {
        target: approved.declared_target,
        resolved_addresses: approved.resolved_addresses,
        destination: approved.destination,
        strategy: request.strategy,
        destination_port: request.destination_port,
        completion: state.completion,
        diagnostics: state.diagnostics,
        stats: run.stats,
    })
}

#[derive(Default)]
struct Collector {
    hops: Vec<Hop>,
    hop_indices: HashMap<u8, usize>,
    undecoded: Vec<UndecodedEvidence>,
}

impl Collector {
    fn observe(&mut self, event: Event) {
        match event {
            Event::Probe {
                target: _,
                destination: _,
                probe,
            } => {
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
                self.hops[hop_index].probes.push(probe);
            }
            Event::Undecoded(evidence) => self.undecoded.push(evidence),
        }
    }

    fn finish(self, summary: Summary) -> Result {
        Result {
            target: summary.target,
            resolved_addresses: summary.resolved_addresses,
            destination: summary.destination,
            strategy: summary.strategy,
            destination_port: summary.destination_port,
            hops: self.hops,
            undecoded: self.undecoded,
            completion: summary.completion,
            diagnostics: summary.diagnostics,
            stats: summary.stats,
        }
    }
}

struct ApprovedTraceroute {
    declared_target: String,
    resolved_addresses: Vec<IpAddr>,
    destination: IpAddr,
    total_probes: usize,
}

fn approve_traceroute<A: Authorizer>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
) -> std::result::Result<ApprovedTraceroute, Error> {
    request.validate()?;
    let resolved = resolve_selected(
        authorizer,
        &request.target,
        request.address_family,
        deadline,
        traceroute_duration_error,
    )?;
    let Some(&destination) = resolved.addresses.first() else {
        return Err(Error::Family {
            family: request.address_family.label(),
        });
    };

    let total_probes = request.total_probe_count()?;
    validate_probe_plan(request, total_probes)?;
    let maximum_wire_bytes = u64::try_from(total_probes)
        .unwrap_or(u64::MAX)
        .checked_mul(MAX_TRACEROUTE_PROBE_BYTES)
        .ok_or(Error::InvalidLimit {
            field: "wire_bytes",
            value: u64::MAX,
            reason: "wire-byte accounting overflowed".to_owned(),
        })?;
    approve_operation(
        authorizer,
        u64::try_from(total_probes).unwrap_or(u64::MAX),
        maximum_wire_bytes,
        deadline,
        traceroute_duration_error,
    )?;
    Ok(ApprovedTraceroute {
        declared_target: resolved.declared,
        resolved_addresses: resolved.addresses,
        destination,
        total_probes,
    })
}

fn validate_probe_plan(request: &Request, total_probes: usize) -> std::result::Result<(), Error> {
    if total_probes > request.limits.max_probes {
        return Err(Error::InvalidLimit {
            field: "probes",
            value: u64::try_from(total_probes).unwrap_or(u64::MAX),
            reason: format!("exceeds max_probes={}", request.limits.max_probes),
        });
    }
    if request.strategy == Strategy::Udp {
        let base = request.destination_port.expect("validated UDP port");
        let last_offset = total_probes.saturating_sub(1);
        if usize::from(base)
            .checked_add(last_offset)
            .is_none_or(|last| last > usize::from(u16::MAX))
        {
            return Err(Error::InvalidPort {
                message: format!(
                    "base UDP port {base} plus {} unique probe(s) exceeds 65535",
                    total_probes
                ),
            });
        }
    }
    let worst_case = worst_case_duration(request)?;
    if worst_case > request.limits.max_duration {
        return Err(Error::DurationLimit {
            actual: worst_case,
            limit: request.limits.max_duration,
        });
    }
    Ok(())
}

struct TracerouteState {
    evidence_budget: Budget,
    retained_undecoded: usize,
    completion: Completion,
    diagnostics: Vec<Diagnostic>,
}

impl Default for TracerouteState {
    fn default() -> Self {
        Self {
            evidence_budget: Budget::default(),
            retained_undecoded: 0,
            completion: Completion::Timeout,
            diagnostics: Vec::new(),
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
    target: &'a str,
    destination: IpAddr,
    state: &'a mut TracerouteState,
    emit: &'a mut F,
}

impl<E, F> ProbeLifecycle<Batch> for Lifecycle<'_, E, F>
where
    E: Executor,
    F: FnMut(Event) -> std::result::Result<(), BoundaryError>,
{
    type Execution = Execution;
    type Output = bool;
    type Error = Error;

    fn execute(&mut self, batch: &Batch) -> std::result::Result<Self::Execution, BoundaryError> {
        self.executor.execute(batch)
    }

    fn validate(
        &mut self,
        batch: &Batch,
        execution: &Self::Execution,
    ) -> std::result::Result<(), Self::Error> {
        validate_execution(batch, execution, self.limits)
    }

    fn process(
        &mut self,
        batch: &Batch,
        execution: Self::Execution,
        deadline: &Deadline,
    ) -> std::result::Result<Self::Output, Self::Error> {
        process_batch(
            batch,
            execution,
            self.registry,
            self.limits,
            self.target,
            self.destination,
            self.state,
            self.emit,
            deadline,
        )
    }

    fn should_stop(output: &Self::Output) -> bool {
        *output
    }

    fn duration_error(actual: Duration, limit: Duration) -> Self::Error {
        traceroute_duration_error(actual, limit)
    }

    fn rate_error(rate: Option<u32>) -> Self::Error {
        Error::InvalidLimit {
            field: "probes_per_second",
            value: u64::from(rate.unwrap_or_default()),
            reason: "rate-delay arithmetic overflowed".to_owned(),
        }
    }

    fn clock_error(sequence: u64, message: String) -> Self::Error {
        Error::Clock { sequence, message }
    }

    fn execution_error(sequence: u64, source: BoundaryError) -> Self::Error {
        Error::Execution { sequence, source }
    }

    fn statistics_error(sequence: u64) -> Self::Error {
        Error::StatisticsOverflow { sequence }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "hop processing threads trusted execution evidence, command context, limits, state, and the progressive sink"
)]
fn process_batch<F>(
    batch: &Batch,
    execution: Execution,
    registry: &Registry,
    limits: Limits,
    target: &str,
    destination: IpAddr,
    state: &mut TracerouteState,
    emit: &mut F,
    deadline: &Deadline,
) -> std::result::Result<bool, Error>
where
    F: FnMut(Event) -> std::result::Result<(), BoundaryError>,
{
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
        return Err(Error::InvalidEvidence {
            sequence: batch.sequence(),
            message: "executor returned evidence for a different execution permit".to_owned(),
        });
    }
    for diagnostic in batch_diagnostics {
        packetcraftr_core::diagnostic::push_once(&mut state.diagnostics, diagnostic);
    }
    enforce_deadline(deadline)?;
    let mut response_selector = ResponseSelector::new(&mut responses);
    let terminal = process_probes(
        batch,
        &sent,
        &mut response_selector,
        registry,
        limits,
        target,
        destination,
        state,
        emit,
        deadline,
    )?;
    let hop_limit = batch.probes[0].hop_limit;
    retain_undecoded_frames(
        batch_undecoded,
        &mut state.retained_undecoded,
        limits.max_undecoded,
        &mut state.evidence_budget,
        TRACEROUTE_EVIDENCE_DIAGNOSTICS,
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
        &mut state.diagnostics,
        |frame| Event::Undecoded(UndecodedEvidence { hop_limit, frame }),
        |event| emit(event).map_err(|source| Error::Output { source }),
        || enforce_deadline(deadline),
    )?;
    Ok(terminal)
}

#[expect(
    clippy::too_many_arguments,
    reason = "hop processing threads trusted evidence, command context, limits, state, and the progressive sink"
)]
fn process_probes<F>(
    batch: &Batch,
    sent: &[SentPacket],
    response_selector: &mut ResponseSelector<'_>,
    registry: &Registry,
    limits: Limits,
    target: &str,
    destination: IpAddr,
    state: &mut TracerouteState,
    emit: &mut F,
    deadline: &Deadline,
) -> std::result::Result<bool, Error>
where
    F: FnMut(Event) -> std::result::Result<(), BoundaryError>,
{
    let mut terminal = false;
    for (request_index, (probe, sent)) in batch.probes.iter().zip(sent.iter()).enumerate() {
        let evidence = classify_probe(
            probe,
            sent,
            request_index,
            batch.timeout,
            response_selector,
            registry,
            limits,
            state,
            deadline,
        )?;
        terminal |= matches!(
            evidence.response_kind,
            Some(ResponseKind::DestinationReached | ResponseKind::Unreachable)
        );
        state.observe_probe(&evidence);
        emit(Event::Probe {
            target: target.to_owned(),
            destination,
            probe: evidence,
        })
        .map_err(|source| Error::Output { source })?;
        enforce_deadline(deadline)?;
    }
    Ok(terminal)
}

#[expect(
    clippy::too_many_arguments,
    reason = "probe classification needs the planned probe, trusted send, response selector, limits, and evidence state"
)]
fn classify_probe(
    probe: &Probe,
    sent: &SentPacket,
    request_index: usize,
    timeout: Duration,
    response_selector: &mut ResponseSelector<'_>,
    registry: &Registry,
    limits: Limits,
    state: &mut TracerouteState,
    deadline: &Deadline,
) -> std::result::Result<ProbeEvidence, Error> {
    enforce_deadline(deadline)?;
    let sent_at = sent.timing().freshness_marker().wall_clock();
    let best = response_selector.select(
        request_index,
        timeout,
        |response| classify_response(registry, probe.strategy, &sent.built().packet, response),
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
            strategy: probe.strategy,
            destination_port: probe.destination_port,
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
    let response = retain_evidence(
        &mut state.evidence_budget,
        &candidate.decoded.frame,
        TRACEROUTE_EVIDENCE_DIAGNOSTICS,
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
        &mut state.diagnostics,
    )
    .then(|| candidate.decoded.frame.clone());
    Ok(ProbeEvidence {
        sequence: probe.sequence,
        hop_limit: probe.hop_limit,
        attempt: probe.attempt,
        destination: probe.address,
        strategy: probe.strategy,
        destination_port: probe.destination_port,
        status: ProbeStatus::Response,
        response_kind: Some(candidate.observation.kind),
        responder: Some(candidate.observation.responder),
        sent_at,
        received_at: Some(crate::live_timestamp(&candidate.decoded.frame)),
        latency: Some(candidate.latency),
        response,
        reason: candidate.observation.reason.to_owned(),
    })
}

fn enforce_deadline(deadline: &Deadline) -> std::result::Result<(), Error> {
    crate::clock::check_deadline(deadline, traceroute_duration_error)
}

fn traceroute_duration_error(actual: Duration, limit: Duration) -> Error {
    Error::DurationLimit { actual, limit }
}

impl ProbeBatch for Batch {
    fn sequence(&self) -> u64 {
        self.probes[0].sequence
    }

    fn probe_count(&self) -> usize {
        self.probes.len()
    }
}
