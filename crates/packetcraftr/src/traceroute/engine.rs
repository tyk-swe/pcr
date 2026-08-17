// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Traceroute orchestration across authorization, hop execution, and results.

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
    Batch, Completion, Execution, Executor, Hop, Limits, ProbeEvidence, ProbeStatus, Request,
    ResponseKind, Result, Strategy, UndecodedEvidence,
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
    let mut deadline = Deadline::new(request.limits.max_duration);
    let approved = approve_traceroute(request, authorizer, &deadline)?;
    let batches = build_batches(request, approved.destination)?;
    enforce_deadline(&deadline)?;
    let mut undecoded = Vec::new();
    let mut diagnostics = Vec::new();
    let mut evidence_budget = Budget::default();
    let config = ProbeRunConfig {
        probes_per_second: request.probes_per_second,
        duration_limit: request.limits.max_duration,
        final_statistics_sequence: u64::try_from(approved.total_probes.saturating_sub(1))
            .unwrap_or(u64::MAX),
    };
    let mut lifecycle = Lifecycle {
        executor,
        registry,
        limits: request.limits,
        evidence_budget: &mut evidence_budget,
        undecoded: &mut undecoded,
        diagnostics: &mut diagnostics,
    };
    let run = run_batches(&batches, config, &mut deadline, clock, &mut lifecycle)?;
    let completion = completion(&run.outputs);

    Ok(Result {
        target: approved.declared_target,
        resolved_addresses: approved.resolved_addresses,
        destination: approved.destination,
        strategy: request.strategy,
        destination_port: request.destination_port,
        hops: run.outputs,
        undecoded,
        completion,
        diagnostics,
        stats: run.stats,
    })
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

fn completion(hops: &[Hop]) -> Completion {
    let any_response = hops.iter().any(|hop| {
        hop.probes
            .iter()
            .any(|probe| probe.status == ProbeStatus::Response)
    });
    if hops.iter().any(|hop| {
        hop.probes
            .iter()
            .any(|probe| probe.response_kind == Some(ResponseKind::DestinationReached))
    }) {
        Completion::DestinationReached
    } else if hops.iter().any(|hop| {
        hop.probes
            .iter()
            .any(|probe| probe.response_kind == Some(ResponseKind::Unreachable))
    }) {
        Completion::Unreachable
    } else if any_response {
        Completion::MaximumHops
    } else {
        Completion::Timeout
    }
}

struct TracerouteEvidenceState<'a> {
    budget: &'a mut Budget,
    undecoded: &'a mut Vec<UndecodedEvidence>,
    diagnostics: &'a mut Vec<Diagnostic>,
}

struct Lifecycle<'a, E> {
    executor: &'a mut E,
    registry: &'a Registry,
    limits: Limits,
    evidence_budget: &'a mut Budget,
    undecoded: &'a mut Vec<UndecodedEvidence>,
    diagnostics: &'a mut Vec<Diagnostic>,
}

impl<E: Executor> ProbeLifecycle<Batch> for Lifecycle<'_, E> {
    type Execution = Execution;
    type Output = Hop;
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
        let mut evidence = TracerouteEvidenceState {
            budget: self.evidence_budget,
            undecoded: self.undecoded,
            diagnostics: self.diagnostics,
        };
        process_batch(
            batch,
            execution,
            self.registry,
            self.limits,
            &mut evidence,
            deadline,
        )
    }

    fn should_stop(output: &Self::Output) -> bool {
        terminal_hop(output)
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

fn process_batch(
    batch: &Batch,
    execution: Execution,
    registry: &Registry,
    limits: Limits,
    evidence: &mut TracerouteEvidenceState<'_>,
    deadline: &Deadline,
) -> std::result::Result<Hop, Error> {
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
        packetcraftr_core::diagnostic::push_once(evidence.diagnostics, diagnostic);
    }
    enforce_deadline(deadline)?;
    let mut response_selector = ResponseSelector::new(&mut responses);
    let probes = process_probes(
        batch,
        &sent,
        &mut response_selector,
        registry,
        limits,
        evidence,
        deadline,
    )?;
    let hop_limit = batch.probes[0].hop_limit;
    retain_undecoded_frames(
        batch_undecoded,
        evidence.undecoded,
        limits.max_undecoded,
        evidence.budget,
        TRACEROUTE_EVIDENCE_DIAGNOSTICS,
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
        evidence.diagnostics,
        |frame| UndecodedEvidence { hop_limit, frame },
        || enforce_deadline(deadline),
    )?;
    Ok(Hop { hop_limit, probes })
}

fn process_probes(
    batch: &Batch,
    sent: &[SentPacket],
    response_selector: &mut ResponseSelector<'_>,
    registry: &Registry,
    limits: Limits,
    evidence: &mut TracerouteEvidenceState<'_>,
    deadline: &Deadline,
) -> std::result::Result<Vec<ProbeEvidence>, Error> {
    let mut probes = Vec::with_capacity(batch.probes.len());
    for (request_index, (probe, sent)) in batch.probes.iter().zip(sent.iter()).enumerate() {
        enforce_deadline(deadline)?;
        let sent_at = sent.timing().freshness_marker().wall_clock();
        let best = response_selector.select(
            request_index,
            batch.timeout,
            |response| classify_response(registry, probe.strategy, &sent.built().packet, response),
            |observation| observation.kind.rank(),
            |observation| observation.responder,
            || enforce_deadline(deadline),
        )?;

        let probe_evidence = if let Some(candidate) = best {
            let received_at = crate::live_timestamp(&candidate.decoded.frame);
            let latency = candidate.latency;
            let response = retain_evidence(
                evidence.budget,
                &candidate.decoded.frame,
                TRACEROUTE_EVIDENCE_DIAGNOSTICS,
                limits.max_evidence_frames,
                limits.max_evidence_bytes,
                evidence.diagnostics,
            )
            .then(|| candidate.decoded.frame.clone());
            ProbeEvidence {
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
                received_at: Some(received_at),
                latency: Some(latency),
                response,
                reason: candidate.observation.reason.to_owned(),
            }
        } else {
            ProbeEvidence {
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
            }
        };
        probes.push(probe_evidence);
        enforce_deadline(deadline)?;
    }
    Ok(probes)
}

fn enforce_deadline(deadline: &Deadline) -> std::result::Result<(), Error> {
    crate::clock::check_deadline(deadline, traceroute_duration_error)
}

fn traceroute_duration_error(actual: Duration, limit: Duration) -> Error {
    Error::DurationLimit { actual, limit }
}

fn terminal_hop(hop: &Hop) -> bool {
    hop.probes.iter().any(|probe| {
        matches!(
            probe.response_kind,
            Some(ResponseKind::DestinationReached | ResponseKind::Unreachable)
        )
    })
}

impl ProbeBatch for Batch {
    fn sequence(&self) -> u64 {
        self.probes[0].sequence
    }

    fn probe_count(&self) -> usize {
        self.probes.len()
    }
}
