// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Traceroute orchestration across authorization, hop execution, and results.

use std::time::Duration;

use packetcraftr_core::budget::{Deadline, DeadlineExceeded};
use packetcraftr_packet::{
    diagnostic::{Diagnostic, push_diagnostic_once},
    registry::ProtocolRegistry,
};

use crate::clock::Clock;
use crate::probe::evidence::{
    EvidenceBudget, ResponseSelector, retain_evidence, retain_undecoded_frames,
};
use crate::probe::runner::{
    ProbeBatch, ProbeExecution, ProbeLifecycle, ProbeRunConfig, run_batches,
};
use crate::target::{Authorizer, approve_operation, resolve_selected};
use crate::{BoundaryError, Stats};

use super::classification::classify_traceroute_response;
use super::error::TracerouteError;
use super::evidence::validate_execution;
use super::model::{
    TracerouteBatch, TracerouteBatchExecution, TracerouteCompletion, TracerouteExecutor,
    TracerouteHopResult, TracerouteLimits, TracerouteProbeEvidence, TracerouteProbeStatus,
    TracerouteRequest, TracerouteResponseKind, TracerouteResult, TracerouteStrategy,
    TracerouteUndecodedEvidence,
};
use super::plan::{build_batches, worst_case_duration};
use super::{MAX_TRACEROUTE_PROBE_BYTES, TRACEROUTE_EVIDENCE_DIAGNOSTICS};

/// Resolves and authorizes the complete target set before constructing a
/// probe, approves the complete packet/byte/time budget, and preserves every
/// attempt until checksum-valid evidence reaches a terminal outcome.
///
/// # Panics
///
/// Panics if a UDP or TCP strategy reaches probe construction without the
/// destination port its request was validated to carry. Every input-driven
/// rejection, including an out-of-range probe port, is reported through
/// [`TracerouteError`].
pub fn traceroute<A, E, C>(
    request: &TracerouteRequest,
    authorizer: &mut A,
    registry: &ProtocolRegistry,
    executor: &mut E,
    clock: &mut C,
) -> Result<TracerouteResult, TracerouteError>
where
    A: Authorizer,
    E: TracerouteExecutor,
    C: Clock,
{
    let mut deadline = Deadline::new(request.limits.max_duration);
    request.validate()?;
    let resolved = resolve_selected(
        authorizer,
        &request.target,
        request.address_family,
        &deadline,
        traceroute_duration_error,
    )?;
    let resolved_addresses = resolved.addresses;
    let Some(&destination) = resolved_addresses.first() else {
        return Err(TracerouteError::AddressFamily {
            family: request.address_family.label(),
        });
    };

    let total_probes = request.total_probe_count()?;
    if total_probes > request.limits.max_probes {
        return Err(TracerouteError::InvalidLimit {
            field: "probes",
            value: total_probes as u64,
            reason: format!("exceeds max_probes={}", request.limits.max_probes),
        });
    }
    if request.strategy == TracerouteStrategy::Udp {
        let base = request.destination_port.expect("validated UDP port");
        let last_offset = total_probes.saturating_sub(1);
        if usize::from(base)
            .checked_add(last_offset)
            .is_none_or(|last| last > u16::MAX as usize)
        {
            return Err(TracerouteError::InvalidPort {
                message: format!(
                    "base UDP port {base} plus {} unique probe(s) exceeds 65535",
                    total_probes
                ),
            });
        }
    }
    let worst_case = worst_case_duration(request)?;
    if worst_case > request.limits.max_duration {
        return Err(TracerouteError::DurationLimit {
            actual: worst_case,
            limit: request.limits.max_duration,
        });
    }
    let maximum_wire_bytes = (total_probes as u64)
        .checked_mul(MAX_TRACEROUTE_PROBE_BYTES)
        .ok_or(TracerouteError::InvalidLimit {
            field: "wire_bytes",
            value: u64::MAX,
            reason: "wire-byte accounting overflowed".to_owned(),
        })?;
    approve_operation(
        authorizer,
        total_probes as u64,
        maximum_wire_bytes,
        &deadline,
        traceroute_duration_error,
    )?;

    let batches = build_batches(request, destination)?;
    enforce_deadline(&deadline)?;
    let mut undecoded = Vec::new();
    let mut diagnostics = Vec::new();
    let mut evidence_budget = EvidenceBudget::default();
    let config = ProbeRunConfig {
        probes_per_second: request.probes_per_second,
        duration_limit: request.limits.max_duration,
        final_statistics_sequence: total_probes.saturating_sub(1) as u64,
    };
    let mut lifecycle = TracerouteProbeLifecycle {
        executor,
        registry,
        limits: request.limits,
        evidence_budget: &mut evidence_budget,
        undecoded: &mut undecoded,
        diagnostics: &mut diagnostics,
    };
    let run = run_batches(&batches, config, &mut deadline, clock, &mut lifecycle)?;
    let any_response = run.outputs.iter().any(|hop| {
        hop.probes
            .iter()
            .any(|probe| probe.status == TracerouteProbeStatus::Response)
    });
    let completion = if run.outputs.iter().any(|hop| {
        hop.probes
            .iter()
            .any(|probe| probe.response_kind == Some(TracerouteResponseKind::DestinationReached))
    }) {
        TracerouteCompletion::DestinationReached
    } else if run.outputs.iter().any(|hop| {
        hop.probes
            .iter()
            .any(|probe| probe.response_kind == Some(TracerouteResponseKind::Unreachable))
    }) {
        TracerouteCompletion::Unreachable
    } else if any_response {
        TracerouteCompletion::MaximumHops
    } else {
        TracerouteCompletion::Timeout
    };

    Ok(TracerouteResult {
        target: resolved.declared,
        resolved_addresses,
        destination,
        strategy: request.strategy,
        destination_port: request.destination_port,
        hops: run.outputs,
        undecoded,
        completion,
        diagnostics,
        stats: run.stats,
    })
}

struct TracerouteEvidenceState<'a> {
    budget: &'a mut EvidenceBudget,
    undecoded: &'a mut Vec<TracerouteUndecodedEvidence>,
    diagnostics: &'a mut Vec<Diagnostic>,
}

struct TracerouteProbeLifecycle<'a, E> {
    executor: &'a mut E,
    registry: &'a ProtocolRegistry,
    limits: TracerouteLimits,
    evidence_budget: &'a mut EvidenceBudget,
    undecoded: &'a mut Vec<TracerouteUndecodedEvidence>,
    diagnostics: &'a mut Vec<Diagnostic>,
}

impl<E: TracerouteExecutor> ProbeLifecycle<TracerouteBatch> for TracerouteProbeLifecycle<'_, E> {
    type Execution = TracerouteBatchExecution;
    type Output = TracerouteHopResult;
    type Error = TracerouteError;

    fn execute(&mut self, batch: &TracerouteBatch) -> Result<Self::Execution, BoundaryError> {
        self.executor.execute(batch)
    }

    fn validate(
        &mut self,
        batch: &TracerouteBatch,
        execution: &Self::Execution,
    ) -> Result<(), Self::Error> {
        validate_execution(batch, execution, self.limits)
    }

    fn process(
        &mut self,
        batch: &TracerouteBatch,
        execution: Self::Execution,
        deadline: &Deadline,
    ) -> Result<Self::Output, Self::Error> {
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
        TracerouteError::InvalidLimit {
            field: "probes_per_second",
            value: u64::from(rate.unwrap_or_default()),
            reason: "rate-delay arithmetic overflowed".to_owned(),
        }
    }

    fn clock_error(sequence: u64, message: String) -> Self::Error {
        TracerouteError::Clock { sequence, message }
    }

    fn execution_error(sequence: u64, source: BoundaryError) -> Self::Error {
        TracerouteError::Execution { sequence, source }
    }

    fn statistics_error(sequence: u64) -> Self::Error {
        TracerouteError::StatisticsOverflow { sequence }
    }
}

fn process_batch(
    batch: &TracerouteBatch,
    execution: TracerouteBatchExecution,
    registry: &ProtocolRegistry,
    limits: TracerouteLimits,
    evidence: &mut TracerouteEvidenceState<'_>,
    deadline: &Deadline,
) -> Result<TracerouteHopResult, TracerouteError> {
    enforce_deadline(deadline)?;
    let TracerouteBatchExecution {
        sent,
        sent_evidence,
        mut responses,
        unsolicited,
        undecoded: batch_undecoded,
        diagnostics: batch_diagnostics,
        stats: _,
    } = execution;
    for diagnostic in batch_diagnostics {
        push_diagnostic_once(evidence.diagnostics, diagnostic);
    }
    enforce_deadline(deadline)?;
    let mut response_selector = ResponseSelector::new(&mut responses, &unsolicited);

    let mut probes = Vec::with_capacity(batch.probes.len());
    for (request_index, ((probe, built), sent_frame)) in batch
        .probes
        .iter()
        .zip(sent.iter())
        .zip(sent_evidence.iter())
        .enumerate()
    {
        enforce_deadline(deadline)?;
        let best = response_selector.select(
            request_index,
            sent_frame.timestamp,
            batch.timeout,
            |response| classify_traceroute_response(registry, probe.strategy, built, response),
            |observation| observation.kind.rank(),
            |observation| observation.responder,
            || enforce_deadline(deadline),
        )?;

        let evidence = if let Some(candidate) = best {
            let received_at = candidate.decoded.frame.timestamp;
            let latency = candidate
                .latency
                .or_else(|| received_at.duration_since(sent_frame.timestamp).ok());
            let response = retain_evidence(
                evidence.budget,
                &candidate.decoded.frame,
                TRACEROUTE_EVIDENCE_DIAGNOSTICS,
                limits.max_evidence_frames,
                limits.max_evidence_bytes,
                evidence.diagnostics,
            )
            .then(|| candidate.decoded.frame.clone());
            TracerouteProbeEvidence {
                sequence: probe.sequence,
                hop_limit: probe.hop_limit,
                attempt: probe.attempt,
                destination: probe.address,
                strategy: probe.strategy,
                destination_port: probe.destination_port,
                status: TracerouteProbeStatus::Response,
                response_kind: Some(candidate.observation.kind),
                responder: Some(candidate.observation.responder),
                sent_at: sent_frame.timestamp,
                received_at: Some(received_at),
                latency,
                response,
                reason: candidate.observation.reason.to_owned(),
            }
        } else {
            TracerouteProbeEvidence {
                sequence: probe.sequence,
                hop_limit: probe.hop_limit,
                attempt: probe.attempt,
                destination: probe.address,
                strategy: probe.strategy,
                destination_port: probe.destination_port,
                status: TracerouteProbeStatus::Timeout,
                response_kind: None,
                responder: None,
                sent_at: sent_frame.timestamp,
                received_at: None,
                latency: None,
                response: None,
                reason: "no checksum-valid, protocol-consistent response before the deadline"
                    .to_owned(),
            }
        };
        probes.push(evidence);
        enforce_deadline(deadline)?;
    }

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
        |frame| TracerouteUndecodedEvidence { hop_limit, frame },
        || enforce_deadline(deadline),
    )?;
    Ok(TracerouteHopResult { hop_limit, probes })
}

fn enforce_deadline(deadline: &Deadline) -> Result<(), TracerouteError> {
    deadline.check().map_err(duration_limit)
}

fn duration_limit(error: DeadlineExceeded) -> TracerouteError {
    TracerouteError::DurationLimit {
        actual: error.actual,
        limit: error.limit,
    }
}

fn traceroute_duration_error(actual: Duration, limit: Duration) -> TracerouteError {
    TracerouteError::DurationLimit { actual, limit }
}

fn terminal_hop(hop: &TracerouteHopResult) -> bool {
    hop.probes.iter().any(|probe| {
        matches!(
            probe.response_kind,
            Some(TracerouteResponseKind::DestinationReached | TracerouteResponseKind::Unreachable)
        )
    })
}

impl ProbeBatch for TracerouteBatch {
    fn sequence(&self) -> u64 {
        self.probes[0].sequence
    }

    fn probe_count(&self) -> usize {
        self.probes.len()
    }
}

impl ProbeExecution for TracerouteBatchExecution {
    fn stats(&self) -> &Stats {
        &self.stats
    }
}
