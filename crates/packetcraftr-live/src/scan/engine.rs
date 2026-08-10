// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan orchestration across authorization, planning, execution, and results.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_packet::budget::{Deadline, DeadlineExceeded};
use packetcraftr_packet::frame::Frame;
use packetcraftr_packet::{
    diagnostic::{Diagnostic, push_diagnostic_once},
    registry::Registry,
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

use super::classification::classify_scan_response;
use super::error::ScanError;
use super::evidence::validate_exchange_evidence;
use super::model::{
    ScanBatch, ScanBatchExecution, ScanClassification, ScanEndpointResult, ScanExecutor,
    ScanLimits, ScanProbeEvidence, ScanProbeStatus, ScanRequest, ScanResult, ScanTransport,
};
use super::plan::{build_batches, worst_case_duration};
use super::{IPV4_PROBE_BYTES, IPV6_PROBE_BYTES, SCAN_EVIDENCE_DIAGNOSTICS};

/// Resolves and authorizes all targets before constructing probes, enforces operation
/// limits, executes batches, and classifies only checksum-valid correlated responses.
pub fn scan<A, E, C>(
    request: &ScanRequest,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
) -> Result<ScanResult, ScanError>
where
    A: Authorizer,
    E: ScanExecutor,
    C: Clock,
{
    let mut deadline = Deadline::new(request.limits.max_duration);
    let ports = request.validate()?;
    // Implementations must perform declared-target authorization before DNS
    // and authorize every answer before anything below constructs a ScanProbe.
    let resolved = resolve_selected(
        authorizer,
        &request.target,
        request.address_family,
        &deadline,
        scan_duration_error,
    )?;
    let addresses = resolved.addresses;
    if addresses.is_empty() {
        return Err(ScanError::Family {
            family: request.address_family.label(),
        });
    }

    let endpoints_per_address = if request.transport == ScanTransport::Icmp {
        1
    } else {
        ports.len()
    };
    let total_probes = addresses
        .len()
        .checked_mul(endpoints_per_address)
        .and_then(|value| value.checked_mul(request.attempts as usize))
        .ok_or(ScanError::InvalidLimit {
            field: "probes",
            value: u64::MAX,
            reason: "probe-count arithmetic overflowed".to_owned(),
        })?;
    if total_probes > request.limits.max_probes {
        return Err(ScanError::InvalidLimit {
            field: "probes",
            value: total_probes as u64,
            reason: format!("exceeds max_probes={}", request.limits.max_probes),
        });
    }
    let maximum_bytes = addresses.iter().try_fold(0_u64, |total, address| {
        let per_probe = if address.is_ipv4() {
            IPV4_PROBE_BYTES
        } else {
            IPV6_PROBE_BYTES
        };
        let address_probes = (endpoints_per_address as u64)
            .checked_mul(u64::from(request.attempts))
            .ok_or(ScanError::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            })?;
        let address_bytes =
            per_probe
                .checked_mul(address_probes)
                .ok_or(ScanError::InvalidLimit {
                    field: "wire_bytes",
                    value: u64::MAX,
                    reason: "wire-byte accounting overflowed".to_owned(),
                })?;
        total
            .checked_add(address_bytes)
            .ok_or(ScanError::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            })
    })?;
    let worst_case = worst_case_duration(request, addresses.len(), endpoints_per_address)?;
    if worst_case > request.limits.max_duration {
        return Err(ScanError::DurationLimit {
            actual: worst_case,
            limit: request.limits.max_duration,
        });
    }
    approve_operation(
        authorizer,
        total_probes as u64,
        maximum_bytes,
        &deadline,
        scan_duration_error,
    )?;

    let endpoint_ports = if request.transport == ScanTransport::Icmp {
        vec![None]
    } else {
        ports.iter().copied().map(Some).collect()
    };
    let batches = build_batches(request, &addresses, &endpoint_ports)?;
    enforce_deadline(&deadline)?;

    let endpoints = addresses
        .iter()
        .flat_map(|address| {
            endpoint_ports.iter().map(move |port| ScanEndpointResult {
                address: *address,
                transport: request.transport,
                port: *port,
                classification: ScanClassification::Timeout,
                evidence: Vec::with_capacity(request.attempts as usize),
            })
        })
        .collect::<Vec<_>>();
    let endpoint_indices = endpoints
        .iter()
        .enumerate()
        .map(|(index, endpoint)| ((endpoint.address, endpoint.port), index))
        .collect::<HashMap<_, _>>();
    let mut output = ScanOutput {
        evidence_budget: EvidenceBudget::default(),
        endpoints,
        endpoint_indices,
        undecoded: Vec::new(),
        diagnostics: Vec::new(),
    };
    let config = ProbeRunConfig {
        probes_per_second: request.probes_per_second,
        duration_limit: request.limits.max_duration,
        final_statistics_sequence: total_probes.saturating_sub(1) as u64,
    };
    let mut lifecycle = ScanProbeLifecycle {
        executor,
        registry,
        limits: request.limits,
        output: &mut output,
    };
    let run = run_batches(&batches, config, &mut deadline, clock, &mut lifecycle)?;

    Ok(ScanResult {
        target: resolved.declared,
        resolved_addresses: addresses,
        endpoints: output.endpoints,
        undecoded: output.undecoded,
        diagnostics: output.diagnostics,
        stats: run.stats,
    })
}

struct ScanOutput {
    evidence_budget: EvidenceBudget,
    endpoints: Vec<ScanEndpointResult>,
    endpoint_indices: HashMap<(IpAddr, Option<u16>), usize>,
    undecoded: Vec<Frame>,
    diagnostics: Vec<Diagnostic>,
}

struct ScanProbeLifecycle<'a, E> {
    executor: &'a mut E,
    registry: &'a Registry,
    limits: ScanLimits,
    output: &'a mut ScanOutput,
}

impl<E: ScanExecutor> ProbeLifecycle<ScanBatch> for ScanProbeLifecycle<'_, E> {
    type Execution = ScanBatchExecution;
    type Output = ();
    type Error = ScanError;

    fn execute(&mut self, batch: &ScanBatch) -> Result<Self::Execution, BoundaryError> {
        self.executor.execute(batch)
    }

    fn validate(
        &mut self,
        batch: &ScanBatch,
        execution: &Self::Execution,
    ) -> Result<(), Self::Error> {
        validate_exchange_evidence(batch, execution, self.limits)
    }

    fn process(
        &mut self,
        batch: &ScanBatch,
        execution: Self::Execution,
        deadline: &Deadline,
    ) -> Result<Self::Output, Self::Error> {
        process_batch(
            batch,
            execution,
            self.registry,
            self.limits,
            self.output,
            deadline,
        )
    }

    fn should_stop((): &Self::Output) -> bool {
        false
    }

    fn duration_error(actual: Duration, limit: Duration) -> Self::Error {
        scan_duration_error(actual, limit)
    }

    fn rate_error(rate: Option<u32>) -> Self::Error {
        ScanError::InvalidLimit {
            field: "probes_per_second",
            value: u64::from(rate.unwrap_or_default()),
            reason: "rate-delay arithmetic overflowed".to_owned(),
        }
    }

    fn clock_error(sequence: u64, message: String) -> Self::Error {
        ScanError::Clock { sequence, message }
    }

    fn execution_error(sequence: u64, source: BoundaryError) -> Self::Error {
        ScanError::Execution { sequence, source }
    }

    fn statistics_error(sequence: u64) -> Self::Error {
        ScanError::StatisticsOverflow { sequence }
    }
}

fn process_batch(
    batch: &ScanBatch,
    exchange: ScanBatchExecution,
    registry: &Registry,
    limits: ScanLimits,
    output: &mut ScanOutput,
    deadline: &Deadline,
) -> Result<(), ScanError> {
    enforce_deadline(deadline)?;
    let ScanBatchExecution {
        permit,
        sent,
        mut responses,
        unsolicited: _,
        undecoded: batch_undecoded,
        diagnostics: batch_diagnostics,
        stats: _,
    } = exchange;
    if permit != batch.permit {
        return Err(ScanError::InvalidEvidence {
            sequence: batch.sequence(),
            message: "executor returned evidence for a different execution permit".to_owned(),
        });
    }
    for diagnostic in batch_diagnostics {
        push_diagnostic_once(&mut output.diagnostics, diagnostic);
    }
    enforce_deadline(deadline)?;
    let mut response_selector = ResponseSelector::new(&mut responses);

    for (request_index, (probe, sent)) in batch.probes.iter().zip(sent.iter()).enumerate() {
        enforce_deadline(deadline)?;
        let sent_at = sent.timing().freshness_marker().wall_clock();
        let best = response_selector.select(
            request_index,
            batch.timeout,
            |response| {
                classify_scan_response(registry, probe.transport, &sent.built().packet, response)
            },
            |observation| observation.classification.rank(),
            |observation| observation.responder,
            || enforce_deadline(deadline),
        )?;

        let endpoint_index = output
            .endpoint_indices
            .get(&(probe.address, probe.port))
            .copied()
            .expect("validated scan probe must have a result endpoint");
        let endpoint = &mut output.endpoints[endpoint_index];
        let evidence = if let Some(candidate) = best {
            let received_at = crate::live_timestamp(&candidate.decoded.frame);
            let latency = candidate.latency;
            let response = retain_evidence(
                &mut output.evidence_budget,
                &candidate.decoded.frame,
                SCAN_EVIDENCE_DIAGNOSTICS,
                limits.max_evidence_frames,
                limits.max_evidence_bytes,
                &mut output.diagnostics,
            )
            .then(|| candidate.decoded.frame.clone());
            if candidate.observation.classification.rank() > endpoint.classification.rank() {
                endpoint.classification = candidate.observation.classification;
            }
            ScanProbeEvidence {
                attempt: probe.attempt,
                status: ScanProbeStatus::Response,
                classification: candidate.observation.classification,
                responder: Some(candidate.observation.responder),
                sent_at,
                received_at: Some(received_at),
                latency: Some(latency),
                response,
                reason: candidate.observation.reason.to_owned(),
            }
        } else {
            ScanProbeEvidence {
                attempt: probe.attempt,
                status: ScanProbeStatus::Timeout,
                classification: ScanClassification::Timeout,
                responder: None,
                sent_at,
                received_at: None,
                latency: None,
                response: None,
                reason: "no checksum-valid, protocol-consistent response before the deadline"
                    .to_owned(),
            }
        };
        endpoint.evidence.push(evidence);
        enforce_deadline(deadline)?;
    }

    retain_undecoded_frames(
        batch_undecoded,
        &mut output.undecoded,
        limits.max_undecoded,
        &mut output.evidence_budget,
        SCAN_EVIDENCE_DIAGNOSTICS,
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
        &mut output.diagnostics,
        |frame| frame,
        || enforce_deadline(deadline),
    )?;
    Ok(())
}

fn enforce_deadline(deadline: &Deadline) -> Result<(), ScanError> {
    deadline.check().map_err(duration_limit)
}

fn duration_limit(error: DeadlineExceeded) -> ScanError {
    ScanError::DurationLimit {
        actual: error.actual,
        limit: error.limit,
    }
}

fn scan_duration_error(actual: Duration, limit: Duration) -> ScanError {
    ScanError::DurationLimit { actual, limit }
}

impl ProbeBatch for ScanBatch {
    fn sequence(&self) -> u64 {
        self.probes[0].sequence
    }

    fn probe_count(&self) -> usize {
        self.probes.len()
    }
}

impl ProbeExecution for ScanBatchExecution {
    fn stats(&self) -> &Stats {
        &self.stats
    }
}
