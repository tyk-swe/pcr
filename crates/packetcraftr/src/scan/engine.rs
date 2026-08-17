// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan orchestration across authorization, planning, execution, and results.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{
    diagnostic::{Diagnostic, push_once as push_diagnostic_once},
    registry::Registry,
};

use crate::BoundaryError;
use crate::clock::Clock;
use crate::evidence::Budget;
use crate::probe::evidence::{ResponseSelector, retain_evidence, retain_undecoded_frames};
use crate::probe::runner::{ProbeBatch, ProbeLifecycle, ProbeRunConfig, run_batches};
use crate::target::{Authorizer, approve_operation, resolve_selected};

use super::classification::classify_response;
use super::error::Error;
use super::evidence::validate_exchange_evidence;
use super::model::{
    Batch, Classification, Endpoint, Execution, Executor, Limits, ProbeEvidence, ProbeStatus,
    Request, Result, Transport,
};
use super::plan::{build_batches, worst_case_duration};
use super::{IPV4_PROBE_BYTES, IPV6_PROBE_BYTES, SCAN_EVIDENCE_DIAGNOSTICS};

/// Validates the request, authorizes every resolved target and the complete
/// operation budget before constructing probes, then executes and classifies
/// checksum-valid correlated responses.
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
    let approved = approve_scan(request, authorizer, &deadline)?;
    let batches = build_batches(request, &approved.addresses, &approved.endpoint_ports)?;
    enforce_deadline(&deadline)?;
    let mut output = initial_output(request, &approved.addresses, &approved.endpoint_ports);
    let config = ProbeRunConfig {
        probes_per_second: request.probes_per_second,
        duration_limit: request.limits.max_duration,
        final_statistics_sequence: u64::try_from(approved.total_probes.saturating_sub(1))
            .unwrap_or(u64::MAX),
    };
    let mut lifecycle = ScanProbeLifecycle {
        executor,
        registry,
        limits: request.limits,
        output: &mut output,
    };
    let run = run_batches(&batches, config, &mut deadline, clock, &mut lifecycle)?;

    Ok(Result {
        target: approved.declared_target,
        resolved_addresses: approved.addresses,
        endpoints: output.endpoints,
        undecoded: output.undecoded,
        diagnostics: output.diagnostics,
        stats: run.stats,
    })
}

struct ApprovedScan {
    declared_target: String,
    addresses: Vec<IpAddr>,
    endpoint_ports: Vec<Option<u16>>,
    total_probes: usize,
}

fn approve_scan<A: Authorizer>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
) -> std::result::Result<ApprovedScan, Error> {
    let ports = request.validate()?;
    // Implementations must authorize the declared target before DNS and every
    // answer before anything below constructs a probe.
    let resolved = resolve_selected(
        authorizer,
        &request.target,
        request.address_family,
        deadline,
        scan_duration_error,
    )?;
    if resolved.addresses.is_empty() {
        return Err(Error::Family {
            family: request.address_family.label(),
        });
    }

    let endpoints_per_address = if request.transport == Transport::Icmp {
        1
    } else {
        ports.len()
    };
    let total_probes = probe_count(
        resolved.addresses.len(),
        endpoints_per_address,
        request.attempts,
    )?;
    if total_probes > request.limits.max_probes {
        return Err(Error::InvalidLimit {
            field: "probes",
            value: u64::try_from(total_probes).unwrap_or(u64::MAX),
            reason: format!("exceeds max_probes={}", request.limits.max_probes),
        });
    }
    let maximum_bytes = maximum_wire_bytes(&resolved.addresses, endpoints_per_address, request)?;
    let worst_case = worst_case_duration(request, resolved.addresses.len(), endpoints_per_address)?;
    if worst_case > request.limits.max_duration {
        return Err(Error::DurationLimit {
            actual: worst_case,
            limit: request.limits.max_duration,
        });
    }
    approve_operation(
        authorizer,
        u64::try_from(total_probes).unwrap_or(u64::MAX),
        maximum_bytes,
        deadline,
        scan_duration_error,
    )?;

    let endpoint_ports = if request.transport == Transport::Icmp {
        vec![None]
    } else {
        ports.into_iter().map(Some).collect()
    };
    Ok(ApprovedScan {
        declared_target: resolved.declared,
        addresses: resolved.addresses,
        endpoint_ports,
        total_probes,
    })
}

fn probe_count(
    address_count: usize,
    endpoints_per_address: usize,
    attempts: u32,
) -> std::result::Result<usize, Error> {
    address_count
        .checked_mul(endpoints_per_address)
        .and_then(|value| value.checked_mul(usize::try_from(attempts).unwrap_or(usize::MAX)))
        .ok_or(Error::InvalidLimit {
            field: "probes",
            value: u64::MAX,
            reason: "probe-count arithmetic overflowed".to_owned(),
        })
}

fn maximum_wire_bytes(
    addresses: &[IpAddr],
    endpoints_per_address: usize,
    request: &Request,
) -> std::result::Result<u64, Error> {
    addresses.iter().try_fold(0_u64, |total, address| {
        let per_probe = if address.is_ipv4() {
            IPV4_PROBE_BYTES
        } else {
            IPV6_PROBE_BYTES
        };
        let address_probes = u64::try_from(endpoints_per_address)
            .unwrap_or(u64::MAX)
            .checked_mul(u64::from(request.attempts))
            .ok_or(Error::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            })?;
        let address_bytes = per_probe
            .checked_mul(address_probes)
            .ok_or(Error::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            })?;
        total.checked_add(address_bytes).ok_or(Error::InvalidLimit {
            field: "wire_bytes",
            value: u64::MAX,
            reason: "wire-byte accounting overflowed".to_owned(),
        })
    })
}

fn initial_output(
    request: &Request,
    addresses: &[IpAddr],
    endpoint_ports: &[Option<u16>],
) -> ScanOutput {
    let endpoints = addresses
        .iter()
        .flat_map(|address| {
            endpoint_ports.iter().map(move |port| Endpoint {
                address: *address,
                transport: request.transport,
                port: *port,
                classification: Classification::Timeout,
                evidence: Vec::with_capacity(
                    usize::try_from(request.attempts).unwrap_or(usize::MAX),
                ),
            })
        })
        .collect::<Vec<_>>();
    let endpoint_indices = endpoints
        .iter()
        .enumerate()
        .map(|(index, endpoint)| ((endpoint.address, endpoint.port), index))
        .collect::<HashMap<_, _>>();
    ScanOutput {
        evidence_budget: Budget::default(),
        endpoints,
        endpoint_indices,
        undecoded: Vec::new(),
        diagnostics: Vec::new(),
    }
}

struct ScanOutput {
    evidence_budget: Budget,
    endpoints: Vec<Endpoint>,
    endpoint_indices: HashMap<(IpAddr, Option<u16>), usize>,
    undecoded: Vec<Frame>,
    diagnostics: Vec<Diagnostic>,
}

struct ScanProbeLifecycle<'a, E> {
    executor: &'a mut E,
    registry: &'a Registry,
    limits: Limits,
    output: &'a mut ScanOutput,
}

impl<E: Executor> ProbeLifecycle<Batch> for ScanProbeLifecycle<'_, E> {
    type Execution = super::model::Execution;
    type Output = ();
    type Error = Error;

    fn execute(&mut self, batch: &Batch) -> std::result::Result<Self::Execution, BoundaryError> {
        self.executor.execute(batch)
    }

    fn validate(
        &mut self,
        batch: &Batch,
        execution: &Self::Execution,
    ) -> std::result::Result<(), Self::Error> {
        validate_exchange_evidence(batch, execution, self.limits)
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
    exchange: Execution,
    registry: &Registry,
    limits: Limits,
    output: &mut ScanOutput,
    deadline: &Deadline,
) -> std::result::Result<(), Error> {
    enforce_deadline(deadline)?;
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
        return Err(Error::InvalidEvidence {
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
            |response| classify_response(registry, probe.transport, &sent.built().packet, response),
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
            ProbeEvidence {
                attempt: probe.attempt,
                status: ProbeStatus::Response,
                classification: candidate.observation.classification,
                responder: Some(candidate.observation.responder),
                sent_at,
                received_at: Some(received_at),
                latency: Some(latency),
                response,
                reason: candidate.observation.reason.to_owned(),
            }
        } else {
            ProbeEvidence {
                attempt: probe.attempt,
                status: ProbeStatus::Timeout,
                classification: Classification::Timeout,
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

fn enforce_deadline(deadline: &Deadline) -> std::result::Result<(), Error> {
    crate::clock::check_deadline(deadline, scan_duration_error)
}

fn scan_duration_error(actual: Duration, limit: Duration) -> Error {
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
