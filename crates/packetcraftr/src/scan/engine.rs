// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan orchestration across authorization, planning, execution, and results.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{diagnostic::Diagnostic, registry::Registry};

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
    Batch, Classification, Endpoint, Event, Execution, Executor, Limits, Probe, ProbeEvidence,
    ProbeStatus, Request, Result, Summary, Transport,
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
    let mut collector = Collector::default();
    let summary = run_with_events(request, authorizer, registry, executor, clock, |event| {
        collector.observe(event);
        Ok(())
    })?;
    Ok(collector.finish(summary))
}

/// Executes one approved scan and publishes each final probe outcome and
/// retained undecoded frame before beginning later batches.
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
    let approved = approve_scan(request, authorizer, &deadline)?;
    let batches = build_batches(request, &approved.addresses, &approved.endpoint_ports)?;
    enforce_deadline(&deadline)?;
    let mut state = ScanState::default();
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
            state: &mut state,
            emit: &mut emit,
        };
        run_batches(&batches, config, &mut deadline, clock, &mut lifecycle)
    };
    let run = run?;

    Ok(Summary {
        target: approved.declared_target,
        resolved_addresses: approved.addresses,
        diagnostics: state.diagnostics,
        stats: run.stats,
    })
}

#[derive(Default)]
struct Collector {
    endpoints: Vec<Endpoint>,
    endpoint_indices: HashMap<(IpAddr, Option<u16>), usize>,
    undecoded: Vec<Frame>,
}

impl Collector {
    fn observe(&mut self, event: Event) {
        match event {
            Event::Probe {
                target: _,
                address,
                transport,
                port,
                evidence,
            } => self.observe_probe(address, transport, port, evidence),
            Event::Undecoded { frame } => self.undecoded.push(frame),
        }
    }

    fn observe_probe(
        &mut self,
        address: IpAddr,
        transport: Transport,
        port: Option<u16>,
        evidence: ProbeEvidence,
    ) {
        let index = match self.endpoint_indices.get(&(address, port)) {
            Some(index) => *index,
            None => {
                let index = self.endpoints.len();
                self.endpoints.push(Endpoint {
                    address,
                    transport,
                    port,
                    classification: Classification::Timeout,
                    evidence: Vec::new(),
                });
                self.endpoint_indices.insert((address, port), index);
                index
            }
        };
        let endpoint = &mut self.endpoints[index];
        if evidence.classification.rank() > endpoint.classification.rank() {
            endpoint.classification = evidence.classification;
        }
        endpoint.evidence.push(evidence);
    }

    fn finish(self, summary: Summary) -> Result {
        Result {
            target: summary.target,
            resolved_addresses: summary.resolved_addresses,
            endpoints: self.endpoints,
            undecoded: self.undecoded,
            diagnostics: summary.diagnostics,
            stats: summary.stats,
        }
    }
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

#[derive(Default)]
struct ScanState {
    evidence_budget: Budget,
    retained_undecoded: usize,
    diagnostics: Vec<Diagnostic>,
}

struct Lifecycle<'a, E, F> {
    executor: &'a mut E,
    registry: &'a Registry,
    limits: Limits,
    target: &'a str,
    state: &'a mut ScanState,
    emit: &'a mut F,
}

impl<E, F> ProbeLifecycle<Batch> for Lifecycle<'_, E, F>
where
    E: Executor,
    F: FnMut(Event) -> std::result::Result<(), BoundaryError>,
{
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
            self.target,
            self.state,
            self.emit,
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

#[expect(
    clippy::too_many_arguments,
    reason = "batch processing threads trusted execution evidence, command context, limits, state, and the progressive sink"
)]
fn process_batch<F>(
    batch: &Batch,
    exchange: Execution,
    registry: &Registry,
    limits: Limits,
    target: &str,
    state: &mut ScanState,
    emit: &mut F,
    deadline: &Deadline,
) -> std::result::Result<(), Error>
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
    } = exchange;
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

    for (request_index, (probe, sent)) in batch.probes.iter().zip(sent.iter()).enumerate() {
        let evidence = classify_probe(
            probe,
            sent,
            request_index,
            batch.timeout,
            registry,
            limits,
            state,
            &mut response_selector,
            deadline,
        )?;
        emit(Event::Probe {
            target: target.to_owned(),
            address: probe.address,
            transport: probe.transport,
            port: probe.port,
            evidence,
        })
        .map_err(|source| Error::Output { source })?;
        enforce_deadline(deadline)?;
    }

    retain_undecoded_frames(
        batch_undecoded,
        &mut state.retained_undecoded,
        limits.max_undecoded,
        &mut state.evidence_budget,
        SCAN_EVIDENCE_DIAGNOSTICS,
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
        &mut state.diagnostics,
        |frame| Event::Undecoded { frame },
        |event| emit(event).map_err(|source| Error::Output { source }),
        || enforce_deadline(deadline),
    )?;
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "probe classification needs the approved probe, trusted send evidence, response set, and operation limits"
)]
fn classify_probe(
    probe: &Probe,
    sent: &crate::SentPacket,
    request_index: usize,
    timeout: Duration,
    registry: &Registry,
    limits: Limits,
    state: &mut ScanState,
    response_selector: &mut ResponseSelector<'_>,
    deadline: &Deadline,
) -> std::result::Result<ProbeEvidence, Error> {
    enforce_deadline(deadline)?;
    let sent_at = sent.timing().freshness_marker().wall_clock();
    let best = response_selector.select(
        request_index,
        timeout,
        |response| classify_response(registry, probe.transport, &sent.built().packet, response),
        |observation| observation.classification.rank(),
        |observation| observation.responder,
        || enforce_deadline(deadline),
    )?;
    let Some(candidate) = best else {
        return Ok(ProbeEvidence {
            sequence: probe.sequence,
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
        });
    };
    let response = retain_evidence(
        &mut state.evidence_budget,
        &candidate.decoded.frame,
        SCAN_EVIDENCE_DIAGNOSTICS,
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
        &mut state.diagnostics,
    )
    .then(|| candidate.decoded.frame.clone());
    Ok(ProbeEvidence {
        sequence: probe.sequence,
        attempt: probe.attempt,
        status: ProbeStatus::Response,
        classification: candidate.observation.classification,
        responder: Some(candidate.observation.responder),
        sent_at,
        received_at: Some(crate::live_timestamp(&candidate.decoded.frame)),
        latency: Some(candidate.latency),
        response,
        reason: candidate.observation.reason.to_owned(),
    })
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
