// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan orchestration across authorization, planning, execution, and results.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{diagnostic::Diagnostic, registry::Registry};

use crate::BoundaryError;
use crate::clock::Clock;
use crate::evidence::Budget;
use crate::probe::evidence::{ResponseSelector, UndecodedRetention, retain_evidence};
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

/// Executes one approved scan and publishes each final probe outcome and
/// retained undecoded frame before beginning later batches. The callback runs
/// on a bounded worker; a callback that does not return cannot keep live I/O
/// armed beyond `max_duration`. Confirmed sends in the current batch are not
/// undone, callback failure prevents later batches, and a worker that outlives
/// the deadline may finish after this function returns and must own its state.
pub fn run_with_events<A, E, C, F>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    emit: F,
) -> std::result::Result<Summary, Error>
where
    A: Authorizer,
    E: Executor,
    C: Clock,
    F: FnMut(Event) -> std::result::Result<(), BoundaryError> + Send + 'static,
{
    let sink =
        packetcraftr_core::progress::Sink::new(emit).map_err(|source| Error::Output { source })?;
    run_observed(
        request,
        authorizer,
        registry,
        executor,
        clock,
        move |event, deadline| match sink.emit(event, deadline) {
            Ok(()) => Ok(()),
            Err(packetcraftr_core::progress::EmitError::Deadline(error)) => {
                Err(scan_duration_error(error.actual, error.limit))
            }
            Err(packetcraftr_core::progress::EmitError::Output(source)) => {
                Err(Error::Output { source })
            }
        },
    )
}

fn run_observed<A, E, C, F>(
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
    F: FnMut(Event, &Deadline) -> std::result::Result<(), Error>,
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
    let stats = {
        let mut lifecycle = Lifecycle {
            executor,
            registry,
            limits: request.limits,
            target: Arc::from(approved.declared_target.as_str()),
            state: &mut state,
            emit: &mut emit,
        };
        run_batches(&batches, config, &mut deadline, clock, &mut lifecycle)
    };
    let stats = stats?;

    Ok(Summary {
        target: approved.declared_target,
        resolved_addresses: approved.addresses,
        diagnostics: Vec::new(),
        stats,
    })
}

#[derive(Default)]
pub struct Collector {
    endpoints: Vec<Endpoint>,
    endpoint_indices: HashMap<(IpAddr, Option<u16>), usize>,
    undecoded: Vec<Frame>,
    diagnostics: Vec<Diagnostic>,
}

impl Collector {
    pub fn observe(&mut self, event: Event) {
        match event {
            Event::Probe { target: _, probe } => self.observe_probe(probe),
            Event::Undecoded { frame } => self.undecoded.push(frame),
            Event::Diagnostic(diagnostic) => self.diagnostics.push(diagnostic),
        }
    }

    fn observe_probe(&mut self, evidence: ProbeEvidence) {
        let address = evidence.address;
        let transport = evidence.transport;
        let port = evidence.port;
        let index = match self.endpoint_indices.get(&(address, port)) {
            Some(index) => *index,
            None => {
                let index = self.endpoints.len();
                self.endpoints.push(Endpoint {
                    address,
                    transport,
                    port,
                    classification: Classification::Timeout,
                    probes: Vec::new(),
                });
                self.endpoint_indices.insert((address, port), index);
                index
            }
        };
        let endpoint = &mut self.endpoints[index];
        if evidence.classification.rank() > endpoint.classification.rank() {
            endpoint.classification = evidence.classification;
        }
        endpoint.probes.push(evidence);
    }

    pub fn finish(mut self, summary: Summary) -> Result {
        self.diagnostics.extend(summary.diagnostics);
        Result {
            target: summary.target,
            resolved_addresses: summary.resolved_addresses,
            endpoints: self.endpoints,
            undecoded: self.undecoded,
            diagnostics: self.diagnostics,
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

struct ProbeOutcome {
    status: ProbeStatus,
    classification: Classification,
    responder: Option<IpAddr>,
    sent_at: std::time::SystemTime,
    received_at: Option<std::time::SystemTime>,
    latency: Option<Duration>,
    response: Option<Frame>,
    reason: String,
}

struct Lifecycle<'a, E, F> {
    executor: &'a mut E,
    registry: &'a Registry,
    limits: Limits,
    target: Arc<str>,
    state: &'a mut ScanState,
    emit: &'a mut F,
}

impl<E, F> ProbeLifecycle<Batch> for Lifecycle<'_, E, F>
where
    E: Executor,
    F: FnMut(Event, &Deadline) -> std::result::Result<(), Error>,
{
    type Execution = super::model::Execution;
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
    ) -> std::result::Result<bool, Self::Error> {
        self.process_batch(batch, execution, deadline)?;
        Ok(false)
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

impl<E, F> Lifecycle<'_, E, F>
where
    E: Executor,
    F: FnMut(Event, &Deadline) -> std::result::Result<(), Error>,
{
    fn process_batch(
        &mut self,
        batch: &Batch,
        exchange: Execution,
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
            self.record_diagnostic(diagnostic, deadline)?;
        }
        enforce_deadline(deadline)?;
        let mut response_selector = ResponseSelector::new(&mut responses);
        for (request_index, (probe, sent)) in batch.probes.iter().zip(sent.iter()).enumerate() {
            let diagnostic_start = self.state.diagnostics.len();
            let evidence = self.classify_probe(
                probe,
                sent,
                request_index,
                batch.timeout,
                &mut response_selector,
                deadline,
            )?;
            self.publish_diagnostics_since(diagnostic_start, deadline)?;
            (self.emit)(
                Event::Probe {
                    target: Arc::clone(&self.target),
                    probe: evidence,
                },
                deadline,
            )?;
            enforce_deadline(deadline)?;
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
    ) -> std::result::Result<ProbeEvidence, Error> {
        enforce_deadline(deadline)?;
        let sent_at = sent.timing().freshness_marker().wall_clock();
        let best = response_selector.select(
            request_index,
            timeout,
            |response| {
                classify_response(
                    self.registry,
                    probe.transport,
                    &sent.built().packet,
                    response,
                )
            },
            |observation| observation.classification.rank(),
            |observation| observation.responder,
            || enforce_deadline(deadline),
        )?;
        let Some(candidate) = best else {
            return Ok(self.probe_evidence(
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
                },
            ));
        };
        let response = retain_evidence(
            &mut self.state.evidence_budget,
            &candidate.decoded.frame,
            SCAN_EVIDENCE_DIAGNOSTICS,
            self.limits.max_evidence_frames,
            self.limits.max_evidence_bytes,
            &mut self.state.diagnostics,
        )
        .then(|| candidate.decoded.frame.clone());
        Ok(self.probe_evidence(
            probe,
            ProbeOutcome {
                status: ProbeStatus::Response,
                classification: candidate.observation.classification,
                responder: Some(candidate.observation.responder),
                sent_at,
                received_at: Some(crate::live_timestamp(&candidate.decoded.frame)),
                latency: Some(candidate.latency),
                response,
                reason: candidate.observation.reason.to_owned(),
            },
        ))
    }

    fn probe_evidence(&self, probe: &Probe, outcome: ProbeOutcome) -> ProbeEvidence {
        ProbeEvidence {
            sequence: probe.sequence,
            address: probe.address,
            transport: probe.transport,
            port: probe.port,
            attempt: probe.attempt,
            status: outcome.status,
            classification: outcome.classification,
            responder: outcome.responder,
            sent_at: outcome.sent_at,
            received_at: outcome.received_at,
            latency: outcome.latency,
            response: outcome.response,
            reason: outcome.reason,
        }
    }

    fn retain_undecoded(
        &mut self,
        frames: Vec<Frame>,
        deadline: &Deadline,
    ) -> std::result::Result<(), Error> {
        let mut retention = UndecodedRetention::new(
            &mut self.state.retained_undecoded,
            self.limits.max_undecoded,
            &mut self.state.evidence_budget,
            SCAN_EVIDENCE_DIAGNOSTICS,
            self.limits.max_evidence_frames,
            self.limits.max_evidence_bytes,
            &mut self.state.diagnostics,
        );
        retention.retain(
            frames,
            |frame| Event::Undecoded { frame },
            Event::Diagnostic,
            |event| (self.emit)(event, deadline),
            || enforce_deadline(deadline),
        )
    }

    fn record_diagnostic(
        &mut self,
        diagnostic: Diagnostic,
        deadline: &Deadline,
    ) -> std::result::Result<(), Error> {
        let previous = self.state.diagnostics.len();
        packetcraftr_core::diagnostic::push_once(&mut self.state.diagnostics, diagnostic);
        self.publish_diagnostics_since(previous, deadline)
    }

    fn publish_diagnostics_since(
        &mut self,
        start: usize,
        deadline: &Deadline,
    ) -> std::result::Result<(), Error> {
        let diagnostics = self.state.diagnostics[start..].to_vec();
        for diagnostic in diagnostics {
            (self.emit)(Event::Diagnostic(diagnostic), deadline)?;
        }
        Ok(())
    }
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
