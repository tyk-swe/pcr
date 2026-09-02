// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan orchestration across authorization, planning, execution, and results.

use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;

use crate::progress::Runtime;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{diagnostic::Diagnostic, registry::Registry};

use crate::BoundaryError;
use crate::clock::Clock;
use crate::probe::evidence::{EvidenceState, ResponseSelector, Retained, validate_batch_evidence};
use crate::probe::runner::{ProbeLifecycle, run_batches, sink_observer};
use crate::target::{Authorizer, approve_operation, budgeted, resolve_selected};

use super::WORKFLOW;
use super::classification::classify_response;
use super::model::{
    Batch, Classification, Endpoint, Event, Execution, Executor, Limits, Probe, ProbeEndpoint,
    ProbeEvidence, ProbeStatus, Report, Request, Summary, Transport,
};
use super::plan::{build_batches, worst_case_duration};
use super::probe::sent_probe_matches;
use super::{IPV4_PROBE_BYTES, IPV6_PROBE_BYTES};
use crate::probe::{Error, ErrorKind};

/// Validates the request, authorizes every resolved target and the complete
/// operation budget before constructing probes, then executes and classifies
/// checksum-valid correlated responses.
pub fn run<A, E, C>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
) -> Result<Report, Error>
where
    A: Authorizer,
    E: Executor<Batch>,
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
/// on a process-budgeted worker; `max_duration` bounds publisher waiting and
/// live I/O, not arbitrary callback execution. Confirmed sends in the current
/// batch are not undone, callback failure prevents later batches, and a
/// callback may finish after this function returns while holding its permit.
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
    E: Executor<Batch>,
    C: Clock,
    F: FnMut(Event) -> Result<(), BoundaryError> + Send + 'static,
{
    let observe = sink_observer(
        runtime,
        emit,
        |error| scan_duration_error(error.actual, error.limit),
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
    E: Executor<Batch>,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    let mut deadline = Deadline::new(request.limits.max_duration);
    let approved = approve_scan(request, authorizer, &deadline)?;
    let batches = build_batches(request, &approved.addresses, &approved.endpoints)?;
    enforce_deadline(&deadline)?;
    let mut state = EvidenceState::default();
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
        resolved_addresses: approved.addresses,
        stats,
    })
}

#[derive(Default)]
pub(super) struct Collector {
    endpoints: Vec<Endpoint>,
    endpoint_indices: HashMap<(IpAddr, Option<u16>), usize>,
    undecoded: Vec<Frame>,
    diagnostics: Vec<Diagnostic>,
}

impl Collector {
    pub(super) fn observe(&mut self, event: Event) {
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
        #[expect(
            clippy::indexing_slicing,
            reason = "`index` is either a live entry from `endpoint_indices` or the index of the \
                      endpoint just pushed, so it is below `endpoints.len()`"
        )]
        let endpoint = &mut self.endpoints[index];
        if evidence.classification.rank() > endpoint.classification.rank() {
            endpoint.classification = evidence.classification;
        }
        endpoint.probes.push(evidence);
    }

    pub(super) fn finish(self, summary: Summary) -> Report {
        Report {
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
    endpoints: Vec<ProbeEndpoint>,
}

fn approve_scan<A: Authorizer>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
) -> Result<ApprovedScan, Error> {
    let ports = request.selected_ports()?;
    // Implementations must authorize the declared target before DNS and every
    // answer before anything below constructs a probe.
    let resolved = resolve_selected(
        authorizer,
        &request.target,
        request.address_family,
        deadline,
        &WORKFLOW,
    )?;
    if resolved.addresses.is_empty() {
        return Err(Error::new(
            WORKFLOW,
            ErrorKind::Family {
                family: request.address_family.label(),
            },
        ));
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
        return Err(Error::new(
            WORKFLOW,
            ErrorKind::InvalidLimit {
                field: "probes",
                value: u64::try_from(total_probes).unwrap_or(u64::MAX),
                reason: format!("exceeds max_probes={}", request.limits.max_probes),
            },
        ));
    }
    let maximum_bytes = maximum_wire_bytes(&resolved.addresses, endpoints_per_address, request)?;
    let worst_case = worst_case_duration(request, resolved.addresses.len(), endpoints_per_address)?;
    if worst_case > request.limits.max_duration {
        return Err(Error::new(
            WORKFLOW,
            ErrorKind::DurationLimit {
                actual: worst_case,
                limit: request.limits.max_duration,
            },
        ));
    }
    approve_operation(
        authorizer,
        budgeted(
            u64::try_from(total_probes).unwrap_or(u64::MAX),
            maximum_bytes,
        ),
        deadline,
        &WORKFLOW,
    )?;

    let endpoints = match request.transport {
        Transport::Icmp => vec![ProbeEndpoint::Icmp],
        Transport::Tcp => ports
            .into_iter()
            .map(|port| ProbeEndpoint::Tcp { port })
            .collect(),
        Transport::Udp => ports
            .into_iter()
            .map(|port| ProbeEndpoint::Udp { port })
            .collect(),
    };
    Ok(ApprovedScan {
        declared_target: resolved.declared,
        addresses: resolved.addresses,
        endpoints,
    })
}

fn probe_count(
    address_count: usize,
    endpoints_per_address: usize,
    attempts: u32,
) -> Result<usize, Error> {
    address_count
        .checked_mul(endpoints_per_address)
        .and_then(|value| value.checked_mul(usize::try_from(attempts).unwrap_or(usize::MAX)))
        .ok_or(Error::new(
            WORKFLOW,
            ErrorKind::InvalidLimit {
                field: "probes",
                value: u64::MAX,
                reason: "probe-count arithmetic overflowed".to_owned(),
            },
        ))
}

fn maximum_wire_bytes(
    addresses: &[IpAddr],
    endpoints_per_address: usize,
    request: &Request,
) -> Result<u64, Error> {
    addresses.iter().try_fold(0_u64, |total, address| {
        let per_probe = if address.is_ipv4() {
            IPV4_PROBE_BYTES
        } else {
            IPV6_PROBE_BYTES
        };
        let address_probes = u64::try_from(endpoints_per_address)
            .unwrap_or(u64::MAX)
            .checked_mul(u64::from(request.attempts))
            .ok_or(Error::new(
                WORKFLOW,
                ErrorKind::InvalidLimit {
                    field: "wire_bytes",
                    value: u64::MAX,
                    reason: "wire-byte accounting overflowed".to_owned(),
                },
            ))?;
        let address_bytes = per_probe.checked_mul(address_probes).ok_or(Error::new(
            WORKFLOW,
            ErrorKind::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            },
        ))?;
        total.checked_add(address_bytes).ok_or(Error::new(
            WORKFLOW,
            ErrorKind::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            },
        ))
    })
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
    state: &'a mut EvidenceState,
    emit: &'a mut F,
}

impl<E, F> ProbeLifecycle<Probe> for Lifecycle<'_, E, F>
where
    E: Executor<Batch>,
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
        self.process_batch(batch, execution, deadline)?;
        Ok(ControlFlow::Continue(()))
    }
}

impl<E, F> Lifecycle<'_, E, F>
where
    E: Executor<Batch>,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    fn process_batch(
        &mut self,
        batch: &Batch,
        exchange: Execution,
        deadline: &Deadline,
    ) -> Result<(), Error> {
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
        for (request_index, (probe, sent)) in batch.probes.iter().zip(sent.iter()).enumerate() {
            let evidence = self.classify_probe(
                probe,
                sent,
                request_index,
                batch.timeout,
                &mut response_selector,
                deadline,
            )?;
            self.publish_new_diagnostics(deadline)?;
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
    ) -> Result<ProbeEvidence, Error> {
        enforce_deadline(deadline)?;
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
            },
            |observation| observation.classification.rank(),
            |observation| observation.responder,
            || enforce_deadline(deadline),
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
                classification: candidate.observation.classification,
                responder: Some(candidate.observation.responder),
                sent_at,
                received_at: candidate.decoded.frame.timestamp,
                latency: Some(candidate.latency),
                response,
                reason: candidate.observation.reason.to_owned(),
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
        }
    }

    fn retain_undecoded(&mut self, frames: Vec<Frame>, deadline: &Deadline) -> Result<(), Error> {
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
            || enforce_deadline(deadline),
        )
    }

    fn record_diagnostics(
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

fn enforce_deadline(deadline: &Deadline) -> Result<(), Error> {
    crate::clock::check_deadline(deadline, scan_duration_error)
}

fn scan_duration_error(actual: Duration, limit: Duration) -> Error {
    Error::new(WORKFLOW, ErrorKind::DurationLimit { actual, limit })
}
