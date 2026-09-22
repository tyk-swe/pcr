// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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
use crate::policy::Authorizer;
use crate::probe::evidence::{
    EvidenceState, ResponseSelector, Retained, check_probe_count, check_probe_duration,
    validate_batch_evidence,
};
use crate::probe::runner::{ProbeLifecycle, run_batches, sink_observer};
use crate::target::{DeclaredTargets, admit_selection, budgeted};

use super::WORKFLOW;
use super::classification::classify_response;
use super::plan::{build_batches, worst_case_duration};
use super::probe::sent_probe_matches;
use super::{
    Batch, Classification, ClassificationCounts, Endpoint, Event, Limits, Probe, ProbeEvidence,
    Report, Request, Summary,
};
use super::{IPV4_PROBE_BYTES, IPV6_PROBE_BYTES};
use crate::probe::{
    Error, ErrorKind, Execution, Executor, ProbeEndpoint, ProbeStatus, Transport, duration_limit,
    enforce_deadline, index_or_push,
};
use crate::probe::{PipelineEvent, PipelineOptions};

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
/// on a runtime-budgeted worker; `max_duration` bounds publisher waiting and
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
        |error| duration_limit(WORKFLOW, error.actual, error.limit),
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
    let mut deadline =
        Deadline::new(request.limits.max_duration).with_cancellation(clock.cancellation());
    enforce_deadline(WORKFLOW, &deadline)?;
    if (2..=1024).contains(&request.max_in_flight)
        && request.max_in_flight > executor.pipeline_capacity()
    {
        return Err(Error::new(
            WORKFLOW,
            ErrorKind::PipelineExecution {
                source: BoundaryError::new(
                    "executor cannot provide the requested packet window",
                    packetcraftr_core::error::Classification::new(
                        "capability.probe_pipeline",
                        packetcraftr_core::error::Kind::Capability,
                        Some("use max_in_flight=1 or a pipeline-capable executor"),
                    ),
                    Vec::new(),
                ),
            },
        ));
    }
    let approved = approve_scan(request, authorizer, &deadline)?;
    let batches = build_batches(request, &approved.addresses, &approved.endpoints)?;
    enforce_deadline(WORKFLOW, &deadline)?;
    let mut state = EvidenceState::default();
    let mut winners = HashMap::new();
    let mut rtt = super::report::RttAccumulator::default();
    let mut processor = Processor {
        registry,
        limits: request.limits,
        target: Arc::from(approved.declared_target.as_str()),
        state: &mut state,
        winners: &mut winners,
        rtt: &mut rtt,
        emit: &mut emit,
    };
    let stats = if request.max_in_flight == 1 {
        let mut lifecycle = Lifecycle {
            executor,
            processor: &mut processor,
        };
        run_batches(
            WORKFLOW,
            batches,
            request.probes_per_second,
            &mut deadline,
            clock,
            &mut lifecycle,
        )
    } else {
        run_pipelined(
            request,
            executor,
            &mut processor,
            &deadline,
            batches,
            &approved,
        )
    };
    let stats = stats?;
    let mut counts = ClassificationCounts::default();
    for classification in winners.into_values() {
        counts.increment(classification);
    }

    Ok(Summary {
        planned_duration: approved.planned_duration,
        target: approved.declared_target,
        resolved_addresses: approved.addresses,
        counts,
        stats,
        rtt: rtt.finish(),
    })
}

/// Executes the scan through the executor's rolling packet window, publishing
/// the same events the serial path emits. The completion check rejects a
/// pipeline whose reported statistics disagree with the validated sends.
fn run_pipelined<E, F, B>(
    request: &Request,
    executor: &mut E,
    processor: &mut Processor<'_, F>,
    deadline: &Deadline,
    batches: B,
    approved: &ApprovedScan,
) -> Result<crate::Stats, Error>
where
    E: Executor<Batch>,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
    B: Iterator<Item = Batch>,
{
    let count = approved
        .addresses
        .len()
        .saturating_mul(approved.endpoints.len())
        .saturating_mul(request.attempts as usize);
    if count.saturating_mul(std::mem::size_of::<Batch>()) > request.limits.max_prepared_bytes {
        return Err(Error::new(
            WORKFLOW,
            ErrorKind::PipelineExecution {
                source: super::pipeline::limit(
                    "prepared descriptions",
                    request.limits.max_prepared_bytes,
                ),
            },
        ));
    }
    let batches: Vec<_> = batches.collect();
    let mut completed = vec![false; batches.len()];
    let mut confirmed = vec![false; batches.len()];
    let mut sent_bytes = 0u64;
    let remaining = deadline
        .remaining()
        .map_err(|error| duration_limit(WORKFLOW, error.actual, error.limit))?;
    let settings = PipelineOptions {
        max_in_flight: request.max_in_flight,
        probes_per_second: request.probes_per_second,
        max_duration: remaining,
        max_prepared_bytes: request.limits.max_prepared_bytes,
        max_evidence_frames: request.limits.max_evidence_frames,
        max_evidence_bytes: request.limits.max_evidence_bytes,
        max_undecoded: request.limits.max_undecoded,
    };
    let result = executor.execute_pipeline(&batches, settings, &mut |event| {
        let invalid = |index| {
            crate::BoundaryError::from_error(Error::new(
                WORKFLOW,
                ErrorKind::InvalidEvidence {
                    sequence: index as u64,
                    message: "pipeline returned an invalid or repeated request index".to_owned(),
                },
            ))
        };
        match event {
            PipelineEvent::Sent { index, sent } => {
                let batch = batches.get(index).ok_or_else(|| invalid(index))?;
                if confirmed[index] || !sent_probe_matches(&batch.probe, &sent.built().packet) {
                    return Err(invalid(index));
                }
                confirmed[index] = true;
                sent_bytes = sent_bytes
                    .checked_add(sent.bytes_sent() as u64)
                    .ok_or_else(|| invalid(index))?;
                (processor.emit)(
                    Event::Sent(super::SentProbe {
                        probe: batch.probe.clone(),
                        sent,
                    }),
                    deadline,
                )
                .map_err(crate::BoundaryError::from_error)?;
            }
            PipelineEvent::Completed { index, execution } => {
                let batch = batches.get(index).ok_or_else(|| invalid(index))?;
                if completed[index] || !confirmed[index] {
                    return Err(invalid(index));
                }
                validate_batch_evidence(
                    WORKFLOW,
                    std::slice::from_ref(&batch.probe),
                    batch.timeout,
                    &execution,
                    request.limits.evidence(),
                    sent_probe_matches,
                )
                .map_err(crate::BoundaryError::from_error)?;
                processor
                    .process_batch(batch, execution, deadline)
                    .map_err(crate::BoundaryError::from_error)?;
                completed[index] = true;
            }
            PipelineEvent::Undecoded { frame } => processor
                .retain_undecoded(vec![frame], deadline)
                .map_err(crate::BoundaryError::from_error)?,
            PipelineEvent::Diagnostic(diagnostic) => processor
                .record_diagnostics(vec![diagnostic], deadline)
                .map_err(crate::BoundaryError::from_error)?,
        }
        Ok(())
    });
    match result {
        Ok(stats) => {
            if completed.iter().any(|done| !*done)
                || stats.packets_attempted != batches.len() as u64
                || stats.packets_completed != batches.len() as u64
                || stats.bytes != sent_bytes
            {
                return Err(Error::new(
                    WORKFLOW,
                    ErrorKind::InvalidEvidence {
                        sequence: 0,
                        message:
                            "pipeline completion statistics disagree with validated sends/outcomes"
                                .to_owned(),
                    },
                ));
            }
            enforce_deadline(WORKFLOW, deadline)?;
            Ok(stats)
        }
        Err(source) => Err(Error::new(
            WORKFLOW,
            ErrorKind::PipelineExecution { source },
        )),
    }
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
            Event::Sent(_) => {}
            Event::Probe { target: _, probe } => self.observe_probe(probe),
            Event::Undecoded { frame } => self.undecoded.push(frame),
            Event::Diagnostic(diagnostic) => self.diagnostics.push(diagnostic),
        }
    }

    fn observe_probe(&mut self, evidence: ProbeEvidence) {
        let address = evidence.address;
        let transport = evidence.transport;
        let port = evidence.port;
        let endpoint = index_or_push(
            &mut self.endpoints,
            &mut self.endpoint_indices,
            (address, port),
            || Endpoint {
                address,
                transport,
                port,
                classification: Classification::Timeout,
                probes: Vec::new(),
            },
        );
        endpoint.classification.promote(evidence.classification);
        endpoint.probes.push(evidence);
    }

    pub(super) fn finish(mut self, summary: Summary) -> Report {
        for endpoint in &mut self.endpoints {
            endpoint.probes.sort_by_key(|probe| probe.sequence);
        }
        self.endpoints
            .sort_by_key(|endpoint| endpoint.probes.first().map(|probe| probe.sequence));
        Report {
            planned_duration: summary.planned_duration,
            target: summary.target,
            resolved_addresses: summary.resolved_addresses,
            endpoints: self.endpoints,
            undecoded: self.undecoded,
            diagnostics: self.diagnostics,
            stats: summary.stats,
            rtt: summary.rtt,
        }
    }
}

struct ApprovedScan {
    planned_duration: std::time::Duration,
    declared_target: String,
    addresses: Vec<IpAddr>,
    endpoints: Vec<ProbeEndpoint>,
}

/// The complete cost charged to the operation budget before any probe.
struct ScanPlan {
    total_probes: usize,
    maximum_bytes: u64,
    worst_case: Duration,
}

fn approve_scan<A: Authorizer>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
) -> Result<ApprovedScan, Error> {
    let ports = request.selected_ports()?;
    // Implementations must authorize the declared target before DNS and every
    // answer before anything below constructs a probe; `admit_selection` owns
    // that ordering.
    let (selected, plan) = admit_selection(
        authorizer,
        deadline,
        &WORKFLOW,
        DeclaredTargets {
            selection: &request.targets,
            family: request.address_family,
            max_targets: request.limits.max_targets,
        },
        |source| Error::new(WORKFLOW, ErrorKind::TargetSelection(source)),
        |selected| {
            let endpoints_per_address = if request.transport == Transport::Icmp {
                1
            } else {
                ports.len()
            };
            let total_probes = probe_count(
                selected.addresses.len(),
                endpoints_per_address,
                request.attempts,
            )?;
            check_probe_count(WORKFLOW, total_probes, request.limits.max_probes)?;
            let maximum_bytes = maximum_wire_bytes(&selected.addresses, &ports, request)?;
            let worst_case =
                worst_case_duration(request, selected.addresses.len(), endpoints_per_address)?;
            check_probe_duration(WORKFLOW, worst_case, request.limits.max_duration)?;
            Ok(ScanPlan {
                total_probes,
                maximum_bytes,
                worst_case,
            })
        },
        |plan| {
            Ok(budgeted(
                u64::try_from(plan.total_probes).unwrap_or(u64::MAX),
                plan.maximum_bytes,
            ))
        },
    )?;

    let endpoints = probe_endpoints(request.transport, ports);
    Ok(ApprovedScan {
        planned_duration: plan.worst_case,
        declared_target: selected.declared,
        addresses: selected.addresses,
        endpoints,
    })
}

fn probe_endpoints(transport: Transport, ports: Vec<u16>) -> Vec<ProbeEndpoint> {
    match transport {
        Transport::Icmp => vec![ProbeEndpoint::Icmp],
        Transport::Tcp => ports
            .into_iter()
            .map(|port| ProbeEndpoint::Tcp { port })
            .collect(),
        Transport::Udp => ports
            .into_iter()
            .map(|port| ProbeEndpoint::Udp { port })
            .collect(),
    }
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
    ports: &[u16],
    request: &Request,
) -> Result<u64, Error> {
    let overflow = || {
        Error::new(
            WORKFLOW,
            ErrorKind::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "scan payload accounting overflowed".to_owned(),
            },
        )
    };
    let endpoints = if request.transport == Transport::Icmp {
        1
    } else {
        ports.len() as u64
    };
    let payload = if request.transport == Transport::Udp {
        ports.iter().try_fold(0u64, |total, port| {
            total
                .checked_add(
                    request
                        .udp_profiles
                        .get(port)
                        .map_or(request.udp_payload.len(), |profile| {
                            profile.payload_length()
                        }) as u64,
                )
                .ok_or_else(overflow)
        })?
    } else {
        0
    };
    addresses.iter().try_fold(0u64, |total, address| {
        let header = if address.is_ipv4() {
            IPV4_PROBE_BYTES
        } else {
            IPV6_PROBE_BYTES
        };
        let bytes = header
            .checked_mul(endpoints)
            .and_then(|bytes| bytes.checked_add(payload))
            .and_then(|bytes| bytes.checked_mul(u64::from(request.attempts)))
            .ok_or_else(overflow)?;
        total.checked_add(bytes).ok_or_else(overflow)
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
    application: Option<super::profile::Evidence>,
}

struct Processor<'a, F> {
    registry: &'a Registry,
    limits: Limits,
    target: Arc<str>,
    state: &'a mut EvidenceState,
    /// The winning classification per endpoint, so the summary reports counts
    /// without a collector.
    winners: &'a mut HashMap<(IpAddr, Option<u16>), Classification>,
    rtt: &'a mut super::report::RttAccumulator,
    emit: &'a mut F,
}
struct Lifecycle<'a, 'b, E, F> {
    executor: &'a mut E,
    processor: &'a mut Processor<'b, F>,
}

impl<E, F> ProbeLifecycle<Batch> for Lifecycle<'_, '_, E, F>
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
            std::slice::from_ref(&batch.probe),
            batch.timeout,
            execution,
            self.processor.limits.evidence(),
            sent_probe_matches,
        )
    }

    fn process(
        &mut self,
        batch: &Batch,
        execution: Execution,
        deadline: &Deadline,
    ) -> Result<ControlFlow<()>, Error> {
        self.processor.process_batch(batch, execution, deadline)?;
        Ok(ControlFlow::Continue(()))
    }
}

impl<F> Processor<'_, F>
where
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    fn process_batch(
        &mut self,
        batch: &Batch,
        exchange: Execution,
        deadline: &Deadline,
    ) -> Result<(), Error> {
        enforce_deadline(WORKFLOW, deadline)?;
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
                    sequence: batch.probe.sequence,
                    message: "executor returned evidence for a different execution permit"
                        .to_owned(),
                },
            ));
        }
        self.record_diagnostics(batch_diagnostics, deadline)?;
        enforce_deadline(WORKFLOW, deadline)?;
        let mut response_selector = ResponseSelector::new(&mut responses);
        for (request_index, (probe, sent)) in
            std::iter::once(&batch.probe).zip(sent.iter()).enumerate()
        {
            let evidence = self.classify_probe(
                probe,
                sent,
                request_index,
                batch.timeout,
                &mut response_selector,
                deadline,
            )?;
            self.publish_new_diagnostics(deadline)?;
            self.winners
                .entry((evidence.address, evidence.port))
                .or_insert(Classification::Timeout)
                .promote(evidence.classification);
            self.rtt.note_sent();
            if evidence.status == ProbeStatus::Response
                && let Some(latency) = evidence.latency
            {
                self.rtt.note_received(latency);
            }
            (self.emit)(
                Event::Probe {
                    target: Arc::clone(&self.target),
                    probe: evidence,
                },
                deadline,
            )?;
            enforce_deadline(WORKFLOW, deadline)?;
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
        enforce_deadline(WORKFLOW, deadline)?;
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
                .map(|classified| {
                    (
                        classified,
                        super::profile::evidence(probe, &sent.built().packet, response),
                    )
                })
            },
            |observation| {
                observation.0.classification.rank() * 4
                    + observation
                        .1
                        .as_ref()
                        .map_or(2, super::profile::Evidence::rank)
            },
            |observation| observation.0.responder,
            || enforce_deadline(WORKFLOW, deadline),
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
                    application: probe
                        .udp_profile
                        .as_ref()
                        .map(|profile| profile.not_observed()),
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
                classification: candidate.observation.0.classification,
                responder: Some(candidate.observation.0.responder),
                sent_at,
                received_at: candidate.decoded.frame.timestamp,
                latency: Some(candidate.latency),
                response,
                reason: candidate.observation.0.reason.to_owned(),
                application: candidate.observation.1,
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
            application: outcome.application,
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
            || enforce_deadline(WORKFLOW, deadline),
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
