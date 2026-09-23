// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::progress::Runtime;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{diagnostic::Diagnostic, registry::Registry};

use crate::BoundaryError;
use crate::clock::Clock;
use crate::policy::Authorizer;
use crate::probe::limits::{check_probe_count, check_probe_duration};
use crate::probe::runner::{BatchEvidence, run_batches, sink_observer};
use crate::target::{DeclaredTargets, GateErrors, admit_selection, budgeted};

use super::WORKFLOW;
use super::evidence::ProbeClassifier;
use super::plan::{build_batches, worst_case_duration};
use super::probe::sent_probe_matches;
use super::report::RttAccumulator;
use super::{
    Batch, Classification, ClassificationCounts, Endpoint, Event, ProbeEvidence, Report, Request,
    Summary,
};
use super::{IPV4_PROBE_BYTES, IPV6_PROBE_BYTES};
use crate::probe::{
    Error, ErrorKind, Executor, ProbeEndpoint, Transport, enforce_deadline, index_or_push,
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
        |error| WORKFLOW.duration_limit(error.actual, error.limit),
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
    emit: F,
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
    let mut evidence = BatchEvidence::new(
        WORKFLOW,
        request.limits.evidence(),
        ProbeClassifier {
            registry,
            target: Arc::from(approved.declared_target.as_str()),
            winners: HashMap::new(),
            rtt: RttAccumulator::default(),
        },
        emit,
    );
    let stats = if request.max_in_flight == 1 {
        run_batches(
            batches,
            request.probes_per_second,
            &mut deadline,
            clock,
            executor,
            &mut evidence,
        )
    } else {
        run_pipelined(
            request,
            executor,
            &mut evidence,
            &deadline,
            batches,
            &approved,
        )
    };
    let stats = stats?;
    let ProbeClassifier { winners, rtt, .. } = evidence.into_classifier();
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
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F>,
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
        .map_err(|error| WORKFLOW.duration_limit(error.actual, error.limit))?;
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
                if confirmed[index] || !sent_probe_matches(batch.probe(), &sent.built().packet) {
                    return Err(invalid(index));
                }
                confirmed[index] = true;
                sent_bytes = sent_bytes
                    .checked_add(sent.bytes_sent() as u64)
                    .ok_or_else(|| invalid(index))?;
                evidence
                    .emit(
                        Event::Sent(super::SentProbe {
                            probe: batch.probe().clone(),
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
                // Scan probe events never end the operation early.
                let _ = evidence
                    .validate(batch, &execution)
                    .and_then(|()| evidence.process(batch, execution, deadline))
                    .map_err(crate::BoundaryError::from_error)?;
                completed[index] = true;
            }
            PipelineEvent::Undecoded { frame } => evidence
                .retain_undecoded(&[], vec![frame], deadline)
                .map_err(crate::BoundaryError::from_error)?,
            PipelineEvent::Diagnostic(diagnostic) => evidence
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
