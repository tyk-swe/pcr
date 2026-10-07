// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::registry::Registry;

use crate::clock::Clock;
use crate::execution::Errors as _;
use crate::execution::publisher;
use crate::policy::Authorizer;
use crate::probe::runner::{BatchEvidence, run_batches};
use crate::probe::{Batch, check_collection_evidence, check_probe_count, check_probe_duration};
use crate::providers::{PacketProviders, TargetProviders};
use crate::target::ResolveTarget;
use crate::target::{DeclaredTargets, FamilyGate, admit_selection, wire_limits};
use crate::{Client, Sink};

use super::Error;
use super::WORKFLOW;
use super::error::Probes;
use super::evidence::ProbeClassifier;
use super::executor::{ClientExecutor, PipelineEvent, PipelineOptions, Pipelined};
use super::plan::packet::sent_probe_matches;
use super::plan::{build_batches, probe_count, worst_case_duration};
use super::report::RttAccumulator;
use super::{ClassificationCounts, Event, Probe, Report, Request};
use super::{IPV4_PROBE_BYTES, IPV6_PROBE_BYTES};
use crate::probe::{ProbeEndpoint, enforce_deadline};

impl<P: PacketProviders + TargetProviders, K: Clock> Client<P, K> {
    /// Scans the request's authorized targets and publishes each probe's
    /// final outcome, each retained undecoded frame, and each diagnostic to
    /// `sink`. When `max_in_flight` exceeds one, each probe's confirmed send
    /// is also published as [`Event::Sent`] before its outcome.
    pub fn scan<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let publish = publisher(
            &self.runtime,
            sink,
            |error| Probes.duration_limit(0, error),
            |source| Error::Output { source },
        )?;
        run(
            &request,
            &mut self.admission(),
            &self.registry,
            &mut ClientExecutor::new(self, &request),
            &mut self.clock.clone(),
            &mut self.deadline(request.limits.max_duration),
            publish,
        )
    }
}

pub(crate) fn run<A, E, C, F>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    deadline: &mut Deadline,
    emit: F,
) -> Result<Report, Error>
where
    A: Authorizer + ResolveTarget,
    E: Pipelined,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    enforce_deadline(&Probes, deadline)?;
    let approved = approve_scan(request, authorizer, deadline)?;
    let batches = build_batches(request, &approved.targets, &approved.endpoints);
    enforce_deadline(&Probes, deadline)?;
    let mut evidence = BatchEvidence::new(
        WORKFLOW,
        Probes,
        request.limits.evidence(),
        ProbeClassifier {
            registry,
            target: Arc::from(approved.declared_target.as_str()),
            winners: HashMap::new(),
            rtt: RttAccumulator::default(),
        },
        emit,
    );
    evidence.reserve_responses(
        approved.total_probes,
        request.collection.capture.snap_length,
    );
    for duplicate in &approved.duplicates {
        evidence.emit(
            Event::Diagnostic(request.duplicate_diagnostic(*duplicate)),
            deadline,
        )?;
    }
    let stats = if request.max_in_flight == 1 {
        run_batches(
            batches,
            request.probes_per_second,
            deadline,
            clock,
            executor,
            &mut evidence,
        )
    } else {
        run_pipelined(
            request,
            executor,
            &mut evidence,
            deadline,
            batches,
            &approved,
        )
    };
    let stats = stats?;
    let retained_evidence_bytes = evidence.retained_evidence_bytes();
    let ProbeClassifier { winners, rtt, .. } = evidence.into_classifier();
    let mut counts = ClassificationCounts::default();
    for classification in winners.into_values() {
        counts.increment(classification);
    }

    let resolved_addresses = approved.addresses();
    Ok(Report {
        planned_duration: approved.planned_duration,
        target: approved.declared_target,
        resolved_addresses,
        counts,
        retained_evidence_bytes,
        stats,
        rtt: rtt.finish(),
    })
}

fn run_pipelined<E, F, B>(
    request: &Request,
    executor: &mut E,
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Probes>,
    deadline: &Deadline,
    batches: B,
    approved: &ApprovedScan,
) -> Result<crate::Stats, Error>
where
    E: Pipelined,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
    B: Iterator<Item = Batch<Probe>>,
{
    let probes_per_target = approved.total_probes / approved.targets.len();
    let batch_bytes = approved.targets.iter().fold(0usize, |bytes, target| {
        let scope_bytes = target.scope.as_ref().map_or(0, |scope| {
            scope
                .zone
                .as_str()
                .len()
                .saturating_add(scope.interface.name.len())
        });
        bytes.saturating_add(
            (std::mem::size_of::<Batch<Probe>>() + std::mem::size_of::<Probe>())
                .saturating_add(scope_bytes)
                .saturating_mul(probes_per_target),
        )
    });
    if batch_bytes > request.limits.max_prepared_bytes {
        return Err(Error::PipelineExecution {
            source: super::executor::limit(
                "prepared descriptions",
                request.limits.max_prepared_bytes,
            ),
        });
    }
    let batches: Vec<_> = batches.collect();
    let mut completed = vec![false; batches.len()];
    let mut confirmed = vec![false; batches.len()];
    let mut sent_bytes = 0u64;
    let remaining = deadline
        .remaining()
        .map_err(|error| Probes.duration_limit(0, error))?;
    let settings = PipelineOptions {
        max_in_flight: request.max_in_flight,
        probes_per_second: request.probes_per_second,
        max_duration: remaining,
        max_prepared_bytes: request.limits.max_prepared_bytes,
        max_evidence_frames: request.limits.max_evidence_frames,
        max_evidence_bytes: request.limits.max_evidence_bytes,
    };
    let result = executor.execute_pipeline(&batches, settings, &mut |event| {
        let invalid = |index| {
            packetcraftr_core::error::BoundaryError::from_error(Error::InvalidEvidence {
                sequence: index as u64,
                message: "pipeline returned an invalid or repeated request index".to_owned(),
            })
        };
        match event {
            PipelineEvent::Sent { index, sent } => {
                let batch = batches.get(index).ok_or_else(|| invalid(index))?;
                let probe = batch.probe()?;
                if confirmed[index] || !sent_probe_matches(probe, &sent.built().packet) {
                    return Err(invalid(index));
                }
                confirmed[index] = true;
                sent_bytes = sent_bytes
                    .checked_add(sent.bytes_sent() as u64)
                    .ok_or_else(|| invalid(index))?;
                evidence
                    .emit(
                        Event::Sent(super::SentProbe {
                            probe: probe.clone(),
                            sent,
                        }),
                        deadline,
                    )
                    .map_err(packetcraftr_core::error::BoundaryError::from_error)?;
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
                    .map_err(packetcraftr_core::error::BoundaryError::from_error)?;
                completed[index] = true;
            }
            PipelineEvent::Undecoded { frame } => evidence
                .retain_undecoded(&[], vec![frame], deadline)
                .map_err(packetcraftr_core::error::BoundaryError::from_error)?,
            PipelineEvent::Unattributed {
                frame,
                attribution,
                sequence,
            } => evidence
                .retain_unattributed(
                    &frame,
                    |frame| {
                        Event::Unattributed(super::Unattributed {
                            attribution,
                            sequence,
                            frame,
                        })
                    },
                    deadline,
                )
                .map_err(packetcraftr_core::error::BoundaryError::from_error)?,
            PipelineEvent::Diagnostic(diagnostic) => evidence
                .record_diagnostics(vec![diagnostic], deadline)
                .map_err(packetcraftr_core::error::BoundaryError::from_error)?,
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
                return Err(Error::InvalidEvidence {
                    sequence: 0,
                    message:
                        "pipeline completion statistics disagree with validated sends/outcomes"
                            .to_owned(),
                });
            }
            enforce_deadline(&Probes, deadline)?;
            Ok(stats)
        }
        Err(source) => Err(Error::PipelineExecution { source }),
    }
}

struct ApprovedScan {
    planned_duration: std::time::Duration,
    declared_target: String,
    targets: Vec<crate::target::SelectedAddress>,
    duplicates: Vec<u32>,
    endpoints: Vec<ProbeEndpoint>,
    total_probes: usize,
}

impl ApprovedScan {
    fn addresses(&self) -> Vec<IpAddr> {
        self.targets.iter().map(|target| target.address).collect()
    }
}

struct ScanPlan {
    total_probes: usize,
    maximum_bytes: u64,
    worst_case: Duration,
}

fn approve_scan<A: Authorizer + ResolveTarget>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
) -> Result<ApprovedScan, Error> {
    let endpoints = request.planned_endpoints()?.to_vec();
    // Only the serial path reuses `collection` to retain each exchange's frames.
    if request.max_in_flight == 1 {
        check_collection_evidence(&Probes, &request.collection, request.limits.evidence())?;
    }
    // Implementations must authorize the declared target before DNS and every
    // answer before anything below constructs a probe; `admit_selection` owns
    // that ordering.
    let (selected, plan) = admit_selection(
        authorizer,
        deadline,
        &Probes,
        DeclaredTargets {
            selection: &request.targets,
            family: FamilyGate::new(request.address_family, Error::family),
            max_targets: request.limits.max_targets,
        },
        Error::TargetSelection,
        |selected| {
            let total_probes =
                probe_count(selected.targets.len(), endpoints.len(), request.attempts)?;
            check_probe_count(&Probes, total_probes, request.limits.max_probes)?;
            let maximum_bytes = maximum_wire_bytes(&selected.targets, &endpoints, request)?;
            let worst_case = worst_case_duration(request, total_probes)?;
            check_probe_duration(&Probes, worst_case, request.limits.max_duration)?;
            Ok(ScanPlan {
                total_probes,
                maximum_bytes,
                worst_case,
            })
        },
        |plan| {
            Ok(wire_limits(
                u64::try_from(plan.total_probes).unwrap_or(u64::MAX),
                plan.maximum_bytes,
            ))
        },
    )?;
    if request.route.interface.is_some()
        && selected.targets.iter().any(|target| target.scope.is_some())
    {
        return Err(Error::InvalidLimit {
            field: "interface",
            value: 0,
            reason: "scoped targets cannot combine with an explicit --interface".to_owned(),
        });
    }

    Ok(ApprovedScan {
        planned_duration: plan.worst_case,
        declared_target: selected.declared,
        targets: selected.targets,
        duplicates: selected.duplicates,
        endpoints,
        total_probes: plan.total_probes,
    })
}

fn maximum_wire_bytes(
    targets: &[crate::target::SelectedAddress],
    endpoints: &[ProbeEndpoint],
    request: &Request,
) -> Result<u64, Error> {
    let overflow = || Error::InvalidLimit {
        field: "wire_bytes",
        value: u64::MAX,
        reason: "scan payload accounting overflowed".to_owned(),
    };
    let payload = endpoints
        .iter()
        .filter_map(|endpoint| match endpoint {
            ProbeEndpoint::Udp { port } => Some(port),
            ProbeEndpoint::Tcp { .. } | ProbeEndpoint::Icmp => None,
        })
        .try_fold(0u64, |total, port| {
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
        })?;
    let endpoints = endpoints.len() as u64;
    targets.iter().try_fold(0u64, |total, target| {
        let header = if target.address.is_ipv4() {
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
