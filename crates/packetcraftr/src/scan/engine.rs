// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::registry::Registry;
use packetcraftr_netio::link::Mode;

use crate::clock::Clock;
use crate::execution::Errors as _;
use crate::execution::{pause, publisher, rate_delay};
use crate::policy::Authorizer;
use crate::probe::runner::{BatchEvidence, run_batches};
use crate::probe::{Batch, check_collection_evidence, check_probe_count, check_probe_duration};
use crate::providers::{PacketProviders, TargetProviders};
use crate::target::ResolveTarget;
use crate::target::{DeclaredTargets, FamilyGate, SelectedAddress, admit_selection, wire_limits};
use crate::{Client, Sink};

use super::Error;
use super::WORKFLOW;
use super::discovery::{self, Composer};
use super::error::Probes;
use super::evidence::ProbeClassifier;
use super::executor::{ClientExecutor, PipelineEvent, PipelineOptions, Pipelined};
use super::plan::packet::sent_probe_matches;
use super::plan::{Stage, build_batches, probe_count, worst_case_duration};
use super::report::RttAccumulator;
use super::{ClassificationCounts, Event, Probe, Report, Request};
use super::{IPV4_NEIGHBOR_BYTES, IPV4_PROBE_BYTES, IPV6_NEIGHBOR_BYTES, IPV6_PROBE_BYTES};
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
            discovery: Vec::new(),
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
    let options = &request.discovery;
    let mut composer = Composer::new(&approved.targets, options.mode, options.unresponsive);
    let mut stats = crate::Stats::default();
    let mut scan_sequence = 0;
    if options.runs() {
        let mut sendable = vec![true; approved.targets.len()];
        if options.neighbor {
            sendable = discover_neighbors(
                request,
                &approved.targets,
                executor,
                clock,
                deadline,
                &mut composer,
                &mut stats,
            )?;
        }
        // A target whose own link address stayed silent accepts no frame:
        // its IP probes would only fail to materialize, so they are skipped
        // and the host keeps its `no_response` record.
        let probe_targets: Vec<_> = approved
            .targets
            .iter()
            .zip(&sendable)
            .filter(|(_, sendable)| **sendable)
            .map(|(target, _)| target.clone())
            .collect();
        let discovery = StagePlan {
            targets: &probe_targets,
            endpoints: &options.probes,
            stage: Stage::Discovery,
            first_sequence: 0,
        };
        scan_sequence = discovery.probes(request)?;
        let discovered = execute(
            request,
            executor,
            clock,
            deadline,
            &mut evidence,
            &discovery,
        )?;
        add_stats(&mut stats, &discovered, scan_sequence)?;
        for observation in evidence.classifier_mut().discovery.drain(..) {
            if !composer.observe(observation) {
                return Err(Error::IncoherentEvents {
                    message: "a discovery outcome names no selected target".to_owned(),
                });
            }
        }
        if discovered.packets_attempted > 0 && !approved.endpoints.is_empty() {
            pace(request, clock, deadline, 1, &mut stats)?;
        }
    }
    let hosts = composer.finish();
    let scanned: Vec<_> = approved
        .targets
        .iter()
        .zip(&hosts)
        .filter(|(_, host)| host.scan == discovery::Scan::Scanned)
        .map(|(target, _)| target.clone())
        .collect();
    let scan = StagePlan {
        targets: &scanned,
        endpoints: &approved.endpoints,
        stage: Stage::Scan,
        first_sequence: scan_sequence,
    };
    let scan_probes = scan.probes(request)?;
    // Skipped hosts hold no response capacity for this stage, whose own
    // probes are the only outstanding ones left.
    evidence.reserve_responses(
        usize::try_from(scan_probes).unwrap_or(usize::MAX),
        request.collection.capture.snap_length,
    );
    let scanned = execute(request, executor, clock, deadline, &mut evidence, &scan)?;
    add_stats(
        &mut stats,
        &scanned,
        scan_sequence.saturating_add(scan_probes),
    )?;
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
        hosts,
        counts,
        retained_evidence_bytes,
        stats,
        rtt: rtt.finish(),
    })
}

/// Resolves each target's link address in selection order. Each request is
/// paced like a probe, and a silent neighbor is asked again until the
/// request's attempts are spent.
///
/// Returns the targets a frame can still be sent to: a target whose own
/// resolution stayed silent accepts nothing, so later stages skip it.
fn discover_neighbors<E: Pipelined, C: Clock>(
    request: &Request,
    targets: &[SelectedAddress],
    executor: &mut E,
    clock: &mut C,
    deadline: &mut Deadline,
    composer: &mut Composer,
    stats: &mut crate::Stats,
) -> Result<Vec<bool>, Error> {
    let mut sendable = vec![true; targets.len()];
    let mut sent = false;
    for (index, target) in targets.iter().enumerate() {
        let mut attempts = 0;
        let neighbor = loop {
            if sent {
                pace(request, clock, deadline, 1, stats)?;
            }
            enforce_deadline(&Probes, deadline)?;
            let (neighbor, exchange) = executor
                .resolve_neighbor(target, request.timeout, deadline)
                .map_err(|source| Error::Neighbor {
                    address: target.address,
                    source,
                })?;
            // A resolver stopped by the deadline reports silence; the deadline
            // decides instead.
            enforce_deadline(&Probes, deadline)?;
            if neighbor.attempts > 1 {
                return Err(Error::InvalidEvidence {
                    sequence: 0,
                    message: format!(
                        "neighbor discovery of {} sent {} requests in one attempt",
                        target.address, neighbor.attempts
                    ),
                });
            }
            add_stats(stats, &exchange, 0)?;
            sent = neighbor.attempts > 0;
            attempts += neighbor.attempts;
            let silent = matches!(neighbor.outcome, discovery::NeighborOutcome::Silent);
            if !silent || !sent || attempts >= request.attempts {
                break discovery::Neighbor {
                    attempts,
                    ..neighbor
                };
            }
        };
        sendable[index] = !matches!(neighbor.outcome, discovery::NeighborOutcome::Silent);
        composer.neighbor(index, neighbor);
    }
    if sent {
        pace(request, clock, deadline, 1, stats)?;
    }
    Ok(sendable)
}

/// Waits out the request rate for `items` probes already sent, recording
/// the pause in the aggregate statistics like the probe runners do. The
/// delay is reserved against the deadline before the sleep and the deadline
/// is enforced again after, so the operation's boundary stays authoritative.
fn pace<C: Clock>(
    request: &Request,
    clock: &mut C,
    deadline: &mut Deadline,
    items: usize,
    stats: &mut crate::Stats,
) -> Result<(), Error> {
    let delay = rate_delay(
        &Probes,
        "probes_per_second",
        items,
        request.probes_per_second,
    )?;
    if delay.is_zero() {
        return Ok(());
    }
    pause(deadline, clock, delay).map_err(|paused| paused.into_error(&Probes, 0))?;
    add_stats(
        stats,
        &crate::Stats {
            elapsed: delay,
            ..crate::Stats::default()
        },
        0,
    )
}

/// One stage's probes: every endpoint on every target, attempt by attempt,
/// numbered from `first_sequence`.
struct StagePlan<'a> {
    targets: &'a [SelectedAddress],
    endpoints: &'a [ProbeEndpoint],
    stage: Stage,
    first_sequence: u64,
}

impl StagePlan<'_> {
    fn probes(&self, request: &Request) -> Result<u64, Error> {
        probe_count(self.targets.len(), self.endpoints.len(), request.attempts)
            .map(|count| count as u64)
    }

    fn batches<'r>(&self, request: &'r Request) -> impl Iterator<Item = Batch<Probe>> + 'r
    where
        Self: 'r,
    {
        build_batches(
            request,
            self.targets,
            self.endpoints,
            self.stage,
            self.first_sequence,
        )
    }
}

fn execute<E, C, F>(
    request: &Request,
    executor: &mut E,
    clock: &mut C,
    deadline: &mut Deadline,
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Probes>,
    plan: &StagePlan<'_>,
) -> Result<crate::Stats, Error>
where
    E: Pipelined,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    if plan.targets.is_empty() || plan.endpoints.is_empty() {
        Ok(crate::Stats::default())
    } else if request.max_in_flight == 1 {
        run_batches(
            plan.batches(request),
            request.probes_per_second,
            deadline,
            clock,
            executor,
            evidence,
        )
    } else {
        run_pipelined(request, executor, evidence, deadline, plan)
    }
}

fn add_stats(total: &mut crate::Stats, stage: &crate::Stats, sequence: u64) -> Result<(), Error> {
    total
        .checked_add_assign(stage)
        .map_err(|_| Error::StatisticsOverflow { sequence })
}

fn run_pipelined<E, F>(
    request: &Request,
    executor: &mut E,
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Probes>,
    deadline: &Deadline,
    plan: &StagePlan<'_>,
) -> Result<crate::Stats, Error>
where
    E: Pipelined,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    // Checked before any description is built.
    let probes_per_target = plan
        .endpoints
        .len()
        .saturating_mul(request.attempts as usize);
    let batch_bytes = plan.targets.iter().fold(0usize, |bytes, target| {
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
    let batches: Vec<_> = plan.batches(request).collect();
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
    targets: Vec<SelectedAddress>,
    duplicates: Vec<u32>,
    endpoints: Vec<ProbeEndpoint>,
    /// Discovery and scan probes, without neighbor requests.
    total_probes: usize,
}

impl ApprovedScan {
    fn addresses(&self) -> Vec<IpAddr> {
        self.targets.iter().map(|target| target.address).collect()
    }
}

struct ScanPlan {
    total_probes: usize,
    neighbor_requests: usize,
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
        |selected| plan_scan(request, &selected.targets, &endpoints),
        |plan| {
            Ok(wire_limits(
                u64::try_from(plan.total_probes.saturating_add(plan.neighbor_requests))
                    .unwrap_or(u64::MAX),
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

/// Plans discovery and the scan as one budget: their probes, neighbor
/// requests, wire bytes, and worst-case durations must fit the request's
/// limits together, before discovery decides which hosts are scanned.
fn plan_scan(
    request: &Request,
    targets: &[SelectedAddress],
    endpoints: &[ProbeEndpoint],
) -> Result<ScanPlan, Error> {
    let overflow = || Error::InvalidLimit {
        field: "probes",
        value: u64::MAX,
        reason: "probe-count arithmetic overflowed".to_owned(),
    };
    let discovery = &request.discovery;
    let probes = if discovery.runs() {
        discovery.probes.as_slice()
    } else {
        &[]
    };
    let discovery_probes = probe_count(targets.len(), probes.len(), request.attempts)?;
    let explicit_requests = if discovery.runs() && discovery.neighbor {
        probe_count(targets.len(), 1, request.attempts)?
    } else {
        0
    };
    let scan_probes = probe_count(targets.len(), endpoints.len(), request.attempts)?;
    let total_probes = discovery_probes
        .checked_add(scan_probes)
        .ok_or_else(overflow)?;
    // Ordinary probes materialize a link-layer route inside their exchange:
    // a fresh resolution asks for the target's neighbor, or its gateway's,
    // with at most one request each. That work is additive to the discovery
    // stage's own requests, which only ask for the target.
    let implicit_requests = if total_probes > 0 && request.route.link_mode != Mode::Layer3 {
        targets.len()
    } else {
        0
    };
    if implicit_requests > 0 {
        // Those requests capture within the evidence limits, which must hold
        // a decodable reply just as explicit neighbor discovery requires.
        crate::neighbor::Options::default()
            .one_attempt(
                request.timeout,
                request.limits.max_evidence_frames,
                request.limits.max_evidence_bytes,
            )
            .validate()
            .map_err(|source| Error::InvalidLimit {
                field: "max_evidence_bytes",
                value: u64::try_from(request.limits.max_evidence_bytes).unwrap_or(u64::MAX),
                reason: format!("cannot hold an implicit neighbor resolution: {source}"),
            })?;
    }
    let neighbor_requests = explicit_requests
        .checked_add(implicit_requests)
        .ok_or_else(overflow)?;
    check_probe_count(
        &Probes,
        total_probes
            .checked_add(neighbor_requests)
            .ok_or_else(overflow)?,
        request.limits.max_probes,
    )?;
    let neighbor_frames = targets.iter().try_fold(0u64, |total, target| {
        let frame = if target.address.is_ipv4() {
            IPV4_NEIGHBOR_BYTES
        } else {
            IPV6_NEIGHBOR_BYTES
        };
        total.checked_add(frame)
    });
    // One target's neighbor bytes cover `attempts` discovery requests plus
    // at most one implicit request from its probes' materialization.
    let neighbor_bytes = neighbor_frames
        .and_then(|per_target| {
            let explicit = if explicit_requests == 0 {
                Some(0)
            } else {
                per_target.checked_mul(u64::from(request.attempts))
            }?;
            explicit.checked_add(if implicit_requests == 0 {
                0
            } else {
                per_target
            })
        })
        .ok_or_else(overflow)?;
    let maximum_bytes = maximum_wire_bytes(targets, probes, request)?
        .checked_add(maximum_wire_bytes(targets, endpoints, request)?)
        .and_then(|bytes| bytes.checked_add(neighbor_bytes))
        .ok_or_else(overflow)?;
    let too_long = || Error::DurationLimit {
        actual: Duration::MAX,
        limit: request.limits.max_duration,
    };
    let pause = rate_delay(&Probes, "probes_per_second", 1, request.probes_per_second)?;
    // Discovery requests pace between targets; an implicit resolution waits
    // only the attempt timeout inside the probe's own exchange.
    let neighbor_duration = u32::try_from(explicit_requests)
        .ok()
        .and_then(|requests| request.timeout.checked_add(pause)?.checked_mul(requests))
        .and_then(|explicit| {
            u32::try_from(implicit_requests)
                .ok()
                .and_then(|requests| request.timeout.checked_mul(requests))
                .and_then(|implicit| implicit.checked_add(explicit))
        })
        .ok_or_else(too_long)?;
    let stage_pause = if discovery_probes > 0 && scan_probes > 0 {
        pause
    } else {
        Duration::ZERO
    };
    let worst_case = [
        worst_case_duration(request, discovery_probes)?,
        neighbor_duration,
        stage_pause,
        worst_case_duration(request, scan_probes)?,
    ]
    .into_iter()
    .try_fold(Duration::ZERO, Duration::checked_add)
    .ok_or_else(too_long)?;
    check_probe_duration(&Probes, worst_case, request.limits.max_duration)?;
    Ok(ScanPlan {
        total_probes,
        neighbor_requests,
        maximum_bytes,
        worst_case,
    })
}

fn maximum_wire_bytes(
    targets: &[SelectedAddress],
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
