// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::registry::Registry;
use packetcraftr_netio::link::Mode;

use crate::clock::Clock;
use crate::deadline::DeadlineExt as _;
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
use super::plan::{
    Stage, adaptive_worst_case_duration, build_batches, probe_count, worst_case_duration,
};
use super::report::RttAccumulator;
use super::{ClassificationCounts, Event, Probe, Report, Request};
use super::{IPV4_PROBE_BYTES, IPV6_PROBE_BYTES};
use crate::neighbor::{IPV4_REQUEST_BYTES, IPV6_REQUEST_BYTES};
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
    mut emit: F,
) -> Result<Report, Error>
where
    A: Authorizer + ResolveTarget,
    E: Pipelined,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    enforce_deadline(&Probes, deadline)?;
    let approved = approve_scan(request, authorizer, deadline)?;
    let options = &request.discovery;
    executor.resolves_neighbors(approved.resolves_neighbors);
    enforce_deadline(&Probes, deadline)?;
    let mut controller = request.adaptive.map(|config| {
        super::adaptive::Controller::new(config, request.timeout, request.max_in_flight)
    });
    let mut reservation = 0usize;
    if controller.is_some() {
        reservation = adaptive_reservation(
            request,
            &approved.targets,
            options.probes.len().max(approved.endpoints.len()),
        );
        admit_adaptive(request, executor, deadline, &approved, reservation)?;
        if let Some(controller) = controller.as_mut() {
            for target in &approved.targets {
                controller.host_index(target);
            }
        }
    } else if request.max_in_flight > 1 {
        // Each stage is admitted for every target before any neighbor request
        // or probe, though discovery may leave the scan fewer.
        let mut first_sequence = 0;
        if request.discovery.runs() {
            let discovery = StagePlan {
                targets: &approved.targets,
                endpoints: &request.discovery.probes,
                stage: Stage::Discovery,
                first_sequence,
            };
            admit_pipelined(request, executor, deadline, &discovery)?;
            first_sequence = discovery.probes(request)?;
        }
        let scan = StagePlan {
            targets: &approved.targets,
            endpoints: &approved.endpoints,
            stage: Stage::Scan,
            first_sequence,
        };
        admit_pipelined(request, executor, deadline, &scan)?;
    }
    let mut retries_started = 0usize;
    let mut emit = |event: Event, deadline: &Deadline| {
        if let Event::Probe { probe, .. } = &event
            && probe.attempt > 1
        {
            retries_started = retries_started.saturating_add(1);
        }
        emit(event, deadline)
    };
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
            feedback: controller
                .as_ref()
                .map(|_| (Vec::new(), request.max_in_flight)),
            adaptive_attempts: controller.as_ref().map(|_| request.attempts),
        },
        &mut emit,
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
    let mut composer = Composer::new(&approved.targets, options.mode, options.unresponsive);
    let mut stats = crate::Stats::default();
    let mut peak = 0usize;
    // Transmissions whose rate pause is still owed, waited out just before
    // the next one so the operation's last transmission leaves no pause.
    let mut owed = Owed::default();
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
                &mut owed,
                controller.as_mut(),
            )?;
        }
        if !options.probes.is_empty() {
            for (index, target) in approved.targets.iter().enumerate() {
                if !sendable[index] {
                    continue;
                }
                match reach_next_hop(
                    request,
                    executor,
                    clock,
                    deadline,
                    target,
                    &mut stats,
                    &mut owed,
                    0,
                    controller.as_mut(),
                )? {
                    ReachOutcome::Resolved => {}
                    ReachOutcome::Silent(_) => {
                        sendable[index] = false;
                        composer.unreachable(index);
                    }
                    ReachOutcome::HostExpired => sendable[index] = false,
                }
            }
        }
        // A target whose own link address, or next hop, stayed silent accepts
        // no frame: its IP probes would only fail to materialize, so they are
        // skipped and the host keeps its `no_response` record.
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
        let discovery_probes = discovery.probes(request)?;
        scan_sequence = if controller.is_some() {
            probe_count(
                approved.targets.len(),
                options.probes.len(),
                request.attempts,
            )? as u64
        } else {
            discovery_probes
        };
        // Probes skipped after a silent neighbor or next hop hold no
        // response capacity; only the remaining targets' probes are
        // outstanding.
        let scan_probes = probe_count(
            probe_targets.len(),
            approved.endpoints.len(),
            request.attempts,
        )?;
        evidence.reserve_responses(
            usize::try_from(discovery_probes)
                .unwrap_or(usize::MAX)
                .saturating_add(scan_probes),
            request.collection.capture.snap_length,
        );
        if !probe_targets.is_empty() && !options.probes.is_empty() {
            settle(request, clock, deadline, &mut owed, &mut stats)?;
        }
        let discovered = match controller.as_mut() {
            Some(controller) => execute_adaptive(
                request,
                executor,
                clock,
                deadline,
                &mut evidence,
                controller,
                Stage::Discovery,
                &probe_targets,
                &options.probes,
                0,
                &mut owed,
                reservation,
            )?,
            None => execute(
                request,
                executor,
                clock,
                deadline,
                &mut evidence,
                &discovery,
                &stats,
                &mut peak,
            )?,
        };
        add_stats(&mut stats, &discovered, scan_sequence)?;
        for observation in evidence.classifier_mut().discovery.drain(..) {
            if !composer.observe(observation) {
                return Err(Error::IncoherentEvents {
                    message: "a discovery outcome names no selected target".to_owned(),
                });
            }
        }
        if discovered.packets_attempted > 0 {
            // When the stage's last probe left is not known on the operation's
            // clock, so its whole pause stays owed.
            owed.owe(1, None);
        }
    }
    if let Some(controller) = &controller {
        for (index, target) in approved.targets.iter().enumerate() {
            if controller
                .find(target)
                .is_some_and(|host| controller.is_incomplete(host))
            {
                composer.incomplete(index);
            }
        }
    }
    let mut hosts = composer.finish();
    let scanned: Vec<_> = approved
        .targets
        .iter()
        .zip(&hosts)
        .filter(|(_, host)| host.scan == discovery::Scan::Scanned)
        .map(|(target, _)| target.clone())
        .collect();
    if !approved.endpoints.is_empty() {
        for target in &scanned {
            // Discovery answers for a target it reached; without it, a
            // scan target no frame can reach fails the scan.
            match reach_next_hop(
                request,
                executor,
                clock,
                deadline,
                target,
                &mut stats,
                &mut owed,
                scan_sequence,
                controller.as_mut(),
            )? {
                ReachOutcome::Resolved | ReachOutcome::HostExpired => {}
                ReachOutcome::Silent(source) => {
                    return Err(Error::Neighbor {
                        address: target.address,
                        source,
                    });
                }
            }
        }
    }
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
    if !scanned.is_empty() && !approved.endpoints.is_empty() {
        settle(request, clock, deadline, &mut owed, &mut stats)?;
    }
    let scanned = match controller.as_mut() {
        Some(controller) => execute_adaptive(
            request,
            executor,
            clock,
            deadline,
            &mut evidence,
            controller,
            Stage::Scan,
            &scanned,
            &approved.endpoints,
            scan_sequence,
            &mut owed,
            reservation,
        )?,
        None => execute(
            request,
            executor,
            clock,
            deadline,
            &mut evidence,
            &scan,
            &stats,
            &mut peak,
        )?,
    };
    add_stats(
        &mut stats,
        &scanned,
        scan_sequence.saturating_add(scan_probes),
    )?;
    if let Some(controller) = &controller {
        for (index, target) in approved.targets.iter().enumerate() {
            if controller
                .find(target)
                .is_some_and(|host| controller.is_incomplete(host))
            {
                hosts[index].scan = discovery::Scan::Incomplete;
            }
        }
    }
    let retained_evidence_bytes = evidence.retained_evidence_bytes();
    let ProbeClassifier { winners, rtt, .. } = evidence.into_classifier();
    let mut counts = ClassificationCounts::default();
    for classification in winners.into_values() {
        counts.increment(classification);
    }

    let resolved_addresses = approved.addresses();
    let scheduling = match controller {
        Some(controller) => controller.finish((None, None)),
        None => super::adaptive::fixed_scheduling((None, None), peak, retries_started),
    };
    Ok(Report {
        planned_duration: approved.planned_duration,
        target: approved.declared_target,
        resolved_addresses,
        hosts,
        counts,
        retained_evidence_bytes,
        stats,
        rtt: rtt.finish(),
        scheduling,
    })
}

/// Resolves each target's link address in selection order. Each request is
/// paced like a probe, and a silent neighbor is asked again until the
/// request's attempts are spent.
///
/// Returns the targets a frame can still be sent to: a target whose own
/// resolution stayed silent accepts nothing, so later stages skip it.
#[allow(clippy::too_many_arguments)]
fn discover_neighbors<E: Pipelined, C: Clock>(
    request: &Request,
    targets: &[SelectedAddress],
    executor: &mut E,
    clock: &mut C,
    deadline: &mut Deadline,
    composer: &mut Composer,
    stats: &mut crate::Stats,
    owed: &mut Owed,
    controller: Option<&mut super::adaptive::Controller>,
) -> Result<Vec<bool>, Error> {
    let mut sendable = vec![true; targets.len()];
    let mut controller = controller;
    for (index, target) in targets.iter().enumerate() {
        let host = controller.as_deref_mut().map(|c| c.host_index(target));
        if let (Some(c), Some(h)) = (&mut controller, host) {
            c.host_started(h, clock.now());
            if c.host_expired(h, clock.now()) {
                c.mark_incomplete(h);
                sendable[index] = false;
                continue;
            }
        }
        let mut attempts = 0;
        let mut last: Option<discovery::Neighbor> = None;
        let neighbor = loop {
            if let (Some(c), Some(h)) = (&mut controller, host)
                && c.host_expired(h, clock.now())
            {
                c.mark_incomplete(h);
                break last;
            }
            // A pause owed by an earlier request is waited out only before
            // another; a target answered without one leaves it owed.
            if requests_neighbor(executor, target, true, deadline)? {
                settle(request, clock, deadline, owed, stats)?;
            }
            enforce_deadline(&Probes, deadline)?;
            if let (Some(c), Some(h)) = (&mut controller, host)
                && c.host_expired(h, clock.now())
            {
                c.mark_incomplete(h);
                break last;
            }
            let timeout = host.map_or(request.timeout, |h| {
                controller.as_deref().map_or(request.timeout, |c| {
                    request.timeout.min(c.host_remaining(h, clock.now()))
                })
            });
            let began = clock.now();
            let (neighbor, exchange) = match executor.resolve_neighbor(target, timeout, deadline) {
                Ok(resolved) => resolved,
                Err(source) => {
                    if let (Some(c), Some(h)) = (&mut controller, host)
                        && c.host_expired(h, clock.now())
                    {
                        c.mark_incomplete(h);
                        break last;
                    }
                    return Err(Error::Neighbor {
                        address: target.address,
                        source,
                    });
                }
            };
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
            let sent = neighbor.attempts > 0;
            owed.owe(usize::from(sent), Some(began));
            attempts += neighbor.attempts;
            let silent = matches!(neighbor.outcome, discovery::NeighborOutcome::Silent);
            if silent
                && let (Some(c), Some(h)) = (&mut controller, host)
                && c.host_expired(h, clock.now())
            {
                c.mark_incomplete(h);
                break last;
            }
            let neighbor = discovery::Neighbor {
                attempts,
                ..neighbor
            };
            if !silent || !sent || attempts >= request.attempts {
                break Some(neighbor);
            }
            last = Some(neighbor);
        };
        match neighbor {
            Some(neighbor) => {
                sendable[index] = !matches!(neighbor.outcome, discovery::NeighborOutcome::Silent);
                composer.neighbor(index, neighbor);
            }
            None => sendable[index] = false,
        }
    }
    Ok(sendable)
}

/// Transmissions whose rate pause is still owed, and when the last of them
/// began, if that is known.
#[derive(Debug, Default)]
struct Owed {
    transmissions: usize,
    since: Option<Instant>,
}

impl Owed {
    /// Owes the pause of `transmissions` more, the last of which began at
    /// `began`. Several at once leave their last start unknown.
    fn owe(&mut self, transmissions: usize, began: Option<Instant>) {
        if transmissions == 0 {
            return;
        }
        self.transmissions = self.transmissions.saturating_add(transmissions);
        self.since = began.filter(|_| transmissions == 1);
    }
}

/// Waits out the rate for the `owed` transmissions sent since the last
/// wait, just before the next one is sent. Time already spent since the last
/// of them began, such as its wait for a reply, counts toward the pause.
fn settle<C: Clock>(
    request: &Request,
    clock: &mut C,
    deadline: &mut Deadline,
    owed: &mut Owed,
    stats: &mut crate::Stats,
) -> Result<(), Error> {
    let Owed {
        transmissions,
        since,
    } = std::mem::take(owed);
    if transmissions == 0 {
        return Ok(());
    }
    let spent = since.map_or(Duration::ZERO, |since| {
        clock.now().saturating_duration_since(since)
    });
    pace(request, clock, deadline, transmissions, spent, stats)
}

/// Waits out the request rate for `items` probes already sent, less the
/// `spent` time since the last began, recording
/// the pause in the aggregate statistics like the probe runners do. The
/// delay is reserved against the deadline before the sleep and the deadline
/// is enforced again after, so the operation's boundary stays authoritative.
fn pace<C: Clock>(
    request: &Request,
    clock: &mut C,
    deadline: &mut Deadline,
    items: usize,
    spent: Duration,
    stats: &mut crate::Stats,
) -> Result<(), Error> {
    let delay = rate_delay(
        &Probes,
        "probes_per_second",
        items,
        request.probes_per_second,
    )?
    .saturating_sub(spent);
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

#[allow(clippy::too_many_arguments)]
fn execute<E, C, F>(
    request: &Request,
    executor: &mut E,
    clock: &mut C,
    deadline: &mut Deadline,
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Probes>,
    plan: &StagePlan<'_>,
    preceding: &crate::Stats,
    peak: &mut usize,
) -> Result<crate::Stats, Error>
where
    E: Pipelined,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    if plan.targets.is_empty() || plan.endpoints.is_empty() {
        return Ok(crate::Stats::default());
    }
    enforce_deadline(&Probes, deadline)?;
    if request.max_in_flight == 1 {
        let probes = run_batches(
            plan.batches(request),
            request.probes_per_second,
            deadline,
            clock,
            executor,
            evidence,
        )?;
        *peak = (*peak).max(usize::from(probes.packets_attempted > 0));
        Ok(probes)
    } else {
        // A pipeline's failure reports the operation's traffic before it too.
        let (probes, wave_peak) = run_pipelined(
            request,
            executor,
            clock,
            evidence,
            deadline,
            plan,
            preceding.clone(),
        )?;
        *peak = (*peak).max(wave_peak);
        Ok(probes)
    }
}

/// Whether resolving `target`'s neighbor would send a request.
fn requests_neighbor<E: Pipelined>(
    executor: &mut E,
    target: &SelectedAddress,
    explicit: bool,
    deadline: &Deadline,
) -> Result<bool, Error> {
    executor
        .requests_neighbor(target, explicit, deadline)
        .map_err(|source| Error::Neighbor {
            address: target.address,
            source,
        })
}

enum ReachOutcome {
    Resolved,
    Silent(BoundaryError),
    HostExpired,
}

/// Resolves `target`'s next hop before its stage arms any capture, so no
/// resolution's capture overlaps a probe's and each request joins `stats`.
/// Returns why the target is unreachable when its next hop stayed silent.
#[allow(clippy::too_many_arguments)]
fn reach_next_hop<E: Pipelined, C: Clock>(
    request: &Request,
    executor: &mut E,
    clock: &mut C,
    deadline: &mut Deadline,
    target: &SelectedAddress,
    stats: &mut crate::Stats,
    owed: &mut Owed,
    sequence: u64,
    mut controller: Option<&mut super::adaptive::Controller>,
) -> Result<ReachOutcome, Error> {
    let host = controller.as_deref_mut().map(|c| c.host_index(target));
    if let (Some(c), Some(h)) = (&mut controller, host) {
        c.host_started(h, clock.now());
        if c.host_expired(h, clock.now()) {
            c.mark_incomplete(h);
            return Ok(ReachOutcome::HostExpired);
        }
    }
    let needs_request = match (&controller, host) {
        (Some(c), Some(h)) => {
            let scoped = deadline
                .for_wait(c.host_remaining(h, clock.now()))
                .map_err(Error::from)?;
            requests_neighbor(executor, target, false, &scoped)?
        }
        _ => requests_neighbor(executor, target, false, deadline)?,
    };
    if needs_request {
        settle(request, clock, deadline, owed, stats)?;
    }
    enforce_deadline(&Probes, deadline)?;
    if let (Some(c), Some(h)) = (&mut controller, host)
        && c.host_expired(h, clock.now())
    {
        c.mark_incomplete(h);
        return Ok(ReachOutcome::HostExpired);
    }
    let began = clock.now();
    let scoped;
    let effective: &Deadline = match (&controller, host) {
        (Some(c), Some(h)) => {
            scoped = deadline
                .for_wait(c.host_remaining(h, clock.now()))
                .map_err(Error::from)?;
            &scoped
        }
        _ => deadline,
    };
    let resolved = match executor.resolve_next_hop(target, effective) {
        Ok(resolved) => resolved,
        Err(source) => {
            if let (Some(c), Some(h)) = (&mut controller, host)
                && c.host_expired(h, clock.now())
            {
                c.mark_incomplete(h);
                return Ok(ReachOutcome::HostExpired);
            }
            return Err(Error::Neighbor {
                address: target.address,
                source,
            });
        }
    };
    // A resolver stopped by the deadline reports silence; the deadline
    // decides instead.
    enforce_deadline(&Probes, deadline)?;
    add_stats(stats, &resolved.stats, sequence)?;
    // A request spends the rate like a probe, so it is spaced from the next
    // request or the stage's first probe.
    let requests = usize::try_from(resolved.stats.packets_attempted).unwrap_or(usize::MAX);
    owed.owe(requests, Some(began));
    Ok(match resolved.silence {
        Some(source) => {
            if let (Some(c), Some(h)) = (&mut controller, host)
                && c.host_expired(h, clock.now())
            {
                c.mark_incomplete(h);
                return Ok(ReachOutcome::HostExpired);
            }
            ReachOutcome::Silent(source)
        }
        None => ReachOutcome::Resolved,
    })
}

fn add_stats(total: &mut crate::Stats, stage: &crate::Stats, sequence: u64) -> Result<(), Error> {
    total
        .checked_add_assign(stage)
        .map_err(|_| Error::StatisticsOverflow { sequence })
}

/// Rejects a pipelined stage over its preparation limit without sending
/// anything: first by its batch descriptions, before they are built, then
/// by the pipeline's own admission of its probes.
fn admit_pipelined<E: Pipelined>(
    request: &Request,
    executor: &mut E,
    deadline: &Deadline,
    plan: &StagePlan<'_>,
) -> Result<(), Error> {
    if plan.targets.is_empty() || plan.endpoints.is_empty() {
        return Ok(());
    }
    check_prepared_descriptions(request, plan.targets, plan.endpoints)?;
    let batches: Vec<_> = plan.batches(request).collect();
    executor
        .admit_pipeline(
            &batches,
            &pipeline_options(request, deadline, crate::Stats::default(), 0)?,
        )
        .map_err(|source| Error::PipelineExecution { source })
}

pub(super) fn adaptive_batches<'r>(
    request: &'r Request,
    targets: &'r [SelectedAddress],
    endpoints: &'r [ProbeEndpoint],
    stage: Stage,
    first_sequence: u64,
) -> impl Iterator<Item = Batch<Probe>> + 'r {
    let host_count = targets.len() as u64;
    let endpoint_count = endpoints.len() as u64;
    (1..=request.attempts)
        .flat_map(move |attempt| {
            endpoints
                .iter()
                .enumerate()
                .flat_map(move |(endpoint_index, endpoint)| {
                    targets.iter().enumerate().map(move |(host_index, target)| {
                        (host_index, endpoint_index, attempt, target, *endpoint)
                    })
                })
        })
        .map(
            move |(host_index, endpoint_index, attempt, target, endpoint)| {
                let sequence = first_sequence.saturating_add(
                    ((u64::from(attempt) - 1)
                        .saturating_mul(endpoint_count)
                        .saturating_add(endpoint_index as u64))
                    .saturating_mul(host_count)
                    .saturating_add(host_index as u64),
                );
                Batch::single(
                    super::plan::planned_probe(request, sequence, stage, target, endpoint, attempt),
                    request.timeout,
                )
            },
        )
}

pub(crate) fn adaptive_reservation(
    request: &Request,
    targets: &[SelectedAddress],
    endpoints_per_host: usize,
) -> usize {
    let mut shared = request.udp_payload.len();
    let mut profiles = std::collections::HashSet::new();
    for profile in request.udp_profiles.values() {
        if profiles.insert(std::sync::Arc::as_ptr(profile)) {
            shared = shared.saturating_add(profile.storage_bytes());
        }
    }
    super::adaptive::state_charge(
        targets.len(),
        endpoints_per_host,
        request.max_in_flight,
        super::adaptive::scoped_bytes(targets),
        shared,
    )
}

fn check_adaptive_prepared(request: &Request, reservation: usize) -> Result<(), Error> {
    let wave = request.max_in_flight.saturating_mul(
        std::mem::size_of::<Batch<Probe>>().saturating_add(std::mem::size_of::<Probe>()),
    );
    if reservation.saturating_add(wave) > request.limits.max_prepared_bytes {
        return Err(Error::PipelineExecution {
            source: super::executor::limit(
                "prepared descriptions",
                request.limits.max_prepared_bytes,
            ),
        });
    }
    Ok(())
}

fn admit_adaptive<E: Pipelined>(
    request: &Request,
    executor: &mut E,
    deadline: &Deadline,
    approved: &ApprovedScan,
    reservation: usize,
) -> Result<(), Error> {
    let discovery = if request.discovery.runs() {
        request.discovery.probes.as_slice()
    } else {
        &[]
    };
    for (endpoints, stage, first_sequence) in [
        (discovery, Stage::Discovery, 0u64),
        (
            approved.endpoints.as_slice(),
            Stage::Scan,
            probe_count(approved.targets.len(), discovery.len(), request.attempts)? as u64,
        ),
    ] {
        if approved.targets.is_empty() || endpoints.is_empty() {
            continue;
        }
        check_adaptive_prepared(request, reservation)?;
        let options = pipeline_options(request, deadline, crate::Stats::default(), reservation)?;
        let wave_len = request
            .max_in_flight
            .min(approved.targets.len().saturating_mul(endpoints.len()))
            .max(1);
        let mut admission = super::executor::AdaptiveAdmission::new(wave_len);
        let mut batches = Vec::with_capacity(wave_len);
        for batch in adaptive_batches(request, &approved.targets, endpoints, stage, first_sequence)
        {
            batches.push(batch);
            if batches.len() == wave_len {
                executor
                    .admit_adaptive_pipeline(&batches, &options, &mut admission)
                    .map_err(|source| Error::PipelineExecution { source })?;
                batches.clear();
            }
        }
        if !batches.is_empty() {
            executor
                .admit_adaptive_pipeline(&batches, &options, &mut admission)
                .map_err(|source| Error::PipelineExecution { source })?;
        }
        admission
            .check(wave_len, approved.targets.len(), &options)
            .map_err(|source| Error::PipelineExecution { source })?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_adaptive<E, C, F>(
    request: &Request,
    executor: &mut E,
    clock: &mut C,
    deadline: &mut Deadline,
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Probes>,
    controller: &mut super::adaptive::Controller,
    stage: Stage,
    targets: &[SelectedAddress],
    endpoints: &[ProbeEndpoint],
    first_sequence: u64,
    owed: &mut Owed,
    reservation: usize,
) -> Result<crate::Stats, Error>
where
    E: Pipelined,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    let mut stats = crate::Stats::default();
    if targets.is_empty() || endpoints.is_empty() {
        return Ok(stats);
    }
    enforce_deadline(&Probes, deadline)?;
    let mut work = controller.open_stage(
        targets,
        endpoints.len(),
        request.attempts,
        first_sequence,
        clock.now(),
    );
    let state_charge = reservation;
    loop {
        enforce_deadline(&Probes, deadline)?;
        let now = clock.now();
        let remaining = deadline
            .remaining()
            .map_err(|error| Probes.duration_limit(0, error))?;
        let operation_end = now.checked_add(remaining).ok_or(Error::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })?;
        let capacity = controller.window();
        let wave = controller.select(&mut work, now, operation_end, capacity);
        evidence.release_responses(controller.take_canceled_responses(&mut work));
        if wave.selections.is_empty() {
            if wave.done {
                break;
            }
            let wait = wave
                .next_ready
                .map_or(Duration::from_millis(1), |ready| {
                    ready.saturating_duration_since(now)
                })
                .min(Duration::from_millis(5));
            pause(deadline, clock, wait).map_err(|paused| paused.into_error(&Probes, 0))?;
            add_stats(
                &mut stats,
                &crate::Stats {
                    elapsed: wait,
                    ..crate::Stats::default()
                },
                0,
            )?;
            continue;
        }
        for selection in &wave.selections {
            controller.admitted(&mut work, *selection);
        }
        settle(request, clock, deadline, owed, &mut stats)?;
        let mut batches = Vec::with_capacity(wave.selections.len());
        let mut host_deadlines = Vec::with_capacity(wave.selections.len());
        for selection in &wave.selections {
            batches.push(Batch::single(
                super::plan::planned_probe(
                    request,
                    selection.sequence,
                    stage,
                    &targets[selection.slot],
                    endpoints[selection.endpoint],
                    selection.attempt,
                ),
                selection.timeout,
            ));
            host_deadlines.push(Some(selection.host_deadline));
        }
        let outcome = drive_pipeline(
            request,
            executor,
            clock,
            evidence,
            deadline,
            &batches,
            host_deadlines,
            stats.clone(),
            state_charge,
        )?;
        for (completed, dropped) in outcome.completed.iter().zip(&outcome.omitted) {
            if !completed && !dropped {
                return Err(Error::InvalidEvidence {
                    sequence: 0,
                    message: "pipeline left an adaptive wave entry unsettled".to_owned(),
                });
            }
        }
        let sent = outcome.confirmed.iter().filter(|sent| **sent).count() as u64;
        if outcome.stats.packets_attempted != sent
            || outcome.stats.packets_completed != sent
            || outcome.stats.bytes != outcome.sent_bytes
        {
            return Err(Error::InvalidEvidence {
                sequence: 0,
                message: "pipeline completion statistics disagree with validated sends/outcomes"
                    .to_owned(),
            });
        }
        add_stats(&mut stats, &outcome.stats, 0)?;
        if outcome.stats.packets_attempted > 0 {
            owed.owe(1, None);
        }
        controller.observe_active(outcome.peak_pending);
        let mut replies: std::collections::HashMap<u64, super::evidence::Feedback> =
            std::collections::HashMap::new();
        for feedback in take_feedback(evidence) {
            replies
                .entry(feedback.sequence)
                .and_modify(|kept| {
                    if feedback.received_at < kept.received_at {
                        *kept = feedback;
                    }
                })
                .or_insert(feedback);
        }
        let settled_at = clock.now();
        for (index, selection) in wave.selections.iter().enumerate() {
            let mut selection = *selection;
            if let Some(sent_at) = outcome.sent_at[index] {
                let observed_at = outcome.observed_at[index].unwrap_or(sent_at);
                controller.confirm_send(&mut work, selection, observed_at);
                selection.host_limited = selection.host_limited
                    || sent_at
                        .checked_add(selection.timeout)
                        .is_none_or(|end| end > selection.host_deadline);
            }
            if outcome.omitted[index] {
                controller.mark_incomplete(selection.host);
                controller.settle(
                    &mut work,
                    selection,
                    super::adaptive::Outcome::Omitted,
                    settled_at,
                );
                continue;
            }
            let outcome = match replies.get(&selection.sequence) {
                Some(feedback) => super::adaptive::Outcome::Reply {
                    latency: feedback.latency,
                    responder: feedback.responder,
                    control: matches!(
                        feedback.reply,
                        super::Reply::IcmpPortUnreachable
                            | super::Reply::IcmpDestinationUnreachable
                            | super::Reply::TcpReset
                    ),
                },
                None => super::adaptive::Outcome::Silent,
            };
            controller.settle(&mut work, selection, outcome, settled_at);
        }
        evidence.release_responses(controller.take_canceled_responses(&mut work));
    }
    Ok(stats)
}

fn take_feedback<F>(
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Probes>,
) -> Vec<super::evidence::Feedback>
where
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    match &mut evidence.classifier_mut().feedback {
        Some((feedback, _)) => std::mem::take(feedback),
        None => Vec::new(),
    }
}

fn pipeline_options(
    request: &Request,
    deadline: &Deadline,
    preceding: crate::Stats,
    reserved: usize,
) -> Result<PipelineOptions, Error> {
    Ok(PipelineOptions {
        max_in_flight: request.max_in_flight,
        probes_per_second: request.probes_per_second,
        max_duration: deadline
            .remaining()
            .map_err(|error| Probes.duration_limit(0, error))?,
        max_prepared_bytes: request.limits.max_prepared_bytes.saturating_sub(reserved),
        max_evidence_frames: request.limits.max_evidence_frames,
        max_evidence_bytes: request.limits.max_evidence_bytes,
        host_deadlines: Vec::new(),
        preceding,
    })
}

/// Rejects a pipelined stage whose batch descriptions for `targets` would
/// exceed the preparation limit.
fn check_prepared_descriptions(
    request: &Request,
    targets: &[SelectedAddress],
    endpoints: &[ProbeEndpoint],
) -> Result<(), Error> {
    let probes_per_target = endpoints.len().saturating_mul(request.attempts as usize);
    let batch_bytes = targets.iter().fold(0usize, |bytes, target| {
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
    Ok(())
}

struct WaveOutcome {
    stats: crate::Stats,
    confirmed: Vec<bool>,
    completed: Vec<bool>,
    omitted: Vec<bool>,
    sent_at: Vec<Option<Instant>>,
    observed_at: Vec<Option<Instant>>,
    sent_bytes: u64,
    peak_pending: usize,
}

#[allow(clippy::too_many_arguments)]
fn drive_pipeline<E, C, F>(
    request: &Request,
    executor: &mut E,
    clock: &C,
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Probes>,
    deadline: &Deadline,
    batches: &[Batch<Probe>],
    host_deadlines: Vec<Option<Instant>>,
    preceding: crate::Stats,
    state_charge: usize,
) -> Result<WaveOutcome, Error>
where
    E: Pipelined,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    let mut completed = vec![false; batches.len()];
    let mut confirmed = vec![false; batches.len()];
    let mut omitted = vec![false; batches.len()];
    let mut sent_at: Vec<Option<Instant>> = vec![None; batches.len()];
    let mut observed_at: Vec<Option<Instant>> = vec![None; batches.len()];
    let mut pending_now = 0usize;
    let mut peak_pending = 0usize;
    let mut sent_bytes = 0u64;
    let mut settings = pipeline_options(request, deadline, preceding, state_charge)?;
    settings.host_deadlines = host_deadlines;
    let adaptive_wave = !settings.host_deadlines.is_empty();
    let result = executor.execute_pipeline(batches, settings, &mut |event| {
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
                if confirmed[index]
                    || omitted[index]
                    || !sent_probe_matches(probe, &sent.built().packet)
                {
                    return Err(invalid(index));
                }
                confirmed[index] = true;
                sent_at[index] = Some(sent.timing().freshness_marker().monotonic());
                observed_at[index] = Some(clock.now());
                pending_now = pending_now.saturating_add(1);
                peak_pending = peak_pending.max(pending_now);
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
            PipelineEvent::Omitted { index } => {
                if !adaptive_wave || index >= batches.len() || confirmed[index] || omitted[index] {
                    return Err(invalid(index));
                }
                omitted[index] = true;
            }
            PipelineEvent::Completed { index, execution } => {
                let batch = batches.get(index).ok_or_else(|| invalid(index))?;
                if completed[index] || !confirmed[index] || omitted[index] {
                    return Err(invalid(index));
                }
                // Scan probe events never end the operation early.
                let _ = evidence
                    .validate(batch, &execution)
                    .and_then(|()| evidence.process(batch, execution, deadline))
                    .map_err(packetcraftr_core::error::BoundaryError::from_error)?;
                completed[index] = true;
                pending_now = pending_now.saturating_sub(1);
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
        Ok(stats) => Ok(WaveOutcome {
            stats,
            confirmed,
            completed,
            omitted,
            sent_at,
            observed_at,
            sent_bytes,
            peak_pending,
        }),
        Err(source) => Err(Error::PipelineExecution { source }),
    }
}

fn run_pipelined<E, C, F>(
    request: &Request,
    executor: &mut E,
    clock: &C,
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Probes>,
    deadline: &Deadline,
    plan: &StagePlan<'_>,
    preceding: crate::Stats,
) -> Result<(crate::Stats, usize), Error>
where
    E: Pipelined,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    let batches: Vec<_> = plan.batches(request).collect();
    let outcome = drive_pipeline(
        request,
        executor,
        clock,
        evidence,
        deadline,
        &batches,
        Vec::new(),
        preceding,
        0,
    )?;
    let count = batches.len() as u64;
    if outcome.omitted.iter().any(|dropped| *dropped)
        || outcome.completed.iter().any(|done| !*done)
        || outcome.stats.packets_attempted != count
        || outcome.stats.packets_completed != count
        || outcome.stats.bytes != outcome.sent_bytes
    {
        return Err(Error::InvalidEvidence {
            sequence: 0,
            message: "pipeline completion statistics disagree with validated sends/outcomes"
                .to_owned(),
        });
    }
    enforce_deadline(&Probes, deadline)?;
    Ok((outcome.stats, outcome.peak_pending))
}

struct ApprovedScan {
    planned_duration: std::time::Duration,
    declared_target: String,
    targets: Vec<SelectedAddress>,
    duplicates: Vec<u32>,
    endpoints: Vec<ProbeEndpoint>,
    /// Discovery and scan probes, without neighbor requests.
    total_probes: usize,
    /// Whether explicit discovery or any probe resolves a link-layer
    /// neighbor.
    resolves_neighbors: bool,
}

impl ApprovedScan {
    fn addresses(&self) -> Vec<IpAddr> {
        self.targets.iter().map(|target| target.address).collect()
    }
}

struct ScanPlan {
    total_probes: usize,
    resolves_neighbors: bool,
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
        resolves_neighbors: plan.resolves_neighbors,
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
    // A multicast or limited-broadcast target's link address follows from its
    // own, so neither discovery nor a stage asks for its neighbor.
    let resolvable: Vec<&SelectedAddress> = targets
        .iter()
        .filter(|target| {
            !target.address.is_multicast()
                && target.address != IpAddr::from(std::net::Ipv4Addr::BROADCAST)
        })
        .collect();
    let explicit_requests = if discovery.runs() && discovery.neighbor {
        probe_count(resolvable.len(), 1, request.attempts)?
    } else {
        0
    };
    if explicit_requests > 0 {
        // Each attempt is one resolver request bounded like a probe.
        crate::neighbor::Options::default()
            .single_attempt(
                request.timeout,
                request.limits.max_evidence_frames,
                request.limits.max_evidence_bytes,
                request.collection.capture.snap_length,
            )
            .validate()
            .map_err(|source| Error::InvalidDiscovery {
                message: format!(
                    "neighbor discovery cannot use the scan timeout, snap length, and evidence limits: {source}"
                ),
            })?;
    }
    let scan_probes = probe_count(targets.len(), endpoints.len(), request.attempts)?;
    let total_probes = discovery_probes
        .checked_add(scan_probes)
        .ok_or_else(overflow)?;
    // Each stage resolves its probes' link-layer neighbors before sending
    // them: a fresh resolution asks for the target's neighbor, or its
    // gateway's, with at most one request each.
    let resolves_next_hops =
        total_probes > 0 && request.route.link_mode != Mode::Layer3 && !resolvable.is_empty();
    // Explicit neighbor discovery runs first and covers those requests: an
    // answer stays in the operation's cache, a silent target is sent nothing
    // more, and a routed target, which it sends nothing, needs at most one
    // request for its gateway within its `attempts`.
    let implicit_requests = if resolves_next_hops && explicit_requests == 0 {
        resolvable.len()
    } else {
        0
    };
    if resolves_next_hops {
        // Those requests capture within the evidence limits and snap length,
        // which must hold a decodable reply just as explicit neighbor
        // discovery requires.
        let snap_length = request.collection.capture.snap_length;
        let (field, value) = if snap_length < request.limits.max_evidence_bytes {
            ("snap_length", snap_length)
        } else {
            ("max_evidence_bytes", request.limits.max_evidence_bytes)
        };
        crate::neighbor::Options::default()
            .one_attempt(
                request.timeout,
                request.limits.max_evidence_frames,
                request.limits.max_evidence_bytes,
                snap_length,
            )
            .validate()
            .map_err(|source| Error::InvalidLimit {
                field,
                value: u64::try_from(value).unwrap_or(u64::MAX),
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
    let neighbor_frames = resolvable.iter().try_fold(0u64, |total, target| {
        let frame = if target.address.is_ipv4() {
            IPV4_REQUEST_BYTES
        } else {
            IPV6_REQUEST_BYTES
        };
        total.checked_add(frame)
    });
    // One target's neighbor bytes cover `attempts` discovery requests plus
    // at most one implicit request for its probes' neighbor.
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
    // Every neighbor request waits its attempt timeout and paces like a probe,
    // except a last request no probe follows; a paced request's wait counts
    // toward its pause, so it holds the next transmission back by the longer.
    let neighbor_requests = explicit_requests
        .checked_add(implicit_requests)
        .ok_or_else(too_long)?;
    let neighbor_pauses = if total_probes == 0 {
        neighbor_requests.saturating_sub(1)
    } else {
        neighbor_requests
    };
    let neighbor_duration = u32::try_from(neighbor_requests - neighbor_pauses)
        .ok()
        .and_then(|unpaced| request.timeout.checked_mul(unpaced))
        .and_then(|waits| {
            u32::try_from(neighbor_pauses)
                .ok()
                .and_then(|paced| request.timeout.max(pause).checked_mul(paced))
                .and_then(|paced| paced.checked_add(waits))
        })
        .ok_or_else(too_long)?;
    let stage_pause = if discovery_probes > 0 && scan_probes > 0 {
        pause
    } else {
        Duration::ZERO
    };
    let stage_duration = |probes| {
        request.adaptive.map_or_else(
            || worst_case_duration(request, probes),
            |adaptive| adaptive_worst_case_duration(request, &adaptive, probes),
        )
    };
    let worst_case = [
        stage_duration(discovery_probes)?,
        neighbor_duration,
        stage_pause,
        stage_duration(scan_probes)?,
    ]
    .into_iter()
    .try_fold(Duration::ZERO, Duration::checked_add)
    .ok_or_else(too_long)?;
    check_probe_duration(&Probes, worst_case, request.limits.max_duration)?;
    Ok(ScanPlan {
        total_probes,
        resolves_neighbors: resolves_next_hops || explicit_requests > 0,
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
