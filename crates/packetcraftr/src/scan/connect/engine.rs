// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::tcp::{self, Provider, Stream as _};

use crate::providers::{TargetProviders, TcpOf, TcpProviders};
use crate::{
    Client, Sink,
    clock::Clock,
    execution::Errors as _,
    execution::rate_delay,
    policy::{Authorizer, Operation, SocketLimits, SocketOperation},
    probe::{ProbeEndpoint, enforce_deadline},
    target::ResolveTarget,
    target::{DeclaredTargets, FamilyGate, SelectedAddress, admit_selection, approve_operation},
};
use packetcraftr_core::error::BoundaryError;

use super::super::discovery::{Composer, Observation, ReasonKind, Scan};
use super::super::error::Probes;
use super::super::plan::{adaptive_worst_case_duration, probe_count, worst_case_duration};
use super::super::report::RttAccumulator;
use super::super::{Error, Request, Stage};
use super::{Event, Outcome, ProbeEvidence, Report, Stats};

impl<P: TargetProviders + TcpProviders, K: Clock> Client<P, K> {
    /// Scans the request's targets and ports with kernel TCP connects
    /// through the client's TCP provider, keeping at most `max_in_flight`
    /// attempts pending at once.
    pub fn scan_connect<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let started = self.now();
        let mut deadline = self.deadline(request.limits.max_duration);
        let mut publish =
            crate::execution::publisher(&self.runtime, sink, Error::from, |source| {
                Error::Output { source }
            })?;
        run(
            &request,
            &mut self.admission(),
            &Arc::new(TcpOf(Arc::clone(&self.providers))),
            &self.clock,
            &mut deadline,
            started,
            |probe, deadline| publish(Event::Probe(probe), deadline),
        )
    }
}

pub(super) struct Active<S> {
    pending: tcp::PendingConnect<S>,
    sequence: u64,
    stage: Stage,
    endpoint: SocketAddr,
    scope: Option<crate::target::ResolvedZone>,
    attempt: u32,
    started: Instant,
    scheduled_at: SystemTime,
    timeout: Duration,
    selection: Option<super::super::adaptive::Selection>,
}
fn invalid(field: &'static str, value: usize, reason: &str) -> Error {
    Error::InvalidLimit {
        field,
        value: value as u64,
        reason: reason.to_owned(),
    }
}
fn execution(
    sequence: u64,
    source: impl packetcraftr_core::error::Classified + Send + Sync + 'static,
) -> Error {
    Error::Execution {
        sequence,
        source: BoundaryError::from_error(source),
    }
}

pub(super) struct Planned {
    /// Discovery ports, probed on every target before the scan stage.
    discovery: Vec<u16>,
    /// Scan ports, probed on the targets discovery leaves to the scan.
    ports: Vec<u16>,
    diagnostics: Vec<packetcraftr_core::diagnostic::Diagnostic>,
    delay: Duration,
    limits: SocketLimits,
    planned_duration: Duration,
}

pub(super) fn planned<A: Authorizer + ResolveTarget>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
    active_size: usize,
) -> Result<(Vec<SelectedAddress>, Planned), Error> {
    let tcp_ports = |endpoints: &[ProbeEndpoint]| -> Vec<u16> {
        endpoints
            .iter()
            .filter_map(|endpoint| endpoint.port())
            .collect()
    };
    let ports = tcp_ports(request.planned_endpoints()?);
    if let Some(probe) = super::super::method::unconnectable(request) {
        return Err(Error::MethodProbe {
            method: super::super::method::Method::Connect.as_str(),
            probe,
        });
    }
    let discovery = if request.discovery.runs() {
        tcp_ports(&request.discovery.probes)
    } else {
        Vec::new()
    };
    if request.route.requires_packet_route() {
        return Err(Error::UnsupportedTcpRoute);
    }
    if ports.contains(&0) || discovery.contains(&0) {
        return Err(invalid("port", 0, "TCP connect requires nonzero ports"));
    }
    let (selected, (planned, _)) = admit_selection(
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
            let targets = selected.targets.len();
            let discovery_count = probe_count(targets, discovery.len(), request.attempts)?;
            let scan_count = probe_count(targets, ports.len(), request.attempts)?;
            let count = discovery_count.checked_add(scan_count).ok_or_else(|| {
                invalid("probes", usize::MAX, "probe-count arithmetic overflowed")
            })?;
            crate::probe::check_probe_count(&Probes, count, request.limits.max_probes)?;
            let delay = rate_delay(&Probes, "probes_per_second", 1, request.probes_per_second)?;
            let stage_pause = if discovery_count > 0 && scan_count > 0 {
                delay
            } else {
                Duration::ZERO
            };
            let stage_duration = |probes| {
                request.adaptive.map_or_else(
                    || worst_case_duration(request, probes),
                    |adaptive| adaptive_worst_case_duration(request, &adaptive, probes),
                )
            };
            let planned_duration = [
                stage_duration(discovery_count)?,
                stage_pause,
                stage_duration(scan_count)?,
            ]
            .into_iter()
            .try_fold(Duration::ZERO, Duration::checked_add)
            .ok_or(Error::DurationLimit {
                actual: Duration::MAX,
                limit: request.limits.max_duration,
            })?;
            crate::probe::check_probe_duration(
                &Probes,
                planned_duration,
                request.limits.max_duration,
            )?;
            // Discovery may leave any target to the scan stage, so the
            // operation covers every target on every port of either stage.
            let mut every_port = discovery.clone();
            every_port.extend(ports.iter().filter(|port| !discovery.contains(port)));
            let effective = request.max_in_flight.min(tcp::MAX_PENDING_CONNECTIONS);
            let charge = request
                .adaptive
                .map(|_| {
                    super::super::adaptive::state_charge(
                        targets,
                        every_port.len(),
                        effective,
                        super::super::adaptive::scoped_bytes(&selected.targets),
                        0,
                    )
                })
                .unwrap_or(0)
                .saturating_add(
                    targets
                        .saturating_mul(every_port.len())
                        .saturating_mul(std::mem::size_of::<SocketAddr>()),
                )
                .saturating_add(
                    targets
                        .saturating_mul(std::mem::size_of::<SelectedAddress>())
                        .saturating_mul(2),
                )
                .saturating_add(
                    (discovery.len().saturating_add(ports.len()))
                        .saturating_mul(std::mem::size_of::<u16>()),
                )
                .saturating_add(effective.saturating_mul(active_size));
            if charge > request.limits.max_prepared_bytes {
                return Err(Error::PipelineExecution {
                    source: crate::scan::executor::limit(
                        "prepared descriptions",
                        request.limits.max_prepared_bytes,
                    ),
                });
            }
            let endpoints = selected
                .targets
                .iter()
                .flat_map(|target| {
                    every_port
                        .iter()
                        .map(move |port| socket_endpoint(target, *port))
                })
                .collect::<Vec<_>>();
            Ok((
                Planned {
                    discovery: discovery.clone(),
                    ports: ports.clone(),
                    diagnostics: selected
                        .duplicates
                        .iter()
                        .map(|duplicate| request.duplicate_diagnostic(*duplicate))
                        .collect(),
                    delay,
                    limits: SocketLimits::new(count as u64, 0, 0),
                    planned_duration,
                },
                endpoints,
            ))
        },
        |(planned, endpoints)| {
            SocketOperation::new(endpoints, planned.limits)
                .map(Operation::Socket)
                .map_err(|source| execution(0, source))
        },
    )?;
    Ok((selected.targets, planned))
}

struct StagePlan<'a> {
    stage: Stage,
    targets: &'a [SelectedAddress],
    ports: &'a [u16],
    first_sequence: u64,
    count: usize,
    delay: Duration,
    limits: &'a SocketLimits,
}

impl<'a> StagePlan<'a> {
    fn new(
        request: &Request,
        planned: &'a Planned,
        stage: Stage,
        targets: &'a [SelectedAddress],
        first_sequence: u64,
    ) -> Result<Self, Error> {
        let ports = match stage {
            Stage::Discovery => planned.discovery.as_slice(),
            Stage::Scan => planned.ports.as_slice(),
        };
        Ok(Self {
            stage,
            count: probe_count(
                targets.len().saturating_mul(ports.len()),
                1,
                request.attempts,
            )?,
            targets,
            ports,
            first_sequence,
            delay: planned.delay,
            limits: &planned.limits,
        })
    }

    fn endpoint(&self, position: usize) -> (SocketAddr, Option<crate::target::ResolvedZone>) {
        let target = &self.targets[position / self.ports.len()];
        (
            socket_endpoint(target, self.ports[position % self.ports.len()]),
            target.scope.clone(),
        )
    }
}

fn socket_endpoint(selected: &crate::target::SelectedAddress, port: u16) -> SocketAddr {
    match (selected.address, &selected.scope) {
        (IpAddr::V6(address), Some(scope)) => SocketAddr::V6(std::net::SocketAddrV6::new(
            address,
            port,
            0,
            scope.interface.index,
        )),
        (address, _) => SocketAddr::new(address, port),
    }
}

/// `None` means every native connect admission is still held, for example by
/// a cancelled attempt whose provider call has not returned or a finished one
/// whose worker has not yet released it, so the caller retries this endpoint.
#[allow(clippy::too_many_arguments)]
fn admit_next<Q, A>(
    request: &Request,
    stage: &StagePlan<'_>,
    next: usize,
    authorizer: &mut A,
    deadline: &Deadline,
    provider: &Arc<Q>,
    budget: &tcp::ConnectBudget,
    clock: &impl Clock,
) -> Result<Option<Active<Q::Stream>>, Error>
where
    Q: Provider + 'static,
    Q::Stream: 'static,
    A: Authorizer + ResolveTarget,
{
    let endpoints = stage.targets.len() * stage.ports.len();
    let (endpoint, scope) = stage.endpoint(next % endpoints);
    let attempt = (next / endpoints) as u32 + 1;
    let sequence = stage.first_sequence + next as u64;
    let final_endpoints = [endpoint];
    let operation = SocketOperation::new(&final_endpoints, *stage.limits)
        .map_err(|source| execution(sequence, source))?;
    approve_operation(authorizer, Operation::Socket(operation), deadline, &Probes)?;
    let timeout = deadline.bounded_timeout(request.timeout)?;
    let admitted = clock.now();
    let scheduled_at = SystemTime::now();
    let pending = match budget.start(
        Arc::clone(provider),
        endpoint,
        &Deadline::new(timeout).with_cancellation(deadline.cancellation().cloned()),
    ) {
        Ok(pending) => pending,
        Err(tcp::Error::Capacity { .. }) => return Ok(None),
        Err(source) => return Err(execution(sequence, source)),
    };
    Ok(Some(Active {
        pending,
        sequence,
        stage: stage.stage,
        endpoint,
        scope,
        attempt,
        started: admitted,
        scheduled_at,
        timeout,
        selection: None,
    }))
}

fn settle_active<S: tcp::Stream>(
    active: &mut Vec<Active<S>>,
    index: usize,
    now: Instant,
) -> Result<Option<(Active<S>, ProbeEvidence)>, Error> {
    let result = active[index]
        .pending
        .poll()
        .map_err(|source| execution(active[index].sequence, source))?;
    if let Some(result) = result {
        let entry = active.remove(index);
        let probe = finish_probe(&entry, result)?;
        return Ok(Some((entry, probe)));
    }
    if now.saturating_duration_since(active[index].started) < active[index].timeout {
        return Ok(None);
    }
    let mut entry = active.remove(index);
    let attempted = entry.pending.cancel();
    let probe = ProbeEvidence {
        sequence: entry.sequence,
        stage: entry.stage,
        endpoint: entry.endpoint,
        scope: entry.scope.clone(),
        attempt: entry.attempt,
        attempted,
        connect_succeeded: None,
        outcome: Outcome::DeadlineExpired,
        scheduled_at: entry.scheduled_at,
        finished_at: None,
        elapsed: now.saturating_duration_since(entry.started),
        local: None,
        error: None,
    };
    Ok(Some((entry, probe)))
}

/// Totals shared by both stages.
struct Progress {
    stats: Stats,
    rtt: RttAccumulator,
    evidence_bytes: usize,
    next_start: Instant,
    peak: usize,
    retries: usize,
    discovery: Vec<Observation>,
}

pub(super) fn run<Q, A, C, F>(
    request: &Request,
    authorizer: &mut A,
    provider: &Arc<Q>,
    clock: &C,
    deadline: &mut Deadline,
    started: Instant,
    mut emit: F,
) -> Result<Report, Error>
where
    Q: Provider + 'static,
    Q::Stream: 'static,
    A: Authorizer + ResolveTarget,
    C: Clock,
    F: FnMut(ProbeEvidence, &Deadline) -> Result<(), Error>,
{
    enforce_deadline(&Probes, deadline)?;
    let (targets, planned) = planned(
        request,
        authorizer,
        deadline,
        std::mem::size_of::<Active<Q::Stream>>(),
    )?;
    let budget = tcp::ConnectBudget::new(request.max_in_flight);
    let mut controller = request.adaptive.map(|config| {
        super::super::adaptive::Controller::new(config, request.timeout, request.max_in_flight)
    });
    let mut progress = Progress {
        stats: Stats::default(),
        rtt: RttAccumulator::default(),
        evidence_bytes: 0,
        next_start: clock.now(),
        peak: 0,
        retries: 0,
        discovery: Vec::new(),
    };
    let options = &request.discovery;
    let mut composer = Composer::new(&targets, options.mode, options.unresponsive);
    let discovery = StagePlan::new(request, &planned, Stage::Discovery, &targets, 0)?;
    let scan_sequence = discovery.count as u64;
    run_stage(
        request,
        &discovery,
        authorizer,
        provider,
        &budget,
        clock,
        deadline,
        &mut progress,
        &mut emit,
        controller.as_mut(),
    )?;
    for observation in progress.discovery.drain(..) {
        if !composer.observe(observation) {
            return Err(Error::IncoherentEvents {
                message: "a discovery outcome names no selected target".to_owned(),
            });
        }
    }
    if let Some(controller) = &controller {
        for (index, target) in targets.iter().enumerate() {
            if controller
                .find(target)
                .is_some_and(|host| controller.is_incomplete(host))
            {
                composer.incomplete(index);
            }
        }
    }
    let mut hosts = composer.finish();
    let scanned: Vec<_> = targets
        .iter()
        .zip(&hosts)
        .filter(|(_, host)| host.scan == Scan::Scanned)
        .map(|(target, _)| target.clone())
        .collect();
    let scan = StagePlan::new(request, &planned, Stage::Scan, &scanned, scan_sequence)?;
    run_stage(
        request,
        &scan,
        authorizer,
        provider,
        &budget,
        clock,
        deadline,
        &mut progress,
        &mut emit,
        controller.as_mut(),
    )?;
    if let Some(controller) = &controller {
        for (index, target) in targets.iter().enumerate() {
            if controller
                .find(target)
                .is_some_and(|host| controller.is_incomplete(host))
            {
                hosts[index].scan = Scan::Incomplete;
            }
        }
    }
    enforce_deadline(&Probes, deadline)?;
    let Progress {
        mut stats,
        rtt,
        evidence_bytes,
        peak,
        retries,
        ..
    } = progress;
    stats.elapsed = clock.now().saturating_duration_since(started);
    stats.rtt = rtt.finish();
    stats.retained_evidence_bytes = evidence_bytes;
    let ceilings = (Some(budget.capacity()), Some(tcp::MAX_PENDING_CONNECTIONS));
    let scheduling = match controller {
        Some(controller) => controller.finish(ceilings),
        None => super::super::adaptive::fixed_scheduling(ceilings, peak, retries),
    };
    Ok(Report {
        target: request.targets.to_string(),
        resolved_addresses: targets.iter().map(|target| target.address).collect(),
        hosts,
        diagnostics: planned.diagnostics,
        planned_duration: planned.planned_duration,
        stats,
        scheduling,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_stage<Q, A, C, F>(
    request: &Request,
    stage: &StagePlan<'_>,
    authorizer: &mut A,
    provider: &Arc<Q>,
    budget: &tcp::ConnectBudget,
    clock: &C,
    deadline: &mut Deadline,
    progress: &mut Progress,
    emit: &mut F,
    controller: Option<&mut super::super::adaptive::Controller>,
) -> Result<(), Error>
where
    Q: Provider + 'static,
    Q::Stream: 'static,
    A: Authorizer + ResolveTarget,
    C: Clock,
    F: FnMut(ProbeEvidence, &Deadline) -> Result<(), Error>,
{
    if let Some(controller) = controller {
        return run_stage_adaptive(
            request, stage, authorizer, provider, budget, clock, deadline, progress, emit,
            controller,
        );
    }
    let mut active: Vec<Active<Q::Stream>> = Vec::new();
    let effective = request.max_in_flight.min(tcp::MAX_PENDING_CONNECTIONS);
    let mut next = 0usize;
    while next < stage.count || !active.is_empty() {
        enforce_deadline(&Probes, deadline)?;
        let mut admission_held = false;
        while next < stage.count && active.len() < effective && clock.now() >= progress.next_start {
            let Some(admitted) = admit_next(
                request, stage, next, authorizer, deadline, provider, budget, clock,
            )?
            else {
                admission_held = true;
                break;
            };
            active.push(admitted);
            progress.peak = progress.peak.max(active.len());
            progress.stats.connections_scheduled += 1;
            next += 1;
            progress.next_start = clock
                .now()
                .checked_add(stage.delay)
                .ok_or_else(|| invalid("rate", 0, "pacing deadline overflow"))?;
        }
        let mut index = 0;
        while index < active.len() {
            enforce_deadline(&Probes, deadline)?;
            let Some((_, probe)) = settle_active(&mut active, index, clock.now())? else {
                index += 1;
                continue;
            };
            record(request, progress, &probe)?;
            emit(probe, deadline)?;
        }
        if next < stage.count || !active.is_empty() {
            let mut wait = Duration::from_millis(1);
            if next < stage.count && active.len() < effective && !admission_held {
                wait = wait.min(progress.next_start.saturating_duration_since(clock.now()));
            }
            if !wait.is_zero() {
                deadline.start_accounting(Duration::ZERO)?;
                clock.sleep(wait, deadline).map_err(|source| Error::Clock {
                    sequence: stage.first_sequence + next as u64,
                    source: Box::new(source),
                })?;
            }
        }
    }
    Ok(())
}

pub(super) fn connect_outcome(probe: &ProbeEvidence) -> super::super::adaptive::Outcome {
    if !probe.attempted {
        return super::super::adaptive::Outcome::Omitted;
    }
    match probe.outcome {
        Outcome::Connected | Outcome::Refused => super::super::adaptive::Outcome::Reply {
            latency: probe.elapsed,
            responder: probe.endpoint.ip(),
            control: false,
        },
        Outcome::TimedOut | Outcome::DeadlineExpired => super::super::adaptive::Outcome::Silent,
        Outcome::Unreachable | Outcome::LocalError => super::super::adaptive::Outcome::Aborted,
    }
}

#[allow(clippy::too_many_arguments)]
fn run_stage_adaptive<Q, A, C, F>(
    request: &Request,
    stage: &StagePlan<'_>,
    authorizer: &mut A,
    provider: &Arc<Q>,
    budget: &tcp::ConnectBudget,
    clock: &C,
    deadline: &mut Deadline,
    progress: &mut Progress,
    emit: &mut F,
    controller: &mut super::super::adaptive::Controller,
) -> Result<(), Error>
where
    Q: Provider + 'static,
    Q::Stream: 'static,
    A: Authorizer + ResolveTarget,
    C: Clock,
    F: FnMut(ProbeEvidence, &Deadline) -> Result<(), Error>,
{
    let mut work = controller.open_stage(
        stage.targets,
        stage.ports.len(),
        request.attempts,
        stage.first_sequence,
        clock.now(),
    );
    let mut active: Vec<Active<Q::Stream>> = Vec::new();
    loop {
        enforce_deadline(&Probes, deadline)?;
        let mut index = 0;
        let mut settled = Vec::new();
        while index < active.len() {
            enforce_deadline(&Probes, deadline)?;
            let Some((entry, probe)) = settle_active(&mut active, index, clock.now())? else {
                index += 1;
                continue;
            };
            if let Some(selection) = entry.selection {
                if probe.attempted {
                    controller.note_attempted(selection);
                } else {
                    controller.mark_incomplete(selection.host);
                }
                settled.push((selection, connect_outcome(&probe)));
            }
            record(request, progress, &probe)?;
            emit(probe, deadline)?;
        }
        let settled_at = clock.now();
        for (selection, outcome) in settled {
            controller.settle(&mut work, selection, outcome, settled_at);
        }
        if work.done() && active.is_empty() {
            return Ok(());
        }
        let now = clock.now();
        let remaining = deadline
            .remaining()
            .map_err(|error| Probes.duration_limit(0, error))?;
        let operation_end = now
            .checked_add(remaining)
            .ok_or_else(|| invalid("rate", 0, "pacing deadline overflow"))?;
        let capacity = controller
            .window()
            .min(request.max_in_flight.min(tcp::MAX_PENDING_CONNECTIONS))
            .saturating_sub(active.len());
        let wave = controller.select(&mut work, now, operation_end, capacity);
        let mut admission_held = false;
        let mut paced_out = false;
        for mut selection in wave.selections {
            if clock.now() >= selection.host_deadline {
                controller.mark_incomplete(selection.host);
                controller.settle(
                    &mut work,
                    selection,
                    super::super::adaptive::Outcome::Omitted,
                    clock.now(),
                );
                continue;
            }
            if clock.now() < progress.next_start {
                paced_out = true;
                break;
            }
            let (endpoint, scope) =
                stage.endpoint(selection.slot * stage.ports.len() + selection.endpoint);
            let sequence = selection.sequence;
            let final_endpoints = [endpoint];
            let operation = SocketOperation::new(&final_endpoints, *stage.limits)
                .map_err(|source| execution(sequence, source))?;
            approve_operation(authorizer, Operation::Socket(operation), deadline, &Probes)?;
            let now = clock.now();
            let host_remaining = selection.host_deadline.saturating_duration_since(now);
            if host_remaining.is_zero() {
                controller.mark_incomplete(selection.host);
                controller.settle(
                    &mut work,
                    selection,
                    super::super::adaptive::Outcome::Omitted,
                    clock.now(),
                );
                continue;
            }
            if !controller.host_gap_ready(selection.host, now) {
                paced_out = true;
                break;
            }
            let timeout = deadline
                .bounded_timeout(selection.timeout)
                .map_err(|error| Probes.duration_limit(sequence, error))?
                .min(host_remaining);
            selection.host_limited = selection.host_limited || timeout < selection.timeout;
            let admitted = clock.now();
            let scheduled_at = SystemTime::now();
            let pending = match budget.start(
                Arc::clone(provider),
                endpoint,
                &Deadline::new(timeout).with_cancellation(deadline.cancellation().cloned()),
            ) {
                Ok(pending) => pending,
                Err(tcp::Error::Capacity { .. }) => {
                    admission_held = true;
                    break;
                }
                Err(source) => return Err(execution(sequence, source)),
            };
            controller.admitted(&mut work, selection);
            controller.commit_attempt(&mut work, selection, admitted);
            active.push(Active {
                pending,
                sequence,
                stage: stage.stage,
                endpoint,
                scope,
                attempt: selection.attempt,
                started: admitted,
                scheduled_at,
                timeout,
                selection: Some(selection),
            });
            progress.stats.connections_scheduled += 1;
            progress.peak = progress.peak.max(active.len());
            controller.observe_active(active.len());
            progress.next_start = clock
                .now()
                .checked_add(stage.delay)
                .ok_or_else(|| invalid("rate", 0, "pacing deadline overflow"))?;
        }
        if work.done() && active.is_empty() {
            return Ok(());
        }
        let mut wait = Duration::from_millis(1);
        if let Some(ready) = wave.next_ready {
            wait = wait.min(ready.saturating_duration_since(clock.now()));
        }
        if paced_out {
            wait = wait.min(progress.next_start.saturating_duration_since(clock.now()));
        }
        for entry in &active {
            wait = wait.min((entry.started + entry.timeout).saturating_duration_since(clock.now()));
        }
        if admission_held && active.is_empty() && !wave.done {
            wait = wait.max(Duration::from_millis(1));
        }
        if !wait.is_zero() {
            deadline.start_accounting(Duration::ZERO)?;
            clock.sleep(wait, deadline).map_err(|source| Error::Clock {
                sequence: stage.first_sequence,
                source: Box::new(source),
            })?;
        }
    }
}

/// Charges one settled probe to the evidence budget and the statistics, and
/// keeps a discovery outcome for the host records.
fn record(request: &Request, progress: &mut Progress, probe: &ProbeEvidence) -> Result<(), Error> {
    progress.evidence_bytes = progress
        .evidence_bytes
        .checked_add(std::mem::size_of::<ProbeEvidence>())
        .and_then(|bytes| {
            probe.scope.as_ref().map_or(Some(bytes), |scope| {
                bytes
                    .checked_add(scope.zone.as_str().len())
                    .and_then(|bytes| bytes.checked_add(scope.interface.name.len()))
            })
        })
        .and_then(|bytes| {
            bytes.checked_add(
                probe
                    .error
                    .as_ref()
                    .map_or(0, |error| error.to_string().len()),
            )
        })
        .filter(|bytes| *bytes <= request.limits.evidence.max_bytes)
        .ok_or_else(|| {
            invalid(
                "max_evidence_bytes",
                request.limits.evidence.max_bytes,
                "socket evidence budget exceeded",
            )
        })?;
    let stats = &mut progress.stats;
    stats.connections_attempted += u64::from(probe.attempted);
    progress.retries += usize::from(probe.attempted && probe.attempt > 1);
    stats.connections_succeeded += u64::from(probe.connect_succeeded == Some(true));
    if probe.attempted {
        progress.rtt.note_sent();
    }
    if matches!(
        probe.outcome,
        Outcome::Connected | Outcome::Refused | Outcome::Unreachable
    ) {
        progress.rtt.note_received(probe.elapsed);
    }
    if probe.stage == Stage::Discovery {
        // The operating system reports the endpoint's own answer; which
        // device sent it is not observable through a socket.
        let kind = match probe.outcome {
            Outcome::Connected => Some(ReasonKind::Connected),
            Outcome::Refused => Some(ReasonKind::Refused),
            Outcome::TimedOut
            | Outcome::Unreachable
            | Outcome::LocalError
            | Outcome::DeadlineExpired => None,
        };
        progress.discovery.push(Observation {
            sequence: probe.sequence,
            address: probe.endpoint.ip(),
            interface: probe.scope.as_ref().map(|scope| scope.interface.clone()),
            response: kind.map(|kind| (kind, probe.endpoint.ip())),
            observed_at: probe.finished_at.unwrap_or(probe.scheduled_at),
        });
    }
    Ok(())
}

fn finish_probe<S: tcp::Stream>(
    entry: &Active<S>,
    result: tcp::ConnectOutcome<S>,
) -> Result<ProbeEvidence, Error> {
    // Settled attempts keep the worker's completion time; publishing earlier
    // events can delay observation without extending the socket's latency.
    let elapsed = result.elapsed;
    let mut probe = ProbeEvidence {
        sequence: entry.sequence,
        stage: entry.stage,
        endpoint: entry.endpoint,
        scope: entry.scope.clone(),
        attempt: entry.attempt,
        attempted: result.attempted,
        connect_succeeded: Some(result.result.is_ok()),
        outcome: Outcome::LocalError,
        scheduled_at: result.started_at,
        finished_at: Some(result.completed_at),
        elapsed,
        local: None,
        error: None,
    };
    match result.result {
        Ok(stream) => {
            match endpoint_query(entry.sequence, "peer", stream.peer_addr())? {
                Some(peer) if peer != entry.endpoint => {
                    return Err(Error::InvalidEvidence {
                        sequence: entry.sequence,
                        message: "TCP provider returned a different peer endpoint".to_owned(),
                    });
                }
                Some(_) => {
                    probe.local = endpoint_query(entry.sequence, "local", stream.local_addr())?;
                }
                None => {}
            }
            probe.outcome = Outcome::Connected;
            drop(stream);
        }
        Err(error) => {
            let source = socket_error(error);
            probe.outcome = match source.kind() {
                io::ErrorKind::ConnectionRefused => Outcome::Refused,
                io::ErrorKind::TimedOut => Outcome::TimedOut,
                io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
                    Outcome::Unreachable
                }
                _ => Outcome::LocalError,
            };
            probe.error = Some(Arc::new(source));
        }
    }
    if elapsed > entry.timeout {
        probe.outcome = Outcome::DeadlineExpired;
    }
    Ok(probe)
}

/// A peer that reset after the handshake leaves no endpoint to query, but the
/// completed connect is still evidence, so `NotConnected` yields `None`.
fn endpoint_query(
    sequence: u64,
    operation: &'static str,
    result: io::Result<SocketAddr>,
) -> Result<Option<SocketAddr>, Error> {
    match result {
        Ok(endpoint) => Ok(Some(endpoint)),
        Err(source) if source.kind() == io::ErrorKind::NotConnected => Ok(None),
        Err(source) => Err(execution(
            sequence,
            tcp::Error::Evidence { operation, source },
        )),
    }
}

fn socket_error(error: tcp::Error) -> io::Error {
    match error {
        tcp::Error::Socket(source) => source,
        error @ tcp::Error::DeadlineExceeded => io::Error::new(io::ErrorKind::TimedOut, error),
        error @ tcp::Error::Cancelled(_) => io::Error::new(io::ErrorKind::Interrupted, error),
        error => io::Error::other(error),
    }
}
