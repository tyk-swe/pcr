// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::tcp::{self, Provider};

use super::super::adaptive::Ceilings;
use super::super::discovery::{Composer, Scan};
use super::super::error::{duration_limit, probe_error};
use super::super::report::RttAccumulator;
use super::super::{Error, Request, Stage};
use super::accounting::{Progress, record};
use super::attempts::{Active, admit_next, connect_outcome, settle_active};
use super::planning::{StagePlan, planned};
use super::{Event, ProbeEvidence, Report, Stats, execution, invalid};
use crate::clock::Clock;
use crate::policy::{Authorizer, Operation, SocketOperation};
use crate::probe::enforce_deadline;
use crate::providers::{TargetProviders, TcpOf, TcpProviders};
use crate::target::{ResolveTarget, approve_operation};
use crate::{Client, Sink};

impl<P: TargetProviders + TcpProviders, K: Clock> Client<P, K> {
    /// Scans the request's targets and ports with kernel TCP connects
    /// through the client's TCP provider, keeping at most `max_in_flight`
    /// attempts pending at once.
    pub fn scan_connect<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let operation = crate::execution::Operation::new(self, request.limits.max_duration);
        self.scan_connect_in(request, sink, &operation)
    }

    pub(crate) fn scan_connect_in<S>(
        &self,
        request: Request,
        sink: S,
        operation: &crate::execution::Operation,
    ) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let policy = operation.policy(&self.policy);
        let mut admission = crate::execution::Admission::new(&policy, self.providers.resolver());
        let started = self.now();
        let mut deadline = operation.deadline(self, request.limits.max_duration);
        let mut publish =
            crate::execution::publisher(&operation.runtime, sink, Error::from, |source| {
                Error::Output { source }
            })?;
        run(
            &request,
            &mut admission,
            &Arc::new(TcpOf(Arc::clone(&self.providers))),
            &self.clock,
            &mut deadline,
            started,
            |probe, deadline| publish(Event::Probe(probe), deadline),
        )
    }
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
    enforce_deadline(probe_error, deadline)?;
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
    enforce_deadline(probe_error, deadline)?;
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
    let ceilings = Ceilings {
        operation: Some(budget.capacity()),
        process: Some(tcp::MAX_PENDING_CONNECTIONS),
    };
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
        enforce_deadline(probe_error, deadline)?;
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
            enforce_deadline(probe_error, deadline)?;
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
        enforce_deadline(probe_error, deadline)?;
        let mut index = 0;
        let mut settled = Vec::new();
        while index < active.len() {
            enforce_deadline(probe_error, deadline)?;
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
            .map_err(|error| duration_limit(0_u64, error))?;
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
            approve_operation(
                authorizer,
                Operation::Socket(operation),
                deadline,
                probe_error,
            )?;
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
                .map_err(|error| duration_limit(sequence, error))?
                .min(host_remaining);
            selection.host_limited = selection.host_limited || timeout < selection.timeout;
            let admitted = clock.now();
            let scheduled_at = SystemTime::now();
            let pending =
                match budget.start(Arc::clone(provider), endpoint, &deadline.for_wait(timeout)?) {
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
