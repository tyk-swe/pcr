// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod adaptive_execution;
mod approval;
mod neighbors;
mod pacing;
mod pipelined;

use self::adaptive_execution::{admit_adaptive, execute_adaptive};
use self::approval::approve;
use self::neighbors::{ReachOutcome, discover_neighbors, reach_next_hop};
use self::pacing::Owed;
use self::pipelined::{StagePlan, add_stats, admit_pipelined, execute};

pub(crate) use self::adaptive_execution::adaptive_reservation;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use packetcraftr_core::budget::Deadline;

use crate::clock::Clock;
use crate::engine::execution::publisher;
use crate::engine::operation::{Workflow, WorkflowSetup};
use crate::policy::Authorizer;
use crate::probe::runner::BatchEvidence;
use crate::providers::{PacketProviders, TargetProviders};
use crate::target::{ResolveTarget, SelectedAddress};
use crate::{Client, Sink};

use super::Error;
use super::WORKFLOW;
use super::adaptive::{Ceilings, Controller};
use super::discovery::Sweep;
use super::error::duration_limit;
use super::evidence::ProbeClassifier;
use super::executor::{AdaptiveAdmission, ClientExecutor, Pipelined};
use super::plan::probe_count;
use super::report::RttAccumulator;
use super::{ClassificationCounts, Event, Report, Request, Scheduling};
use crate::probe::Stage;
use crate::probe::enforce_deadline;

#[cfg(test)]
#[path = "engine/tests.rs"]
mod tests;

impl<P: PacketProviders + TargetProviders, K: Clock> Client<P, K> {
    /// Scans the request's authorized targets and publishes each probe's
    /// final outcome, each retained undecoded frame, and each diagnostic to
    /// `sink`. When `max_in_flight` exceeds one, each probe's confirmed send
    /// is also published as [`Event::Sent`] before its outcome.
    pub fn scan<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let operation = crate::engine::operation::Operation::new(self, request.limits.max_duration);
        self.scan_in(request, sink, &operation)
    }

    pub(crate) fn scan_in<S>(
        &self,
        request: Request,
        sink: S,
        operation: &crate::engine::operation::Operation,
    ) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let setup = WorkflowSetup::new(self, operation);
        let publish = publisher(
            &operation.runtime,
            sink,
            |error| duration_limit(0_u64, error),
            |source| Error::Output { source },
        )?;
        let mut executor = ClientExecutor::new(self, &request, operation);
        run(
            &request,
            &mut setup.start(self, request.limits.max_duration),
            &mut executor,
            publish,
        )
    }
}

/// What sends one raw scan's probes and neighbor requests: the request, its
/// executor, the operation's clock and deadline, and the rate pause its
/// transmissions still owe.
struct Prober<'a, E, C> {
    request: &'a Request,
    executor: &'a mut E,
    clock: &'a mut C,
    deadline: &'a mut Deadline,
    /// Transmissions whose rate pause is still owed, waited out just before
    /// the next one so the operation's last transmission leaves no pause.
    owed: Owed,
}

enum Scheduler {
    Fixed {
        peak: usize,
    },
    /// Boxed: the controller's state dwarfs the fixed peak counter.
    Adaptive(Box<AdaptiveScheduler>),
}

struct AdaptiveScheduler {
    controller: Controller,
    reservation: usize,
    /// The discovery and scan stages' admissions, in that order.
    admissions: [AdaptiveAdmission; 2],
}

impl Scheduler {
    fn controller(&self) -> Option<&Controller> {
        match self {
            Self::Fixed { .. } => None,
            Self::Adaptive(adaptive) => Some(&adaptive.controller),
        }
    }

    fn is_adaptive(&self) -> bool {
        matches!(self, Self::Adaptive(_))
    }

    fn host_index(&mut self, target: &SelectedAddress) -> Option<usize> {
        match self {
            Self::Fixed { .. } => None,
            Self::Adaptive(adaptive) => Some(adaptive.controller.host_index(target)),
        }
    }

    fn host_started(&mut self, host: Option<usize>, now: Instant) {
        if let (Self::Adaptive(adaptive), Some(host)) = (self, host) {
            adaptive.controller.host_started(host, now);
        }
    }

    fn host_expired(&mut self, host: Option<usize>, now: Instant) -> bool {
        let (Self::Adaptive(adaptive), Some(host)) = (self, host) else {
            return false;
        };
        if !adaptive.controller.host_expired(host, now) {
            return false;
        }
        adaptive.controller.mark_incomplete(host);
        true
    }

    fn host_remaining(&self, host: Option<usize>, now: Instant) -> Option<Duration> {
        let (Self::Adaptive(adaptive), Some(host)) = (self, host) else {
            return None;
        };
        Some(adaptive.controller.host_remaining(host, now))
    }

    fn execute_stage<E, C, F>(
        &mut self,
        prober: &mut Prober<'_, E, C>,
        evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Error>,
        plan: &StagePlan<'_>,
        preceding: &crate::Stats,
    ) -> Result<crate::Stats, Error>
    where
        E: Pipelined,
        C: Clock,
        F: FnMut(Event, &Deadline) -> Result<(), Error>,
    {
        match self {
            Self::Fixed { peak } => execute(prober, evidence, plan, preceding, peak),
            Self::Adaptive(adaptive) => {
                let AdaptiveScheduler {
                    controller,
                    reservation,
                    admissions,
                } = &mut **adaptive;
                let admission = match plan.stage {
                    Stage::Discovery => &admissions[0],
                    Stage::Scan => &admissions[1],
                };
                execute_adaptive(
                    prober,
                    evidence,
                    plan,
                    preceding,
                    controller,
                    *reservation,
                    admission,
                )
            }
        }
    }

    fn finish(self, retries_started: usize) -> Scheduling {
        match self {
            Self::Fixed { peak } => {
                super::adaptive::fixed_scheduling(Ceilings::default(), peak, retries_started)
            }
            Self::Adaptive(adaptive) => adaptive.controller.finish(Ceilings::default()),
        }
    }
}

pub(crate) fn run<A, E, C, F>(
    request: &Request,
    workflow: &mut Workflow<A, C>,
    executor: &mut E,
    mut emit: F,
) -> Result<Report, Error>
where
    A: Authorizer + ResolveTarget,
    E: Pipelined,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    let Workflow {
        authorizer,
        registry,
        clock,
        deadline,
    } = workflow;
    enforce_deadline::<Error>(deadline)?;
    let approved = approve(request, authorizer, deadline)?;
    let options = &request.discovery;
    executor.resolves_neighbors(approved.resolves_neighbors);
    enforce_deadline::<Error>(deadline)?;
    let mut scheduler = match request.adaptive {
        Some(config) => {
            let mut controller = Controller::new(config, request.timeout, request.max_in_flight);
            let reservation = adaptive_reservation(
                request,
                &approved.targets,
                options.probes.len().max(approved.endpoints.len()),
            );
            let admissions = admit_adaptive(request, executor, deadline, &approved, reservation)?;
            for target in &approved.targets {
                controller.host_index(target);
            }
            Scheduler::Adaptive(Box::new(AdaptiveScheduler {
                controller,
                reservation,
                admissions,
            }))
        }
        None => {
            if request.max_in_flight > 1 || request.has_ip_probes() {
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
            Scheduler::Fixed { peak: 0 }
        }
    };
    let mut retries_started = 0usize;
    let mut emit = |event: Event, deadline: &Deadline| {
        if let Event::Probe { probe, .. } = &event
            && probe.attempt > 1
        {
            retries_started = retries_started.saturating_add(1);
        }
        emit(event, deadline)
    };
    let mut evidence = BatchEvidence::new_with_retention_limits(
        WORKFLOW,
        request.limits.evidence,
        request.limits.evidence,
        ProbeClassifier {
            observation_quality: None,
            registry,
            target: Arc::from(approved.declared_target.as_str()),
            winners: HashMap::new(),
            rtt: RttAccumulator::default(),
            discovery: Vec::new(),
            feedback: scheduler
                .is_adaptive()
                .then(|| (Vec::new(), request.max_in_flight)),
            adaptive_attempts: scheduler.is_adaptive().then_some(request.attempts),
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
    let mut sweep = Sweep::new(&approved.targets, options.mode, options.unresponsive);
    let mut stats = crate::Stats::default();
    let mut prober = Prober {
        request,
        executor,
        clock,
        deadline,
        owed: Owed::default(),
    };
    let mut scan_sequence = 0;
    if options.runs() {
        let mut sendable = vec![true; approved.targets.len()];
        if options.neighbor {
            sendable = discover_neighbors(
                &mut prober,
                &approved.targets,
                sweep.composer_mut(),
                &mut stats,
                &mut scheduler,
            )?;
        }
        if !options.probes.is_empty() {
            for (index, target) in approved.targets.iter().enumerate() {
                if !sendable[index] {
                    continue;
                }
                match reach_next_hop(&mut prober, target, &mut stats, 0, &mut scheduler)? {
                    ReachOutcome::Resolved => {}
                    ReachOutcome::Silent(_) => {
                        sendable[index] = false;
                        sweep.unreachable(index);
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
        scan_sequence = if scheduler.is_adaptive() {
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
            prober.settle(&mut stats)?;
        }
        let discovered = scheduler.execute_stage(&mut prober, &mut evidence, &discovery, &stats)?;
        add_stats(&mut stats, &discovered, scan_sequence)?;
        sweep.observe_all(evidence.classifier_mut().discovery.drain(..))?;
        if discovered.packets_attempted > 0 {
            // When the stage's last probe left is not known on the operation's
            // clock, so its whole pause stays owed.
            prober.owed.owe(1, None);
        }
    }
    let discovered = sweep.finish_discovery(scheduler.controller());
    let scanned = discovered.scan_targets();
    if !approved.endpoints.is_empty() {
        for target in &scanned {
            // Discovery answers for a target it reached; without it, a
            // scan target no frame can reach fails the scan.
            match reach_next_hop(
                &mut prober,
                target,
                &mut stats,
                scan_sequence,
                &mut scheduler,
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
        prober.settle(&mut stats)?;
    }
    let scanned = scheduler.execute_stage(&mut prober, &mut evidence, &scan, &stats)?;
    add_stats(
        &mut stats,
        &scanned,
        scan_sequence.saturating_add(scan_probes),
    )?;
    let hosts = discovered.finish_scan(scheduler.controller());
    let retained_evidence_bytes = evidence.retained_evidence_bytes();
    let ProbeClassifier { winners, rtt, .. } = evidence.into_classifier();
    let mut counts = ClassificationCounts::default();
    for classification in winners.into_values() {
        counts.increment(classification);
    }

    let resolved_addresses = approved.addresses();
    let scheduling = scheduler.finish(retries_started);
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
