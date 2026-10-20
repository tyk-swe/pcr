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
use self::pacing::{Owed, settle};
use self::pipelined::{StagePlan, add_stats, admit_pipelined, execute};

pub(crate) use self::adaptive_execution::adaptive_reservation;

use std::collections::HashMap;
use std::sync::Arc;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::registry::Registry;

use crate::clock::Clock;
use crate::execution::publisher;
use crate::policy::Authorizer;
use crate::probe::runner::BatchEvidence;
use crate::providers::{PacketProviders, TargetProviders};
use crate::target::ResolveTarget;
use crate::{Client, Sink};

use super::Error;
use super::WORKFLOW;
use super::adaptive::{Ceilings, Controller};
use super::discovery::{self, Composer};
use super::error::{duration_limit, probe_error};
use super::evidence::ProbeClassifier;
use super::executor::{AdaptiveAdmission, ClientExecutor, Pipelined};
use super::plan::{Stage, probe_count};
use super::report::RttAccumulator;
use super::{ClassificationCounts, Event, Report, Request, Scheduling};
use crate::probe::enforce_deadline;

impl<P: PacketProviders + TargetProviders, K: Clock> Client<P, K> {
    /// Scans the request's authorized targets and publishes each probe's
    /// final outcome, each retained undecoded frame, and each diagnostic to
    /// `sink`. When `max_in_flight` exceeds one, each probe's confirmed send
    /// is also published as [`Event::Sent`] before its outcome.
    pub fn scan<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let operation = crate::execution::Operation::new(self, request.limits.max_duration);
        self.scan_in(request, sink, &operation)
    }

    pub(crate) fn scan_in<S>(
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
        let publish = publisher(
            &operation.runtime,
            sink,
            |error| duration_limit(0_u64, error),
            |source| Error::Output { source },
        )?;
        run(
            &request,
            &mut admission,
            &operation.registry,
            &mut ClientExecutor::new(self, &request, operation),
            &mut self.clock.clone(),
            &mut operation.deadline(self, request.limits.max_duration),
            publish,
        )
    }
}

#[allow(clippy::large_enum_variant)]
enum Scheduler {
    Fixed {
        peak: usize,
    },
    Adaptive {
        controller: Controller,
        reservation: usize,
        admissions: [AdaptiveAdmission; 2],
    },
}

impl Scheduler {
    fn controller(&self) -> Option<&Controller> {
        match self {
            Self::Fixed { .. } => None,
            Self::Adaptive { controller, .. } => Some(controller),
        }
    }

    fn controller_mut(&mut self) -> Option<&mut Controller> {
        match self {
            Self::Fixed { .. } => None,
            Self::Adaptive { controller, .. } => Some(controller),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_stage<E, C, F>(
        &mut self,
        request: &Request,
        executor: &mut E,
        clock: &mut C,
        deadline: &mut Deadline,
        evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Error>,
        owed: &mut Owed,
        plan: &StagePlan<'_>,
        preceding: &crate::Stats,
    ) -> Result<crate::Stats, Error>
    where
        E: Pipelined,
        C: Clock,
        F: FnMut(Event, &Deadline) -> Result<(), Error>,
    {
        match self {
            Self::Fixed { peak } => execute(
                request, executor, clock, deadline, evidence, plan, preceding, peak,
            ),
            Self::Adaptive {
                controller,
                reservation,
                admissions,
            } => {
                let admission = match plan.stage {
                    Stage::Discovery => &admissions[0],
                    Stage::Scan => &admissions[1],
                };
                execute_adaptive(
                    request,
                    executor,
                    clock,
                    deadline,
                    evidence,
                    controller,
                    plan.stage,
                    plan.targets,
                    plan.endpoints,
                    plan.first_sequence,
                    owed,
                    *reservation,
                    admission,
                    preceding,
                )
            }
        }
    }

    fn finish(self, retries_started: usize) -> Scheduling {
        match self {
            Self::Fixed { peak } => {
                super::adaptive::fixed_scheduling(Ceilings::default(), peak, retries_started)
            }
            Self::Adaptive { controller, .. } => controller.finish(Ceilings::default()),
        }
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
    enforce_deadline(probe_error, deadline)?;
    let approved = approve(request, authorizer, deadline)?;
    let options = &request.discovery;
    executor.resolves_neighbors(approved.resolves_neighbors);
    enforce_deadline(probe_error, deadline)?;
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
            Scheduler::Adaptive {
                controller,
                reservation,
                admissions,
            }
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
    let mut evidence = BatchEvidence::new(
        WORKFLOW,
        probe_error,
        request.limits.evidence,
        ProbeClassifier {
            observation_quality: None,
            registry,
            target: Arc::from(approved.declared_target.as_str()),
            winners: HashMap::new(),
            rtt: RttAccumulator::default(),
            discovery: Vec::new(),
            feedback: scheduler
                .controller()
                .map(|_| (Vec::new(), request.max_in_flight)),
            adaptive_attempts: scheduler.controller().map(|_| request.attempts),
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
                scheduler.controller_mut(),
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
                    scheduler.controller_mut(),
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
        scan_sequence = if scheduler.controller().is_some() {
            probe_count(
                approved.targets.len(),
                options.probes.len(),
                request.attempts,
            )? as u64
        } else {
            discovery_probes
        };
        // probe_error skipped after a silent neighbor or next hop hold no
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
        let discovered = scheduler.execute_stage(
            request,
            executor,
            clock,
            deadline,
            &mut evidence,
            &mut owed,
            &discovery,
            &stats,
        )?;
        add_stats(&mut stats, &discovered, scan_sequence)?;
        composer.observe_all(evidence.classifier_mut().discovery.drain(..))?;
        if discovered.packets_attempted > 0 {
            // When the stage's last probe left is not known on the operation's
            // clock, so its whole pause stays owed.
            owed.owe(1, None);
        }
    }
    if let Some(controller) = scheduler.controller() {
        for index in controller.incomplete_targets(&approved.targets) {
            composer.incomplete(index);
        }
    }
    let mut hosts = composer.finish();
    let scanned = discovery::scanned(&approved.targets, &hosts);
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
                scheduler.controller_mut(),
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
    let scanned = scheduler.execute_stage(
        request,
        executor,
        clock,
        deadline,
        &mut evidence,
        &mut owed,
        &scan,
        &stats,
    )?;
    add_stats(
        &mut stats,
        &scanned,
        scan_sequence.saturating_add(scan_probes),
    )?;
    if let Some(controller) = scheduler.controller() {
        for index in controller.incomplete_targets(&approved.targets) {
            hosts[index].scan = discovery::Scan::Incomplete;
        }
    }
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
