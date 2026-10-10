// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod adaptive_execution;
mod approval;
mod neighbors;
mod pacing;
mod pipelined;

use self::adaptive_execution::{admit_adaptive, execute_adaptive};
use self::approval::approve_scan;
use self::neighbors::{ReachOutcome, discover_neighbors, reach_next_hop};
use self::pacing::{Owed, settle};
use self::pipelined::{StagePlan, add_stats, admit_pipelined, execute};

#[cfg(test)]
pub(super) use self::adaptive_execution::adaptive_batches;
pub(crate) use self::adaptive_execution::adaptive_reservation;

use std::collections::HashMap;
use std::sync::Arc;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::registry::Registry;

use crate::clock::Clock;
use crate::execution::Errors as _;
use crate::execution::publisher;
use crate::policy::Authorizer;
use crate::probe::runner::BatchEvidence;
use crate::providers::{PacketProviders, TargetProviders};
use crate::target::ResolveTarget;
use crate::{Client, Sink};

use super::Error;
use super::WORKFLOW;
use super::discovery::{self, Composer};
use super::error::Probes;
use super::evidence::ProbeClassifier;
use super::executor::{ClientExecutor, Pipelined};
use super::plan::{Stage, probe_count};
use super::report::RttAccumulator;
use super::{ClassificationCounts, Event, Report, Request};
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
        request.limits.evidence,
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
