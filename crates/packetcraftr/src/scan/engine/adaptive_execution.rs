// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::budget::Deadline;

use crate::clock::Clock;
use crate::execution::Errors as _;
use crate::execution::pause;
use crate::probe::Batch;
use crate::probe::runner::BatchEvidence;
use crate::target::SelectedAddress;

use super::approval::ApprovedScan;
use super::pacing::{Owed, settle};
use super::pipelined::{add_stats, drive_pipeline, pipeline_options};
use crate::probe::{ProbeEndpoint, enforce_deadline};
use crate::scan::Error;
use crate::scan::error::Probes;
use crate::scan::evidence::ProbeClassifier;
use crate::scan::executor::Pipelined;
use crate::scan::plan::{Stage, probe_count};
use crate::scan::{Event, Probe, Request};

pub(in crate::scan) fn adaptive_batches<'r>(
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
                    crate::scan::plan::planned_probe(
                        request, sequence, stage, target, endpoint, attempt,
                    ),
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
    crate::scan::adaptive::state_charge(
        targets.len(),
        endpoints_per_host,
        request.max_in_flight,
        crate::scan::adaptive::scoped_bytes(targets),
        shared,
    )
}

pub(super) fn check_adaptive_prepared(request: &Request, reservation: usize) -> Result<(), Error> {
    let wave = request.max_in_flight.saturating_mul(
        std::mem::size_of::<Batch<Probe>>().saturating_add(std::mem::size_of::<Probe>()),
    );
    if reservation.saturating_add(wave) > request.limits.max_prepared_bytes {
        return Err(Error::PipelineExecution {
            source: crate::scan::executor::limit(
                "prepared descriptions",
                request.limits.max_prepared_bytes,
            ),
        });
    }
    Ok(())
}

pub(super) fn admit_adaptive<E: Pipelined>(
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
        let mut admission = crate::scan::executor::AdaptiveAdmission::new(wave_len);
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
pub(super) fn execute_adaptive<E, C, F>(
    request: &Request,
    executor: &mut E,
    clock: &mut C,
    deadline: &mut Deadline,
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Probes>,
    controller: &mut crate::scan::adaptive::Controller,
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
                crate::scan::plan::planned_probe(
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
        let mut replies: std::collections::HashMap<u64, crate::scan::evidence::Feedback> =
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
                    crate::scan::adaptive::Outcome::Omitted,
                    settled_at,
                );
                continue;
            }
            let outcome = match replies.get(&selection.sequence) {
                Some(feedback) => crate::scan::adaptive::Outcome::Reply {
                    latency: feedback.latency,
                    responder: feedback.responder,
                    control: matches!(
                        feedback.reply,
                        crate::scan::Reply::IcmpPortUnreachable
                            | crate::scan::Reply::IcmpDestinationUnreachable
                            | crate::scan::Reply::TcpReset
                    ),
                },
                None => crate::scan::adaptive::Outcome::Silent,
            };
            controller.settle(&mut work, selection, outcome, settled_at);
        }
        evidence.release_responses(controller.take_canceled_responses(&mut work));
    }
    Ok(stats)
}

pub(super) fn take_feedback<F>(
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Probes>,
) -> Vec<crate::scan::evidence::Feedback>
where
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    match &mut evidence.classifier_mut().feedback {
        Some((feedback, _)) => std::mem::take(feedback),
        None => Vec::new(),
    }
}
