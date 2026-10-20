// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod feed;

use packetcraftr_core::budget::Deadline;

use crate::clock::Clock;
use crate::probe::Batch;
use crate::probe::runner::BatchEvidence;
use crate::target::SelectedAddress;

use super::approval::Approved;
use super::pacing::{Owed, settle};
use super::pipelined::{add_stats, pipeline_options, prepared_limit};
use crate::probe::{self, enforce_deadline};
use crate::scan::Error;
use crate::scan::error::probe_error;
use crate::scan::evidence::ProbeClassifier;
use crate::scan::executor::Pipelined;
use crate::scan::plan::{Stage, probe_count};
use crate::scan::{Event, Probe, Request};

pub(in crate::scan) fn adaptive_batches<'r>(
    request: &'r Request,
    targets: &'r [SelectedAddress],
    endpoints: &'r [probe::Endpoint],
    stage: Stage,
    first_sequence: u64,
) -> impl Iterator<Item = Batch<Probe>> + 'r {
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
                let sequence = crate::scan::plan::sequence(
                    first_sequence,
                    attempt,
                    endpoint_index,
                    endpoints.len(),
                    host_index,
                    targets.len(),
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
        request
            .max_in_flight
            .min(targets.len().saturating_mul(endpoints_per_host)),
        crate::scan::adaptive::scoped_bytes(targets),
        shared,
    )
}

pub(super) fn check_adaptive_prepared(
    request: &Request,
    reservation: usize,
    window: usize,
) -> Result<(), Error> {
    let wave = window.saturating_mul(
        std::mem::size_of::<Batch<Probe>>().saturating_add(std::mem::size_of::<Probe>()),
    );
    if reservation.saturating_add(wave) > request.limits.max_prepared_bytes {
        return Err(prepared_limit(request));
    }
    Ok(())
}

pub(super) fn admit_adaptive<E: Pipelined>(
    request: &Request,
    executor: &mut E,
    deadline: &Deadline,
    approved: &Approved,
    reservation: usize,
) -> Result<[crate::scan::executor::AdaptiveAdmission; 2], Error> {
    let discovery = if request.discovery.runs() {
        request.discovery.probes.as_slice()
    } else {
        &[]
    };
    let mut summaries = [
        crate::scan::executor::AdaptiveAdmission::new(0),
        crate::scan::executor::AdaptiveAdmission::new(0),
    ];
    for (stage_index, (endpoints, stage, first_sequence)) in [
        (discovery, Stage::Discovery, 0u64),
        (
            approved.endpoints.as_slice(),
            Stage::Scan,
            probe_count(approved.targets.len(), discovery.len(), request.attempts)? as u64,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        if approved.targets.is_empty() || endpoints.is_empty() {
            continue;
        }
        let wave_len = request
            .max_in_flight
            .min(approved.targets.len().saturating_mul(endpoints.len()))
            .max(1);
        let mut admission = crate::scan::executor::AdaptiveAdmission::new(wave_len);
        // Admission does not need an acquisition group. Inspect a bounded
        // source-sized chunk even when the requested execution window is larger.
        let admission_chunk = wave_len.min(packetcraftr_netio::capture::MAX_SOURCES);
        let previous_summaries = summaries.iter().fold(0usize, |bytes, summary| {
            bytes.saturating_add(summary.retained_bytes())
        });
        check_adaptive_prepared(
            request,
            reservation.saturating_add(previous_summaries),
            admission_chunk,
        )?;
        let mut admit =
            |batches: &[Batch<Probe>], summary: &mut crate::scan::executor::AdaptiveAdmission| {
                let held = reservation
                    .saturating_add(previous_summaries)
                    .saturating_add(summary.retained_bytes());
                let options = pipeline_options(request, deadline, crate::Stats::default(), held)?;
                executor
                    .admit_adaptive_pipeline(batches, &options, summary)
                    .map_err(|source| Error::PipelineExecution { source })
            };
        let mut batches = Vec::with_capacity(admission_chunk);
        for batch in adaptive_batches(request, &approved.targets, endpoints, stage, first_sequence)
        {
            batches.push(batch);
            if batches.len() == admission_chunk {
                admit(&batches, &mut admission)?;
                batches.clear();
            }
        }
        if !batches.is_empty() {
            admit(&batches, &mut admission)?;
        }
        summaries[stage_index] = admission;
    }
    let summary_bytes = summaries.iter().fold(0usize, |bytes, summary| {
        bytes.saturating_add(summary.retained_bytes())
    });
    let options = pipeline_options(request, deadline, crate::Stats::default(), reservation)?;
    for summary in &mut summaries {
        summary.reserve_summaries(summary_bytes);
        summary
            .check(request.max_in_flight, approved.targets.len(), &options)
            .map_err(|source| Error::PipelineExecution { source })?;
    }
    Ok(summaries)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute_adaptive<E, C, F>(
    request: &Request,
    executor: &mut E,
    clock: &mut C,
    deadline: &mut Deadline,
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Error>,
    controller: &mut crate::scan::adaptive::Controller,
    stage: Stage,
    targets: &[SelectedAddress],
    endpoints: &[probe::Endpoint],
    first_sequence: u64,
    owed: &mut Owed,
    reservation: usize,
    admission: &crate::scan::executor::AdaptiveAdmission,
    preceding: &crate::Stats,
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
    enforce_deadline(probe_error, deadline)?;
    settle(request, clock, deadline, owed, &mut stats)?;
    let mut prefix = preceding.clone();
    add_stats(&mut prefix, &stats, first_sequence)?;
    let mut options = pipeline_options(request, deadline, prefix, reservation)?;
    options.max_in_flight = options
        .max_in_flight
        .min(targets.len().saturating_mul(endpoints.len()))
        .max(1);
    let attempts = probe_count(targets.len(), endpoints.len(), request.attempts)?;
    let mut feed = feed::Feed::new(
        request,
        feed::StageInput {
            targets,
            endpoints,
            stage,
            first_sequence,
        },
        deadline,
        clock,
        evidence,
        controller,
    );
    let result = executor
        .execute_stream(options, admission, attempts, &mut feed)
        .map_err(|source| Error::PipelineExecution { source })?;
    if !feed.settled()
        || result.packets_attempted != feed.confirmed.packets_attempted
        || result.packets_completed != feed.confirmed.packets_completed
        || result.bytes != feed.confirmed.bytes
    {
        return Err(Error::InvalidEvidence { sequence: first_sequence,
            message: "continuous pipeline left an attempt unsettled or returned incoherent send statistics".to_owned() });
    }
    let last_sent = feed.last_sent;
    drop(feed);
    if result.packets_attempted > 0 {
        owed.owe(1, last_sent);
    }
    add_stats(&mut stats, &result, first_sequence)?;
    Ok(stats)
}

pub(super) fn take_feedback<F>(
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Error>,
) -> Vec<crate::scan::evidence::Feedback>
where
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    match &mut evidence.classifier_mut().feedback {
        Some((feedback, _)) => std::mem::take(feedback),
        None => Vec::new(),
    }
}
