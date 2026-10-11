// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Instant;

use packetcraftr_core::budget::Deadline;

use crate::clock::Clock;
use crate::execution::Errors as _;
use crate::probe::Batch;
use crate::probe::runner::{BatchEvidence, run_batches};
use crate::target::SelectedAddress;

use crate::probe::{ProbeEndpoint, enforce_deadline};
use crate::scan::Error;
use crate::scan::error::Probes;
use crate::scan::evidence::ProbeClassifier;
use crate::scan::executor::{PipelineEvent, PipelineOptions, Pipelined};
use crate::scan::plan::packet::sent_probe_matches;
use crate::scan::plan::{Stage, build_batches, probe_count};
use crate::scan::{Event, Probe, Request};

/// One stage's probes: every endpoint on every target, attempt by attempt,
/// numbered from `first_sequence`.
pub(super) struct StagePlan<'a> {
    pub(super) targets: &'a [SelectedAddress],
    pub(super) endpoints: &'a [ProbeEndpoint],
    pub(super) stage: Stage,
    pub(super) first_sequence: u64,
}

impl StagePlan<'_> {
    pub(super) fn probes(&self, request: &Request) -> Result<u64, Error> {
        probe_count(self.targets.len(), self.endpoints.len(), request.attempts)
            .map(|count| count as u64)
    }

    pub(super) fn batches<'r>(
        &self,
        request: &'r Request,
    ) -> impl Iterator<Item = Batch<Probe>> + 'r
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
pub(super) fn execute<E, C, F>(
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

pub(super) fn add_stats(
    total: &mut crate::Stats,
    stage: &crate::Stats,
    sequence: u64,
) -> Result<(), Error> {
    total
        .checked_add_assign(stage)
        .map_err(|_| Error::StatisticsOverflow { sequence })
}

/// Rejects a pipelined stage over its preparation limit without sending
/// anything: first by its batch descriptions, before they are built, then
/// by the pipeline's own admission of its probes.
pub(super) fn admit_pipelined<E: Pipelined>(
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

pub(super) fn pipeline_options(
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
        max_evidence_frames: request.limits.evidence.max_frames,
        max_evidence_bytes: request.limits.evidence.max_bytes,
        host_deadlines: Vec::new(),
        preceding,
    })
}

/// Rejects a pipelined stage whose batch descriptions for `targets` would
/// exceed the preparation limit.
pub(super) fn check_prepared_descriptions(
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
            source: crate::scan::executor::limit(
                "prepared descriptions",
                request.limits.max_prepared_bytes,
            ),
        });
    }
    Ok(())
}

pub(super) struct WaveOutcome {
    pub(super) stats: crate::Stats,
    pub(super) confirmed: Vec<bool>,
    pub(super) completed: Vec<bool>,
    pub(super) omitted: Vec<bool>,
    pub(super) sent_at: Vec<Option<Instant>>,
    pub(super) observed_at: Vec<Option<Instant>>,
    pub(super) sent_bytes: u64,
    pub(super) peak_pending: usize,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn drive_pipeline<E, C, F>(
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
                        Event::Sent(crate::scan::SentProbe {
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
                        Event::Unattributed(crate::scan::Unattributed {
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

pub(super) fn run_pipelined<E, C, F>(
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
