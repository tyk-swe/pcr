// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::Deadline;

use crate::clock::Clock;
use crate::probe::Batch;
use crate::probe::runner::{BatchEvidence, run_batches};
use crate::target::SelectedAddress;

use crate::probe::{self, enforce_deadline};
use crate::scan::Error;
use crate::scan::error::{duration_limit, probe_error};
use crate::scan::evidence::ProbeClassifier;
use crate::scan::executor::{PipelineEvent, PipelineOptions, Pipelined};
use crate::scan::plan::packet::sent_probe_matches;
use crate::scan::plan::{Stage, build_batches, probe_count};
use crate::scan::{Event, Probe, Request};

/// One stage's probes: every endpoint on every target, attempt by attempt,
/// numbered from `first_sequence`.
pub(super) struct StagePlan<'a> {
    pub(super) targets: &'a [SelectedAddress],
    pub(super) endpoints: &'a [probe::Endpoint],
    pub(super) stage: Stage,
    pub(super) first_sequence: u64,
}

impl StagePlan<'_> {
    fn uses_pipeline(&self, request: &Request) -> bool {
        request.max_in_flight > 1
            || self
                .endpoints
                .iter()
                .any(|endpoint| matches!(endpoint, probe::Endpoint::Ip { .. }))
    }
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
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Error>,
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
    enforce_deadline(probe_error, deadline)?;
    if !plan.uses_pipeline(request) {
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
    if !plan.uses_pipeline(request) {
        return Ok(());
    }
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
        control: deadline.clone(),
        max_in_flight: request.max_in_flight,
        probes_per_second: request.probes_per_second,
        max_duration: deadline
            .remaining()
            .map_err(|error| duration_limit(0_u64, error))?,
        max_prepared_bytes: request.limits.max_prepared_bytes.saturating_sub(reserved),
        max_evidence_frames: request.limits.evidence.max_frames,
        max_evidence_bytes: request.limits.evidence.max_bytes,
        preceding,
    })
}

pub(super) fn prepared_limit(request: &Request) -> Error {
    Error::PipelineExecution {
        source: crate::scan::executor::limit(
            "prepared descriptions",
            request.limits.max_prepared_bytes,
        ),
    }
}

/// Rejects a pipelined stage whose batch descriptions for `targets` would
/// exceed the preparation limit.
pub(super) fn check_prepared_descriptions(
    request: &Request,
    targets: &[SelectedAddress],
    endpoints: &[probe::Endpoint],
) -> Result<(), Error> {
    let probes_per_target = endpoints.len().saturating_mul(request.attempts as usize);
    let batch_bytes = targets.iter().fold(0usize, |bytes, target| {
        bytes.saturating_add(
            (std::mem::size_of::<Batch<Probe>>() + std::mem::size_of::<Probe>())
                .saturating_add(target.scope_bytes())
                .saturating_mul(probes_per_target),
        )
    });
    if batch_bytes > request.limits.max_prepared_bytes {
        return Err(prepared_limit(request));
    }
    Ok(())
}

pub(super) struct PipelineOutcome {
    pub(super) stats: crate::Stats,
    pub(super) completed: Vec<bool>,
    pub(super) sent_bytes: u64,
    pub(super) peak_pending: usize,
}

#[allow(clippy::too_many_arguments)]
fn drive_pipeline<E, F>(
    request: &Request,
    executor: &mut E,
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Error>,
    deadline: &Deadline,
    batches: &[Batch<Probe>],
    preceding: crate::Stats,
) -> Result<PipelineOutcome, Error>
where
    E: Pipelined,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    let mut completed = vec![false; batches.len()];
    let mut confirmed = vec![false; batches.len()];
    let mut pending_now = 0usize;
    let mut peak_pending = 0usize;
    let mut sent_bytes = 0u64;
    let settings = pipeline_options(request, deadline, preceding, 0)?;
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
                if confirmed[index] || !sent_probe_matches(probe, &sent.built().packet) {
                    return Err(invalid(index));
                }
                confirmed[index] = true;
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
            PipelineEvent::Omitted { index } => return Err(invalid(index)),
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
                pending_now = pending_now.saturating_sub(1);
            }
            event => publish_aux(event, evidence, deadline)?,
        }
        Ok(())
    });
    match result {
        Ok(stats) => Ok(PipelineOutcome {
            stats,
            completed,
            sent_bytes,
            peak_pending,
        }),
        Err(source) => Err(Error::PipelineExecution { source }),
    }
}

pub(super) fn publish_aux<F>(
    event: PipelineEvent,
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Error>,
    deadline: &Deadline,
) -> Result<(), packetcraftr_core::error::BoundaryError>
where
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    let result = match event {
        PipelineEvent::Undecoded { frame } => evidence.retain_undecoded(&[], vec![frame], deadline),
        PipelineEvent::Unattributed {
            frame,
            attribution,
            sequence,
        } => evidence.retain_unattributed(
            &frame,
            |frame| {
                Event::Unattributed(crate::scan::Unattributed {
                    attribution,
                    sequence,
                    frame,
                })
            },
            deadline,
        ),
        PipelineEvent::Diagnostic(diagnostic) => {
            evidence.record_diagnostics(vec![diagnostic], deadline)
        }
        PipelineEvent::Qualification(qualification) => {
            evidence
                .classifier_mut()
                .rtt
                .qualify_pending(qualification.coverage());
            evidence.emit(Event::Qualification(qualification), deadline)
        }
        _ => {
            return Err(packetcraftr_core::error::BoundaryError::internal_execution(
                "unexpected attempt event at auxiliary publisher",
                "internal.scan_pipeline_event",
                "preserve the attempt publication boundary",
            ));
        }
    };
    result.map_err(packetcraftr_core::error::BoundaryError::from_error)
}

pub(super) fn run_pipelined<E, F>(
    request: &Request,
    executor: &mut E,
    evidence: &mut BatchEvidence<ProbeClassifier<'_>, F, Error>,
    deadline: &Deadline,
    plan: &StagePlan<'_>,
    preceding: crate::Stats,
) -> Result<(crate::Stats, usize), Error>
where
    E: Pipelined,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    let batches: Vec<_> = plan.batches(request).collect();
    let outcome = drive_pipeline(request, executor, evidence, deadline, &batches, preceding)?;
    let count = batches.len() as u64;
    if outcome.completed.iter().any(|done| !*done)
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
    enforce_deadline(probe_error, deadline)?;
    Ok((outcome.stats, outcome.peak_pending))
}
