// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::Arc;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::registry::Registry;

use crate::BoundaryError;
use crate::clock::Clock;
use crate::policy::Authorizer;
use crate::probe::evidence::{EvidenceState, validate_batch_evidence};
use crate::probe::runner::{ProbeLifecycle, run_batches, sink_observer};
use crate::probe::{
    Error, ErrorKind, Execution, Executor, PipelineEvent, PipelineOptions, duration_limit,
    enforce_deadline,
};
use crate::progress::Runtime;

use super::evidence::Processor;
use super::plan::{ApprovedScan, approve_scan, build_batches};
use super::probe::sent_probe_matches;
use super::report::Collector;
use super::{Batch, ClassificationCounts, Event, Report, Request, Summary, WORKFLOW};

/// Validates the request, authorizes every resolved target and the complete
/// operation budget before constructing probes, then executes and classifies
/// checksum-valid correlated responses.
pub fn run<A, E, C>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
) -> Result<Report, Error>
where
    A: Authorizer,
    E: Executor<Batch>,
    C: Clock,
{
    let mut collector = Collector::default();
    let summary = run_observed(
        request,
        authorizer,
        registry,
        executor,
        clock,
        |event, _| {
            collector.observe(event);
            Ok(())
        },
    )?;
    Ok(collector.finish(summary))
}

/// Executes one approved scan and publishes each final probe outcome and
/// retained undecoded frame before beginning later batches. The callback runs
/// on a runtime-budgeted worker; `max_duration` bounds publisher waiting and
/// live I/O, not arbitrary callback execution. Confirmed sends in the current
/// batch are not undone, callback failure prevents later batches, and a
/// callback may finish after this function returns while holding its permit.
pub fn run_with_events<A, E, C, F>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    runtime: &Runtime,
    emit: F,
) -> Result<Summary, Error>
where
    A: Authorizer,
    E: Executor<Batch>,
    C: Clock,
    F: FnMut(Event) -> Result<(), BoundaryError> + Send + 'static,
{
    let observe = sink_observer(
        runtime,
        emit,
        |error| duration_limit(WORKFLOW, error.actual, error.limit),
        |source| Error::new(WORKFLOW, ErrorKind::Output { source }),
    )?;
    run_observed(request, authorizer, registry, executor, clock, observe)
}

fn run_observed<A, E, C, F>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    mut emit: F,
) -> Result<Summary, Error>
where
    A: Authorizer,
    E: Executor<Batch>,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    let mut deadline =
        Deadline::new(request.limits.max_duration).with_cancellation(clock.cancellation());
    enforce_deadline(WORKFLOW, &deadline)?;
    if (2..=1024).contains(&request.max_in_flight)
        && request.max_in_flight > executor.pipeline_capacity()
    {
        return Err(Error::new(
            WORKFLOW,
            ErrorKind::PipelineExecution {
                source: BoundaryError::new(
                    "executor cannot provide the requested packet window",
                    packetcraftr_core::error::Classification::new(
                        "capability.probe_pipeline",
                        packetcraftr_core::error::Kind::Capability,
                        Some("use max_in_flight=1 or a pipeline-capable executor"),
                    ),
                    Vec::new(),
                ),
            },
        ));
    }
    let approved = approve_scan(request, authorizer, &deadline)?;
    let batches = build_batches(request, &approved.addresses, &approved.endpoints)?;
    enforce_deadline(WORKFLOW, &deadline)?;
    let mut state = EvidenceState::default();
    let mut winners = HashMap::new();
    let mut rtt = super::report::RttAccumulator::default();
    let mut processor = Processor {
        registry,
        limits: request.limits,
        target: Arc::from(approved.declared_target.as_str()),
        state: &mut state,
        winners: &mut winners,
        rtt: &mut rtt,
        emit: &mut emit,
    };
    let stats = if request.max_in_flight == 1 {
        let mut lifecycle = Lifecycle {
            executor,
            processor: &mut processor,
        };
        run_batches(
            WORKFLOW,
            batches,
            request.probes_per_second,
            &mut deadline,
            clock,
            &mut lifecycle,
        )
    } else {
        run_pipelined(
            request,
            executor,
            &mut processor,
            &deadline,
            batches,
            &approved,
        )
    };
    let stats = stats?;
    let mut counts = ClassificationCounts::default();
    for classification in winners.into_values() {
        counts.increment(classification);
    }

    Ok(Summary {
        planned_duration: approved.planned_duration,
        target: approved.declared_target,
        resolved_addresses: approved.addresses,
        counts,
        stats,
        rtt: rtt.finish(),
    })
}

/// Executes the scan through the executor's rolling packet window, publishing
/// the same events the serial path emits. The completion check rejects a
/// pipeline whose reported statistics disagree with the validated sends.
fn run_pipelined<E, F, B>(
    request: &Request,
    executor: &mut E,
    processor: &mut Processor<'_, F>,
    deadline: &Deadline,
    batches: B,
    approved: &ApprovedScan,
) -> Result<crate::Stats, Error>
where
    E: Executor<Batch>,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
    B: Iterator<Item = Batch>,
{
    let count = approved
        .addresses
        .len()
        .saturating_mul(approved.endpoints.len())
        .saturating_mul(request.attempts as usize);
    if count.saturating_mul(std::mem::size_of::<Batch>()) > request.limits.max_prepared_bytes {
        return Err(Error::new(
            WORKFLOW,
            ErrorKind::PipelineExecution {
                source: super::pipeline::limit(
                    "prepared descriptions",
                    request.limits.max_prepared_bytes,
                ),
            },
        ));
    }
    let batches: Vec<_> = batches.collect();
    let mut completed = vec![false; batches.len()];
    let mut confirmed = vec![false; batches.len()];
    let mut sent_bytes = 0u64;
    let remaining = deadline
        .remaining()
        .map_err(|error| duration_limit(WORKFLOW, error.actual, error.limit))?;
    let settings = PipelineOptions {
        max_in_flight: request.max_in_flight,
        probes_per_second: request.probes_per_second,
        max_duration: remaining,
        max_prepared_bytes: request.limits.max_prepared_bytes,
        max_evidence_frames: request.limits.max_evidence_frames,
        max_evidence_bytes: request.limits.max_evidence_bytes,
        max_undecoded: request.limits.max_undecoded,
    };
    let result = executor.execute_pipeline(&batches, settings, &mut |event| {
        let invalid = |index| {
            crate::BoundaryError::from_error(Error::new(
                WORKFLOW,
                ErrorKind::InvalidEvidence {
                    sequence: index as u64,
                    message: "pipeline returned an invalid or repeated request index".to_owned(),
                },
            ))
        };
        match event {
            PipelineEvent::Sent { index, sent } => {
                let batch = batches.get(index).ok_or_else(|| invalid(index))?;
                if confirmed[index] || !sent_probe_matches(&batch.probe, &sent.built().packet) {
                    return Err(invalid(index));
                }
                confirmed[index] = true;
                sent_bytes = sent_bytes
                    .checked_add(sent.bytes_sent() as u64)
                    .ok_or_else(|| invalid(index))?;
                (processor.emit)(
                    Event::Sent(super::SentProbe {
                        probe: batch.probe.clone(),
                        sent,
                    }),
                    deadline,
                )
                .map_err(crate::BoundaryError::from_error)?;
            }
            PipelineEvent::Completed { index, execution } => {
                let batch = batches.get(index).ok_or_else(|| invalid(index))?;
                if completed[index] || !confirmed[index] {
                    return Err(invalid(index));
                }
                validate_batch_evidence(
                    WORKFLOW,
                    std::slice::from_ref(&batch.probe),
                    batch.timeout,
                    &execution,
                    request.limits.evidence(),
                    sent_probe_matches,
                )
                .map_err(crate::BoundaryError::from_error)?;
                processor
                    .process_batch(batch, execution, deadline)
                    .map_err(crate::BoundaryError::from_error)?;
                completed[index] = true;
            }
            PipelineEvent::Undecoded { frame } => processor
                .retain_undecoded(vec![frame], deadline)
                .map_err(crate::BoundaryError::from_error)?,
            PipelineEvent::Diagnostic(diagnostic) => processor
                .record_diagnostics(vec![diagnostic], deadline)
                .map_err(crate::BoundaryError::from_error)?,
        }
        Ok(())
    });
    match result {
        Ok(stats) => {
            if completed.iter().any(|done| !*done)
                || stats.packets_attempted != batches.len() as u64
                || stats.packets_completed != batches.len() as u64
                || stats.bytes != sent_bytes
            {
                return Err(Error::new(
                    WORKFLOW,
                    ErrorKind::InvalidEvidence {
                        sequence: 0,
                        message:
                            "pipeline completion statistics disagree with validated sends/outcomes"
                                .to_owned(),
                    },
                ));
            }
            enforce_deadline(WORKFLOW, deadline)?;
            Ok(stats)
        }
        Err(source) => Err(Error::new(
            WORKFLOW,
            ErrorKind::PipelineExecution { source },
        )),
    }
}

struct Lifecycle<'a, 'b, E, F> {
    executor: &'a mut E,
    processor: &'a mut Processor<'b, F>,
}

impl<E, F> ProbeLifecycle<Batch> for Lifecycle<'_, '_, E, F>
where
    E: Executor<Batch>,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    fn execute(&mut self, batch: &Batch) -> Result<Execution, BoundaryError> {
        self.executor.execute(batch)
    }

    fn validate(&mut self, batch: &Batch, execution: &Execution) -> Result<(), Error> {
        validate_batch_evidence(
            WORKFLOW,
            std::slice::from_ref(&batch.probe),
            batch.timeout,
            execution,
            self.processor.limits.evidence(),
            sent_probe_matches,
        )
    }

    fn process(
        &mut self,
        batch: &Batch,
        execution: Execution,
        deadline: &Deadline,
    ) -> Result<ControlFlow<()>, Error> {
        self.processor.process_batch(batch, execution, deadline)?;
        Ok(ControlFlow::Continue(()))
    }
}
