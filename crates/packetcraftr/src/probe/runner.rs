// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared bounded lifecycle for homogeneous probe workflows.

use std::borrow::BorrowMut;
use std::ops::ControlFlow;
use std::time::Duration;

use crate::progress::{EmitError, Runtime, Sink};
use packetcraftr_core::budget::{Deadline, DeadlineExceeded};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{decode::DecodedPacket, diagnostic::Diagnostic};

use crate::StatsOverflow;
use crate::clock::Clock;
use crate::probe::live_step::{self, EvidenceBounds, LiveRequest, Pacer, StepErrors};
use crate::probe::{Error, ErrorKind, Executor, Workflow};
use crate::target::GateErrors;
use crate::{SentPacket, Stats};

/// Multi-probe request envelope used for traceroute hop batches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch<P> {
    pub probes: Vec<P>,
    pub timeout: Duration,
    pub(crate) permit: crate::evidence::ExecutionPermit,
    /// The first probe's operation-local sequence, recorded by the planner
    /// that built the batch; it names the batch in every error the runner
    /// reports.
    pub(crate) sequence: u64,
}

/// Private pacing/deadline controls for the two existing probe workflows.
/// Scan owns a single-probe value; traceroute owns a variable-size hop batch.
pub(crate) trait BatchPlan: LiveRequest {
    fn sequence(&self) -> u64;
    fn probe_count(&self) -> usize;
}

impl<P> BatchPlan for Batch<P> {
    fn sequence(&self) -> u64 {
        self.sequence
    }
    fn probe_count(&self) -> usize {
        self.probes.len()
    }
}

/// Common executor evidence returned by homogeneous probe batches.
#[derive(Clone, Debug)]
pub struct Execution {
    pub(crate) permit: crate::evidence::ExecutionPermit,
    pub(crate) sent: Vec<SentPacket>,
    pub(crate) responses: Vec<crate::exchange::Response>,
    pub(crate) unsolicited: Vec<DecodedPacket>,
    pub(crate) undecoded: Vec<Frame>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) stats: Stats,
}

impl Execution {
    pub(crate) fn from_exchange(
        permit: crate::evidence::ExecutionPermit,
        result: crate::exchange::Report,
    ) -> Self {
        let crate::exchange::Report {
            sent,
            responses,
            unanswered: _,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        } = result;
        let sent = sent
            .into_iter()
            .map(crate::exchange::into_sent_packet)
            .collect();
        Self {
            permit,
            sent,
            responses,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        }
    }
}

impl<P> crate::probe::Request for Batch<P> {
    type Execution = Execution;
}

/// Wraps a caller's progressive callback in a bounded [`Sink`] and adapts both
/// of its failures into the workflow's own error type, so every `run_with_events`
/// entry point differs only in those two constructors.
pub(crate) fn sink_observer<T, E>(
    runtime: &Runtime,
    emit: impl FnMut(T) -> Result<(), BoundaryError> + Send + 'static,
    on_deadline: impl Fn(DeadlineExceeded) -> E,
    on_output: impl Fn(BoundaryError) -> E,
) -> Result<impl FnMut(T, &Deadline) -> Result<(), E>, E>
where
    T: Send + 'static,
{
    let sink = match Sink::new_in(runtime, emit) {
        Ok(sink) => sink,
        Err(source) => return Err(on_output(source)),
    };
    Ok(
        move |event, deadline: &Deadline| match sink.emit(event, deadline) {
            Ok(()) => Ok(()),
            Err(EmitError::Deadline(error)) => Err(on_deadline(error)),
            Err(EmitError::Output(source)) => Err(on_output(source)),
        },
    )
}

pub(crate) trait Sequenced {
    fn sequence(&self) -> u64;
}

/// Workflow-owned operations for the shared probe runner.
pub(crate) trait ProbeLifecycle<B> {
    fn validate(&mut self, batch: &B, execution: &Execution) -> Result<(), Error>;
    /// Consumes one batch's evidence. [`ControlFlow::Break`] ends the
    /// operation without running the remaining batches.
    fn process(
        &mut self,
        batch: &B,
        execution: Execution,
        deadline: &Deadline,
    ) -> Result<ControlFlow<()>, Error>;
}

/// Maps common live-step failures to a scan or traceroute batch sequence.
pub(crate) struct ProbeStepErrors {
    pub(crate) workflow: Workflow,
    pub(crate) sequence: u64,
}

impl StepErrors for ProbeStepErrors {
    type Error = Error;
    fn interrupted(&self, source: packetcraftr_core::budget::Interrupted) -> Error {
        self.workflow.interrupted(source)
    }
    fn duration(&self, source: DeadlineExceeded) -> Error {
        self.workflow.duration_limit(source.actual, source.limit)
    }
    fn execution(&self, source: BoundaryError) -> Error {
        Error::new(
            self.workflow,
            ErrorKind::Execution {
                sequence: self.sequence,
                source,
            },
        )
    }
    fn clock(&self, source: Box<dyn std::error::Error + Send + Sync>) -> Error {
        Error::new(
            self.workflow,
            ErrorKind::Clock {
                sequence: self.sequence,
                source,
            },
        )
    }
    fn evidence(&self, message: String) -> Error {
        Error::new(
            self.workflow,
            ErrorKind::InvalidEvidence {
                sequence: self.sequence,
                message,
            },
        )
    }
    fn overflow(&self, _: StatsOverflow) -> Error {
        Error::new(
            self.workflow,
            ErrorKind::StatisticsOverflow {
                sequence: self.sequence,
            },
        )
    }
}

/// The approved operation policy passed to the batch runner. The live step
/// itself only needs the captured-evidence bounds for each request.
pub(crate) struct BatchRunOptions {
    pub(crate) workflow: Workflow,
    pub(crate) probes_per_second: Option<u32>,
    pub(crate) evidence: EvidenceBounds,
}

/// Runs approved batches through the live step. Ticket 02 can replace the
/// lifecycle's batch processing without changing this execution boundary.
pub(crate) fn run_batches<B, L, E, C>(
    options: BatchRunOptions,
    batches: impl IntoIterator<Item = impl BorrowMut<B>>,
    deadline: &mut Deadline,
    clock: &mut C,
    executor: &mut E,
    lifecycle: &mut L,
) -> Result<Stats, Error>
where
    B: BatchPlan + crate::probe::Request<Execution = Execution>,
    L: ProbeLifecycle<B>,
    E: Executor<B>,
    C: Clock,
{
    let BatchRunOptions {
        workflow,
        probes_per_second,
        evidence,
    } = options;
    let mut stats = Stats::default();
    let mut previous_probes = None;

    for mut planned in batches {
        let batch = planned.borrow_mut();
        let errors = ProbeStepErrors {
            workflow,
            sequence: batch.sequence(),
        };
        if let Some(probes) = previous_probes {
            let delay = Pacer::delay(probes, probes_per_second).ok_or_else(|| {
                Error::new(
                    workflow,
                    ErrorKind::InvalidLimit {
                        field: "probes_per_second",
                        value: u64::from(probes_per_second.unwrap_or_default()),
                        reason: "rate-delay arithmetic overflowed".to_owned(),
                    },
                )
            })?;
            Pacer::wait(
                deadline,
                clock,
                delay,
                |error| errors.interrupted(error),
                |error| errors.duration(error),
                |source| errors.clock(Box::new(source)),
            )?;
            live_step::account_pacing(&mut stats, delay, &errors)?;
        }
        previous_probes = Some(batch.probe_count());
        let execution = live_step::execute(
            deadline,
            executor,
            batch,
            evidence,
            &mut stats,
            &errors,
            |batch, execution| lifecycle.validate(batch, execution),
        )?;
        if lifecycle.process(batch, execution, deadline)?.is_break() {
            break;
        }
    }
    crate::probe::enforce_deadline(workflow, deadline)?;
    Ok(stats)
}

#[cfg(test)]
mod tests;
