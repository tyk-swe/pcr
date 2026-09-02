// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared bounded lifecycle for homogeneous probe workflows.

use std::ops::ControlFlow;
use std::time::Duration;

use crate::progress::{EmitError, Runtime, Sink};
use packetcraftr_core::budget::{Deadline, DeadlineExceeded};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{decode::DecodedPacket, diagnostic::Diagnostic};

use crate::StatsOverflow;
use crate::clock::{Clock, check_deadline, rate_delay};
use crate::probe::{Error, ErrorKind, Workflow};
use crate::{SentPacket, Stats};

/// Common request envelope for homogeneous scan and traceroute batches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch<P> {
    pub probes: Vec<P>,
    pub timeout: Duration,
    pub(crate) permit: crate::evidence::ExecutionPermit,
    /// The first probe's operation-local sequence, recorded by the planner
    /// that built the batch. It names the batch in every error the runner
    /// reports, so the identity is fixed where the probes are numbered rather
    /// than re-derived by indexing a vector the runner has to assume is
    /// non-empty.
    pub(crate) sequence: u64,
}

impl<P> Batch<P> {
    pub(crate) fn probe_count(&self) -> usize {
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

/// A probe that knows its operation-local sequence number.
pub(crate) trait Sequenced {
    fn sequence(&self) -> u64;
}

/// Workflow-owned operations for the shared probe runner.
pub(crate) trait ProbeLifecycle<P> {
    fn execute(&mut self, batch: &Batch<P>) -> Result<Execution, BoundaryError>;
    fn validate(&mut self, batch: &Batch<P>, execution: &Execution) -> Result<(), Error>;
    /// Consumes one batch's evidence. [`ControlFlow::Break`] ends the
    /// operation without running the remaining batches.
    fn process(
        &mut self,
        batch: &Batch<P>,
        execution: Execution,
        deadline: &Deadline,
    ) -> Result<ControlFlow<()>, Error>;
}

/// Runs already-approved homogeneous batches with shared deadline, pacing,
/// executor-boundary, evidence-validation, and checked-statistics policy.
pub(crate) fn run_batches<P, L, C>(
    workflow: Workflow,
    batches: &[Batch<P>],
    probes_per_second: Option<u32>,
    deadline: &mut Deadline,
    clock: &mut C,
    lifecycle: &mut L,
) -> Result<Stats, Error>
where
    L: ProbeLifecycle<P>,
    C: Clock,
{
    let fail = |kind| Error::new(workflow, kind);
    let duration = |actual, limit| fail(ErrorKind::DurationLimit { actual, limit });
    let exceeded = |error: DeadlineExceeded| duration(error.actual, error.limit);
    let statistics = |sequence| fail(ErrorKind::StatisticsOverflow { sequence });
    let mut stats = Stats::default();
    let mut scheduled_delay = Duration::ZERO;
    let mut previous: Option<&Batch<P>> = None;

    for batch in batches {
        check_deadline(deadline, duration)?;
        let sequence = batch.sequence;
        if let Some(previous) = previous {
            let delay = rate_delay(previous.probe_count(), probes_per_second).ok_or_else(|| {
                fail(ErrorKind::InvalidLimit {
                    field: "probes_per_second",
                    value: u64::from(probes_per_second.unwrap_or_default()),
                    reason: "rate-delay arithmetic overflowed".to_owned(),
                })
            })?;
            check_deadline(deadline, duration)?;
            deadline.start_accounting(delay).map_err(exceeded)?;
            clock.sleep(delay).map_err(|source| {
                fail(ErrorKind::Clock {
                    sequence,
                    source: Box::new(source),
                })
            })?;
            deadline.account(delay).map_err(exceeded)?;
            scheduled_delay = scheduled_delay
                .checked_add(delay)
                .ok_or_else(|| statistics(sequence))?;
        }
        previous = Some(batch);

        check_deadline(deadline, duration)?;
        deadline
            .start_accounting(Duration::ZERO)
            .map_err(exceeded)?;
        let execution = lifecycle
            .execute(batch)
            .map_err(|source| fail(ErrorKind::Execution { sequence, source }))?;
        check_deadline(deadline, duration)?;
        deadline
            .account(execution.stats.elapsed)
            .map_err(exceeded)?;
        lifecycle.validate(batch, &execution)?;
        check_deadline(deadline, duration)?;
        stats
            .checked_add_assign(&execution.stats)
            .map_err(|StatsOverflow| statistics(sequence))?;
        if lifecycle.process(batch, execution, deadline)?.is_break() {
            break;
        }
    }

    check_deadline(deadline, duration)?;
    let final_sequence = previous.map_or(0, |batch| batch.sequence);
    stats.elapsed = stats
        .elapsed
        .checked_add(scheduled_delay)
        .ok_or_else(|| statistics(final_sequence))?;
    Ok(stats)
}
