// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared bounded lifecycle for homogeneous probe workflows.

use std::ops::ControlFlow;
use std::time::Duration;

use packetcraftr_core::budget::{Deadline, DeadlineExceeded};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::progress::{EmitError, Runtime, Sink};
use packetcraftr_core::{decode::DecodedPacket, diagnostic::Diagnostic};

use crate::clock::{Clock, check_deadline, rate_delay};
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

/// The executor boundary every homogeneous probe workflow shares: it takes one
/// approved batch of probes and returns the evidence that batch produced.
/// `P` is the workflow's probe type, so a scan executor and a traceroute
/// executor stay distinct implementations.
pub trait Executor<P> {
    fn execute(&mut self, batch: &Batch<P>) -> Result<Execution, BoundaryError>;
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

/// Every way the shared runner itself can fail, before any workflow-specific
/// policy applies.
///
/// The runner never constructs a workflow error: each workflow converts these
/// with one `From` impl, so a new runner failure is a compile error in every
/// workflow rather than a silently reclassified one.
#[derive(Debug)]
pub(crate) enum ProbeRunError {
    /// The operation's duration budget was spent.
    Duration { actual: Duration, limit: Duration },
    /// The configured probe rate produced unrepresentable pacing arithmetic.
    Rate { rate: Option<u32> },
    /// The clock refused to pace the batch starting at `sequence`.
    Clock {
        sequence: u64,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The executor boundary failed for the batch starting at `sequence`.
    Execution {
        sequence: u64,
        source: BoundaryError,
    },
    /// Accumulating the batch starting at `sequence` overflowed a counter.
    Statistics { sequence: u64 },
}

impl ProbeRunError {
    fn duration(actual: Duration, limit: Duration) -> Self {
        Self::Duration { actual, limit }
    }

    fn exceeded(error: DeadlineExceeded) -> Self {
        Self::Duration {
            actual: error.actual,
            limit: error.limit,
        }
    }
}

/// Workflow-owned operations for the shared probe runner.
pub(crate) trait ProbeLifecycle<P> {
    type Error: From<ProbeRunError>;

    fn execute(&mut self, batch: &Batch<P>) -> Result<Execution, BoundaryError>;
    fn validate(&mut self, batch: &Batch<P>, execution: &Execution) -> Result<(), Self::Error>;
    /// Consumes one batch's evidence. [`ControlFlow::Break`] ends the
    /// operation without running the remaining batches.
    fn process(
        &mut self,
        batch: &Batch<P>,
        execution: Execution,
        deadline: &Deadline,
    ) -> Result<ControlFlow<()>, Self::Error>;
}

/// Runs already-approved homogeneous batches with shared deadline, pacing,
/// executor-boundary, evidence-validation, and checked-statistics policy.
pub(crate) fn run_batches<P, L, C>(
    batches: &[Batch<P>],
    probes_per_second: Option<u32>,
    deadline: &mut Deadline,
    clock: &mut C,
    lifecycle: &mut L,
) -> Result<Stats, L::Error>
where
    L: ProbeLifecycle<P>,
    C: Clock,
{
    let mut stats = Stats::default();
    let mut scheduled_delay = Duration::ZERO;
    let mut previous: Option<&Batch<P>> = None;

    for batch in batches {
        check_deadline(deadline, ProbeRunError::duration)?;
        let sequence = batch.sequence;
        if let Some(previous) = previous {
            let delay = rate_delay(previous.probe_count(), probes_per_second).ok_or(
                ProbeRunError::Rate {
                    rate: probes_per_second,
                },
            )?;
            check_deadline(deadline, ProbeRunError::duration)?;
            deadline
                .start_accounting(delay)
                .map_err(ProbeRunError::exceeded)?;
            clock.sleep(delay).map_err(|source| ProbeRunError::Clock {
                sequence,
                source: Box::new(source),
            })?;
            deadline.account(delay).map_err(ProbeRunError::exceeded)?;
            scheduled_delay = scheduled_delay
                .checked_add(delay)
                .ok_or(ProbeRunError::Statistics { sequence })?;
        }
        previous = Some(batch);

        check_deadline(deadline, ProbeRunError::duration)?;
        deadline
            .start_accounting(Duration::ZERO)
            .map_err(ProbeRunError::exceeded)?;
        let execution = lifecycle
            .execute(batch)
            .map_err(|source| ProbeRunError::Execution { sequence, source })?;
        check_deadline(deadline, ProbeRunError::duration)?;
        deadline
            .account(execution.stats.elapsed)
            .map_err(ProbeRunError::exceeded)?;
        lifecycle.validate(batch, &execution)?;
        check_deadline(deadline, ProbeRunError::duration)?;
        stats
            .checked_add_assign(&execution.stats)
            .ok_or(ProbeRunError::Statistics { sequence })?;
        if lifecycle.process(batch, execution, deadline)?.is_break() {
            break;
        }
    }

    check_deadline(deadline, ProbeRunError::duration)?;
    let final_sequence = previous.map_or(0, |batch| batch.sequence);
    stats.elapsed =
        stats
            .elapsed
            .checked_add(scheduled_delay)
            .ok_or(ProbeRunError::Statistics {
                sequence: final_sequence,
            })?;
    Ok(stats)
}
