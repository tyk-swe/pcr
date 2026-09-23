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

use crate::clock::{Clock, rate_delay};
use crate::evidence::ExecutionPermit;
use crate::execution::{Context, Grant, Receipt};
use crate::probe::{Error, ErrorKind, Workflow};
use crate::{SentPacket, Stats};

/// Multi-probe request envelope used for traceroute hop batches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch<P> {
    pub probes: Vec<P>,
    pub timeout: Duration,
    pub(crate) permit: ExecutionPermit,
    /// The first probe's operation-local sequence, recorded by the planner
    /// that built the batch; it names the batch in every error the runner
    /// reports.
    pub(crate) sequence: u64,
}

/// Private pacing and binding controls for the two existing probe workflows.
/// Scan owns a single-probe value; traceroute owns a variable-size hop batch.
pub(crate) trait BatchPlan {
    fn sequence(&self) -> u64;
    fn probe_count(&self) -> usize;
    /// The timeout the plan requested, before clipping to the operation budget.
    fn timeout(&self) -> Duration;
    /// Binds the execution context's grant so the executor runs the batch
    /// under the clipped timeout and returns evidence for the fresh permit.
    fn bind(&mut self, grant: Grant);
}

impl<P> BatchPlan for Batch<P> {
    fn sequence(&self) -> u64 {
        self.sequence
    }
    fn probe_count(&self) -> usize {
        self.probes.len()
    }
    fn timeout(&self) -> Duration {
        self.timeout
    }
    fn bind(&mut self, grant: Grant) {
        self.timeout = grant.timeout;
        self.permit = grant.permit;
    }
}

/// Common executor evidence returned by homogeneous probe batches.
#[derive(Clone, Debug)]
pub struct Execution {
    pub(crate) permit: ExecutionPermit,
    pub(crate) sent: Vec<SentPacket>,
    pub(crate) responses: Vec<crate::exchange::Response>,
    pub(crate) unsolicited: Vec<DecodedPacket>,
    pub(crate) undecoded: Vec<Frame>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) stats: Stats,
}

impl Execution {
    pub(crate) fn from_exchange(permit: ExecutionPermit, result: crate::exchange::Report) -> Self {
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

impl Receipt for Execution {
    fn permit(&self) -> ExecutionPermit {
        self.permit
    }
    fn stats(&self) -> &Stats {
        &self.stats
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
    fn execute(&mut self, batch: &B) -> Result<Execution, BoundaryError>;
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

/// Runs already-approved homogeneous batches through the execution context,
/// which owns deadline, pacing, permit, timeout-clipping, and checked-statistics
/// policy. The runner supplies the pacing input: each batch waits for the
/// previous batch's probe count at `probes_per_second`.
pub(crate) fn run_batches<B, L, C>(
    workflow: Workflow,
    batches: impl IntoIterator<Item = impl BorrowMut<B>>,
    probes_per_second: Option<u32>,
    deadline: &mut Deadline,
    clock: &mut C,
    lifecycle: &mut L,
) -> Result<Stats, Error>
where
    B: BatchPlan,
    L: ProbeLifecycle<B>,
    C: Clock,
{
    let mut context = Context::new(deadline, clock, workflow);
    let mut previous_probes = None;
    let mut last_sequence = 0;

    for mut planned in batches {
        let batch = planned.borrow_mut();
        let sequence = batch.sequence();
        context.enforce(sequence)?;
        if let Some(previous_probes) = previous_probes {
            let delay = rate_delay(previous_probes, probes_per_second).ok_or_else(|| {
                Error::new(
                    workflow,
                    ErrorKind::InvalidLimit {
                        field: "probes_per_second",
                        value: u64::from(probes_per_second.unwrap_or_default()),
                        reason: "rate-delay arithmetic overflowed".to_owned(),
                    },
                )
            })?;
            context.pace(sequence, delay)?;
        }
        previous_probes = Some(batch.probe_count());
        last_sequence = sequence;

        let (execution, _) = context.step(
            sequence,
            batch.timeout(),
            &mut (&mut *batch, &mut *lifecycle),
            |(batch, lifecycle), grant| {
                batch.bind(grant);
                lifecycle.execute(batch)
            },
            |(batch, lifecycle), execution, _, _| lifecycle.validate(batch, execution),
        )?;
        if lifecycle
            .process(batch, execution, context.deadline())?
            .is_break()
        {
            break;
        }
    }

    context.enforce(last_sequence)?;
    Ok(context.into_stats())
}

#[cfg(test)]
mod tests;
