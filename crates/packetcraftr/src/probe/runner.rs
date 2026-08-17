// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared bounded lifecycle for homogeneous probe workflows.

use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{decode::DecodedPacket, diagnostic::Diagnostic};

use crate::clock::{Clock, check_deadline, rate_delay};
use crate::{SentPacket, Stats};

/// Common request envelope for homogeneous scan and traceroute batches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch<P> {
    pub probes: Vec<P>,
    pub timeout: Duration,
    pub(crate) permit: crate::evidence::ExecutionPermit,
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
        result: crate::exchange::Result,
    ) -> Self {
        let crate::exchange::Result {
            sent,
            responses,
            unanswered: _,
            unsolicited,
            undecoded,
            diagnostics,
            stats,
        } = result;
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

pub(crate) trait ProbeBatch {
    fn sequence(&self) -> u64;
    fn probe_count(&self) -> usize;
}

pub(crate) trait ProbeExecution {
    fn stats(&self) -> &Stats;
}

impl ProbeExecution for Execution {
    fn stats(&self) -> &Stats {
        &self.stats
    }
}

pub(crate) struct BatchRun<O> {
    pub(crate) outputs: Vec<O>,
    pub(crate) stats: Stats,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProbeRunConfig {
    pub(crate) probes_per_second: Option<u32>,
    pub(crate) duration_limit: Duration,
    pub(crate) final_statistics_sequence: u64,
}

/// Workflow-owned operations and error taxonomy for the shared probe runner.
pub(crate) trait ProbeLifecycle<B> {
    type Execution: ProbeExecution;
    type Output;
    type Error;

    fn execute(&mut self, batch: &B) -> Result<Self::Execution, BoundaryError>;
    fn validate(&mut self, batch: &B, execution: &Self::Execution) -> Result<(), Self::Error>;
    fn process(
        &mut self,
        batch: &B,
        execution: Self::Execution,
        deadline: &Deadline,
    ) -> Result<Self::Output, Self::Error>;
    fn should_stop(output: &Self::Output) -> bool;
    fn duration_error(actual: Duration, limit: Duration) -> Self::Error;
    fn rate_error(rate: Option<u32>) -> Self::Error;
    fn clock_error(sequence: u64, message: String) -> Self::Error;
    fn execution_error(sequence: u64, source: BoundaryError) -> Self::Error;
    fn statistics_error(sequence: u64) -> Self::Error;
}

/// Runs already-approved homogeneous batches with shared deadline, pacing,
/// executor-boundary, evidence-validation, and checked-statistics policy.
pub(crate) fn run_batches<B, L, C>(
    batches: &[B],
    config: ProbeRunConfig,
    deadline: &mut Deadline,
    clock: &mut C,
    lifecycle: &mut L,
) -> Result<BatchRun<L::Output>, L::Error>
where
    B: ProbeBatch,
    L: ProbeLifecycle<B>,
    C: Clock,
{
    let mut outputs = Vec::with_capacity(batches.len());
    let mut stats = Stats::default();
    let mut scheduled_delay = Duration::ZERO;

    for (batch_index, batch) in batches.iter().enumerate() {
        check_deadline(deadline, L::duration_error)?;
        let sequence = batch.sequence();
        if batch_index != 0 {
            let delay = rate_delay(
                batches[batch_index - 1].probe_count(),
                config.probes_per_second,
            )
            .ok_or_else(|| L::rate_error(config.probes_per_second))?;
            check_deadline(deadline, L::duration_error)?;
            deadline
                .start_accounting(delay)
                .map_err(|error| L::duration_error(error.actual, error.limit))?;
            clock
                .sleep(delay)
                .map_err(|source| L::clock_error(sequence, source.to_string()))?;
            deadline
                .account(delay)
                .map_err(|error| L::duration_error(error.actual, error.limit))?;
            scheduled_delay = scheduled_delay
                .checked_add(delay)
                .ok_or_else(|| L::duration_error(Duration::MAX, config.duration_limit))?;
        }

        check_deadline(deadline, L::duration_error)?;
        deadline
            .start_accounting(Duration::ZERO)
            .map_err(|error| L::duration_error(error.actual, error.limit))?;
        let execution = lifecycle
            .execute(batch)
            .map_err(|source| L::execution_error(sequence, source))?;
        check_deadline(deadline, L::duration_error)?;
        deadline
            .account(execution.stats().elapsed)
            .map_err(|error| L::duration_error(error.actual, error.limit))?;
        lifecycle.validate(batch, &execution)?;
        check_deadline(deadline, L::duration_error)?;
        stats
            .checked_add_assign(execution.stats())
            .ok_or_else(|| L::statistics_error(sequence))?;
        let output = lifecycle.process(batch, execution, deadline)?;
        let stop = L::should_stop(&output);
        outputs.push(output);
        if stop {
            break;
        }
    }

    check_deadline(deadline, L::duration_error)?;
    stats.elapsed = stats
        .elapsed
        .checked_add(scheduled_delay)
        .ok_or_else(|| L::statistics_error(config.final_statistics_sequence))?;
    Ok(BatchRun { outputs, stats })
}
