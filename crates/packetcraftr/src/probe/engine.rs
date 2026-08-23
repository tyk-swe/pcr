// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared bounded lifecycle for homogeneous probe workflows.

use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{decode::DecodedPacket, diagnostic::Diagnostic};

use crate::clock::{Clock, rate_delay};
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

pub(crate) trait ProbeBatch {
    fn sequence(&self) -> u64;
    fn probe_count(&self) -> usize;
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub(crate) probes_per_second: Option<u32>,
    pub(crate) duration_limit: Duration,
    pub(crate) final_statistics_sequence: u64,
}

/// Workflow-owned operations and error taxonomy for the shared probe runner.
pub(crate) trait ProbeLifecycle<B> {
    fn execute(&mut self, batch: &B) -> Result<Execution, BoundaryError>;
    fn validate(&mut self, batch: &B, execution: &Execution) -> Result<(), crate::Error>;
    fn process(
        &mut self,
        batch: &B,
        execution: Execution,
        deadline: &Deadline,
    ) -> Result<bool, crate::Error>;
}

/// Runs already-approved homogeneous batches with shared deadline, pacing,
/// executor-boundary, evidence-validation, and checked-statistics policy.
pub(crate) fn run_batches<B, L, C>(
    batches: &[B],
    config: Limits,
    deadline: &mut Deadline,
    clock: &mut C,
    lifecycle: &mut L,
) -> Result<Stats, crate::Error>
where
    B: ProbeBatch,
    L: ProbeLifecycle<B>,
    C: Clock,
{
    let mut stats = Stats::default();
    let mut scheduled_delay = Duration::ZERO;

    for (batch_index, batch) in batches.iter().enumerate() {
        deadline.check()?;
        let sequence = batch.sequence();
        if batch_index != 0 {
            let delay = rate_delay(
                batches[batch_index - 1].probe_count(),
                config.probes_per_second,
            )
            .ok_or_else(|| crate::Error::InvalidRequest {
                field: "rate",
                message: format!(
                    "must be between 1 and u32::MAX; received {:?}",
                    config.probes_per_second
                ),
            })?;
            deadline.check()?;
            deadline.start_accounting(delay)?;
            clock.sleep(delay).map_err(|source| crate::Error::Clock {
                context: packetcraftr_core::error::Context::probe_sequence(sequence),
                message: source.to_string(),
            })?;
            deadline.account(delay)?;
            scheduled_delay =
                scheduled_delay
                    .checked_add(delay)
                    .ok_or(crate::Error::DurationLimit {
                        actual: Duration::MAX,
                        limit: config.duration_limit,
                    })?;
        }

        deadline.check()?;
        deadline.start_accounting(Duration::ZERO)?;
        let execution = lifecycle
            .execute(batch)
            .map_err(|source| crate::Error::Execution {
                context: packetcraftr_core::error::Context::probe_sequence(sequence),
                source: Box::new(source),
            })?;
        deadline.check()?;
        deadline.account(execution.stats.elapsed)?;
        lifecycle.validate(batch, &execution)?;
        deadline.check()?;
        stats
            .checked_add_assign(&execution.stats)
            .ok_or(crate::Error::StatisticsOverflow {
                context: packetcraftr_core::error::Context::probe_sequence(sequence),
            })?;
        if lifecycle.process(batch, execution, deadline)? {
            break;
        }
    }

    deadline.check()?;
    stats.elapsed =
        stats
            .elapsed
            .checked_add(scheduled_delay)
            .ok_or(crate::Error::StatisticsOverflow {
                context: packetcraftr_core::error::Context::probe_sequence(
                    config.final_statistics_sequence,
                ),
            })?;
    Ok(stats)
}
