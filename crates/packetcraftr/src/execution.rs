// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The progressive execution context shared by paced live workflows.
//!
//! One [`Context`] owns the mechanics every progressive workflow repeats: the
//! operation [`Deadline`], the injected [`Clock`], pacing between steps,
//! scheduled-delay accounting, a fresh [`ExecutionPermit`] per step, clipping
//! each step's timeout to the remaining budget, and checked [`Stats`] merging.
//! It fixes the order of those checks once. A workflow supplies only what
//! varies: the delay it computed, the work of each step with that step's
//! evidence validation, and an [`Errors`] adapter naming every failure in the
//! workflow's own typed error.

use std::time::Duration;

use packetcraftr_core::budget::{Deadline, DeadlineExceeded, Interrupted};

use crate::clock::Clock;
use crate::evidence::ExecutionPermit;
use crate::{BoundaryError, Stats, StatsOverflow};

/// How a workflow names the failures the execution context can raise, in the
/// style of [`crate::target::GateErrors`]. Every method receives the step
/// coordinate the failure concerns and the original source, so workflow errors
/// stay typed.
pub(crate) trait Errors {
    type Error;
    /// The coordinate that names a step or pause in errors: a probe sequence,
    /// a fuzz case index, a DNS attempt, or a replay source index.
    type Step: Copy;

    /// Committing time would pass the operation budget, or nothing remains
    /// for a step's timeout.
    fn duration_limit(&self, step: Self::Step, source: DeadlineExceeded) -> Self::Error;
    /// A cooperative `Deadline::enforce` boundary refused: the operation was
    /// cancelled or its budget was spent.
    fn interrupted(&self, step: Self::Step, source: Interrupted) -> Self::Error;
    /// The pacing clock failed while the deadline and cancellation still
    /// allowed the operation to continue.
    fn clock(
        &self,
        step: Self::Step,
        source: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self::Error;
    /// The step's work failed at its provider boundary.
    fn execution(&self, step: Self::Step, source: BoundaryError) -> Self::Error;
    /// The step returned evidence bound to a different execution permit.
    fn invalid_evidence(&self, step: Self::Step, message: String) -> Self::Error;
    /// Merging the step's statistics, or the scheduled delay, overflowed.
    fn stats_overflow(&self, step: Self::Step, source: StatsOverflow) -> Self::Error;
}

/// Evidence a step returns: the permit it was executed under and the
/// statistics of the traffic it produced.
pub(crate) trait Receipt {
    fn permit(&self) -> ExecutionPermit;
    fn stats(&self) -> &Stats;
}

/// What the context grants one step: its timeout, already clipped to the
/// remaining operation budget, and the fresh permit its evidence must carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Grant {
    pub(crate) timeout: Duration,
    pub(crate) permit: ExecutionPermit,
}

/// Paces and executes one workflow's steps under its operation deadline.
///
/// The context borrows the deadline and clock, so a workflow that also checks
/// the deadline outside steps reads it through [`Context::deadline`], and a
/// short-lived context can serve a single pause.
pub(crate) struct Context<'a, C, R> {
    deadline: &'a mut Deadline,
    clock: &'a mut C,
    errors: R,
    stats: Stats,
}

impl<'a, C, R> Context<'a, C, R>
where
    C: Clock,
    R: Errors,
{
    pub(crate) fn new(deadline: &'a mut Deadline, clock: &'a mut C, errors: R) -> Self {
        Self {
            deadline,
            clock,
            errors,
            stats: Stats::default(),
        }
    }

    pub(crate) fn deadline(&self) -> &Deadline {
        self.deadline
    }

    /// Statistics merged so far, including every scheduled delay.
    pub(crate) fn into_stats(self) -> Stats {
        self.stats
    }

    /// Cooperative boundary check: cancellation first, then elapsed time.
    pub(crate) fn enforce(&self, step: R::Step) -> Result<(), R::Error> {
        self.deadline
            .enforce()
            .map_err(|source| self.errors.interrupted(step, source))
    }

    /// Checked merge of statistics a workflow accounts outside [`Self::step`].
    /// On overflow the merged statistics are left untouched.
    pub(crate) fn merge(&mut self, step: R::Step, stats: &Stats) -> Result<(), R::Error> {
        self.stats
            .checked_add_assign(stats)
            .map_err(|source| self.errors.stats_overflow(step, source))
    }

    /// Waits `delay` before `step`, charging it to the deadline and to the
    /// elapsed statistics.
    ///
    /// The order is fixed: check → start accounting the delay → sleep →
    /// check both cancellation and the deadline → surface a clock failure →
    /// account the delay → add the scheduled delay. A spent deadline or a
    /// stop request observed after the sleep therefore outranks a clock
    /// failure in every workflow.
    pub(crate) fn pace(&mut self, step: R::Step, delay: Duration) -> Result<(), R::Error> {
        self.enforce(step)?;
        self.deadline
            .start_accounting(delay)
            .map_err(|source| self.errors.duration_limit(step, source))?;
        let slept = self.clock.sleep(delay);
        self.enforce(step)?;
        slept.map_err(|source| self.errors.clock(step, Box::new(source)))?;
        self.deadline
            .account(delay)
            .map_err(|source| self.errors.duration_limit(step, source))?;
        self.merge(
            step,
            &Stats {
                elapsed: delay,
                ..Stats::default()
            },
        )
    }

    /// Runs one step's work and returns its validated evidence with the grant
    /// it ran under.
    ///
    /// `subject` is whatever both closures need mutable access to, such as the
    /// executor or the request the grant is bound into. The order is fixed:
    /// check → start accounting → clip the timeout → issue a permit →
    /// `execute` → observe interruption → surface an execution failure →
    /// check the permit → `validate` → merge stats → surface the interruption
    /// observed after execution → account the elapsed time → check.
    ///
    /// A failed execution produced no evidence to account, so an interruption
    /// observed alongside it is reported instead of the failure. Evidence
    /// from a different permit is rejected before `validate` sees it. Once
    /// evidence is valid its statistics are merged before any interruption
    /// surfaces: traffic that reached the wire stays accounted even when the
    /// operation stops at this boundary.
    pub(crate) fn step<S, X>(
        &mut self,
        step: R::Step,
        timeout: Duration,
        subject: &mut S,
        execute: impl FnOnce(&mut S, Grant) -> Result<X, BoundaryError>,
        validate: impl FnOnce(&mut S, &X, Grant, &Deadline) -> Result<(), R::Error>,
    ) -> Result<(X, Grant), R::Error>
    where
        S: ?Sized,
        X: Receipt,
    {
        self.enforce(step)?;
        self.deadline
            .start_accounting(Duration::ZERO)
            .map_err(|source| self.errors.duration_limit(step, source))?;
        let timeout = self
            .deadline
            .bounded_timeout(timeout)
            .map_err(|source| self.errors.duration_limit(step, source))?;
        let grant = Grant {
            timeout,
            permit: ExecutionPermit::new(),
        };
        let execution = execute(subject, grant);
        let interrupted = self
            .deadline
            .enforce()
            .map_err(|source| self.errors.interrupted(step, source));
        let execution = match execution {
            Ok(execution) => execution,
            Err(source) => {
                interrupted?;
                return Err(self.errors.execution(step, source));
            }
        };
        if execution.permit() != grant.permit {
            return Err(self.errors.invalid_evidence(
                step,
                "executor returned evidence for a different execution permit".to_owned(),
            ));
        }
        validate(subject, &execution, grant, &*self.deadline)?;
        self.merge(step, execution.stats())?;
        interrupted?;
        self.deadline
            .account(execution.stats().elapsed)
            .map_err(|source| self.errors.duration_limit(step, source))?;
        self.enforce(step)?;
        Ok((execution, grant))
    }
}

#[cfg(test)]
mod tests;
