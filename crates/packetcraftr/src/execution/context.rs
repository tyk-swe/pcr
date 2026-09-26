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

use super::{Errors, ExchangeEvidenceError};
use crate::clock::Clock;
use crate::deadline::DeadlineExt as _;
use crate::evidence::ExecutionPermit;
use crate::{BoundaryError, Stats};

/// Why a [`pause`] stopped before its delay was accounted.
#[derive(Debug)]
pub(crate) enum Paused {
    /// Committing the delay would pass the operation budget.
    DurationLimit(DeadlineExceeded),
    /// The operation was cancelled or its budget was spent.
    Interrupted(Interrupted),
    /// The pacing clock failed while the operation could still continue.
    Clock(Box<dyn std::error::Error + Send + Sync>),
}

impl Paused {
    /// Names the failure in the workflow's own error at `step`.
    pub(crate) fn into_error<R: Errors>(self, errors: &R, step: R::Step) -> R::Error {
        match self {
            Self::DurationLimit(source) => errors.duration_limit(step, source),
            Self::Interrupted(source) => errors.interrupted(step, source),
            Self::Clock(source) => errors.clock(step, source),
        }
    }
}

/// Waits `delay` before `step`, charging it to the deadline.
///
/// The order is fixed: check → start accounting the delay → sleep → check
/// both cancellation and the deadline → surface a clock failure → account
/// the delay. A spent deadline or a stop request observed after the sleep
/// therefore outranks a clock failure in every workflow. [`Context::pace`]
/// runs this and then adds the delay to its statistics; a workflow that keeps
/// its own schedule and no statistics calls it directly and names the
/// [`Paused`] failure itself.
pub(crate) fn pause<C: Clock>(
    deadline: &mut Deadline,
    clock: &mut C,
    delay: Duration,
) -> Result<(), Paused> {
    deadline.enforce().map_err(Paused::Interrupted)?;
    deadline
        .start_accounting(delay)
        .map_err(Paused::DurationLimit)?;
    let slept = clock.sleep(delay);
    deadline.enforce().map_err(Paused::Interrupted)?;
    slept.map_err(|source| Paused::Clock(Box::new(source)))?;
    deadline.account(delay).map_err(Paused::DurationLimit)
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

    /// Checked merge of a step's statistics or a scheduled delay. On overflow
    /// the merged statistics are left untouched.
    fn merge(&mut self, step: R::Step, stats: &Stats) -> Result<(), R::Error> {
        self.stats
            .checked_add_assign(stats)
            .map_err(|source| self.errors.stats_overflow(step, source))
    }

    /// Waits `delay` before `step` in the fixed [`pause`] order, then adds the
    /// scheduled delay to the elapsed statistics.
    pub(crate) fn pace(&mut self, step: R::Step, delay: Duration) -> Result<(), R::Error> {
        pause(self.deadline, self.clock, delay)
            .map_err(|paused| paused.into_error(&self.errors, step))?;
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
            return Err(self
                .errors
                .invalid_evidence(step, ExchangeEvidenceError::PermitMismatch));
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
