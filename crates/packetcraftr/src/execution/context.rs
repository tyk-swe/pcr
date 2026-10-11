// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The progressive execution context shared by paced live workflows.

use std::time::Duration;

use packetcraftr_core::budget::{Deadline, DeadlineExceeded, Interrupted};

use super::Errors;
use crate::Stats;
use crate::clock::Clock;
use crate::evidence::ExecutionPermit;
use packetcraftr_core::error::BoundaryError;

#[derive(Debug)]
pub(crate) enum Paused {
    DurationLimit(DeadlineExceeded),
    Interrupted(Interrupted),
    Clock(Box<dyn std::error::Error + Send + Sync>),
}

impl Paused {
    pub(crate) fn into_error<R: Errors>(self, errors: &R, step: R::Step) -> R::Error {
        match self {
            Self::DurationLimit(source) => errors.duration_limit(step, source),
            Self::Interrupted(source) => errors.interrupted(step, source),
            Self::Clock(source) => errors.clock(step, source),
        }
    }
}

/// A spent deadline or a stop request observed after the sleep outranks a clock failure.
pub(crate) fn pause<C: Clock>(
    deadline: &mut Deadline,
    clock: &mut C,
    delay: Duration,
) -> Result<(), Paused> {
    deadline.enforce().map_err(Paused::Interrupted)?;
    deadline
        .start_accounting(delay)
        .map_err(Paused::DurationLimit)?;
    let slept = clock.sleep(delay, deadline);
    deadline.enforce().map_err(Paused::Interrupted)?;
    slept.map_err(|source| Paused::Clock(Box::new(source)))?;
    deadline.account(delay).map_err(Paused::DurationLimit)
}

pub(crate) fn rate_delay<R: Errors>(
    errors: &R,
    field: &'static str,
    items: usize,
    rate: Option<u32>,
) -> Result<Duration, R::Error> {
    crate::clock::rate_delay(items, rate).ok_or_else(|| {
        errors.invalid_limit(
            field,
            u64::from(rate.unwrap_or_default()),
            "rate-delay arithmetic overflowed".to_owned(),
        )
    })
}

pub(crate) trait Receipt {
    fn permit(&self) -> ExecutionPermit;
    fn stats(&self) -> &Stats;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Grant {
    pub(crate) timeout: Duration,
    pub(crate) permit: ExecutionPermit,
}

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

    pub(crate) fn now(&self) -> std::time::Instant {
        self.clock.now()
    }

    pub(crate) fn into_stats(self) -> Stats {
        self.stats
    }

    pub(crate) fn enforce(&self, step: R::Step) -> Result<(), R::Error> {
        self.deadline
            .enforce()
            .map_err(|source| self.errors.interrupted(step, source))
    }

    /// Counts work a step did besides its execution.
    pub(crate) fn account(&mut self, step: R::Step, stats: &Stats) -> Result<(), R::Error> {
        self.merge(step, stats)
    }

    /// On overflow the merged statistics are left untouched.
    fn merge(&mut self, step: R::Step, stats: &Stats) -> Result<(), R::Error> {
        self.stats
            .checked_add_assign(stats)
            .map_err(|source| self.errors.stats_overflow(step, source))
    }

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

    /// An interruption observed with a failed execution is reported instead of the failure.
    /// Valid evidence is merged before any interruption surfaces, so wire traffic stays accounted.
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
                .invalid_evidence(step, crate::evidence::Error::PermitMismatch));
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
