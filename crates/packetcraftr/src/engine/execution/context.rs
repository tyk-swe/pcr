// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The progressive execution context shared by paced live workflows.

use std::time::Duration;

use packetcraftr_core::budget::{Deadline, DeadlineExceeded, Interrupted};

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
    pub(crate) fn into_error<E>(self, errors: fn(u64, crate::error::Failure) -> E, step: u64) -> E {
        match self {
            Self::DurationLimit(source) => {
                (errors)(step, crate::error::Failure::DurationLimit(source))
            }
            Self::Interrupted(source) => (errors)(step, crate::error::Failure::Interrupted(source)),
            Self::Clock(source) => (errors)(step, crate::error::Failure::Clock(source)),
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

pub(crate) fn rate_delay<E>(
    errors: fn(u64, crate::error::Failure) -> E,
    field: &'static str,
    items: usize,
    rate: Option<u32>,
) -> Result<Duration, E> {
    crate::clock::rate_delay(items, rate).ok_or_else(|| {
        (errors)(
            0_u64,
            crate::error::Failure::InvalidLimit {
                field,
                value: u64::from(rate.unwrap_or_default()),
                reason: "rate-delay arithmetic overflowed".to_owned(),
            },
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

pub(crate) struct Context<'a, C, E> {
    deadline: &'a mut Deadline,
    clock: &'a mut C,
    errors: fn(u64, crate::error::Failure) -> E,
    stats: Stats,
}

impl<'a, C, E> Context<'a, C, E>
where
    C: Clock,
{
    pub(crate) fn new(
        deadline: &'a mut Deadline,
        clock: &'a mut C,
        errors: fn(u64, crate::error::Failure) -> E,
    ) -> Self {
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

    pub(crate) fn enforce(&self, step: u64) -> Result<(), E> {
        self.deadline
            .enforce()
            .map_err(|source| (self.errors)(step, crate::error::Failure::Interrupted(source)))
    }

    /// On overflow the merged statistics are left untouched.
    pub(crate) fn account(&mut self, step: u64, stats: &Stats) -> Result<(), E> {
        self.stats
            .checked_add_assign(stats)
            .map_err(|source| (self.errors)(step, crate::error::Failure::StatsOverflow(source)))
    }

    pub(crate) fn pace(&mut self, step: u64, delay: Duration) -> Result<(), E> {
        pause(self.deadline, self.clock, delay)
            .map_err(|paused| paused.into_error(self.errors, step))?;
        self.account(
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
        step: u64,
        timeout: Duration,
        subject: &mut S,
        execute: impl FnOnce(&mut S, Grant) -> Result<X, BoundaryError>,
        validate: impl FnOnce(&mut S, &X, Grant, &Deadline) -> Result<(), E>,
    ) -> Result<(X, Grant), E>
    where
        S: ?Sized,
        X: Receipt,
    {
        self.enforce(step)?;
        self.deadline
            .start_accounting(Duration::ZERO)
            .map_err(|source| (self.errors)(step, crate::error::Failure::DurationLimit(source)))?;
        let timeout = self
            .deadline
            .bounded_timeout(timeout)
            .map_err(|source| (self.errors)(step, crate::error::Failure::DurationLimit(source)))?;
        let grant = Grant {
            timeout,
            permit: ExecutionPermit::new(),
        };
        let execution = execute(subject, grant);
        let interrupted = self
            .deadline
            .enforce()
            .map_err(|source| (self.errors)(step, crate::error::Failure::Interrupted(source)));
        let execution = match execution {
            Ok(execution) => execution,
            Err(source) => {
                interrupted?;
                return Err((self.errors)(
                    step,
                    crate::error::Failure::Execution(source),
                ));
            }
        };
        if execution.permit() != grant.permit {
            return Err((self.errors)(
                step,
                crate::error::Failure::InvalidEvidence(crate::evidence::Error::PermitMismatch),
            ));
        }
        validate(subject, &execution, grant, &*self.deadline)?;
        self.account(step, execution.stats())?;
        interrupted?;
        self.deadline
            .account(execution.stats().elapsed)
            .map_err(|source| (self.errors)(step, crate::error::Failure::DurationLimit(source)))?;
        self.enforce(step)?;
        Ok((execution, grant))
    }
}
