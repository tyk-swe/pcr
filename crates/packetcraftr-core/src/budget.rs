// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Finite time budgets shared by every bounded PacketcraftR workflow.
//!
//! This module sits at the bottom of the dependency graph, so both the offline
//! analysis pipeline and the live probing workflows can bound themselves
//! without either one having to depend on the other.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cooperative operation deadline combining wall time with deterministic
/// elapsed-time accounting. A blocked provider cannot be interrupted; callers
/// must check immediately before and after each provider boundary.
pub struct Deadline {
    baseline: Instant,
    accounted: Duration,
    limit: Duration,
    now: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl Deadline {
    /// Starts a deadline that expires once accounted time exceeds `limit`.
    #[must_use]
    pub fn new(limit: Duration) -> Self {
        Self::with_time_source(limit, Instant::now)
    }

    /// Starts a deadline using an explicit monotonic time source.
    ///
    /// This constructor supports deterministic hosts and tests. The source
    /// must never move backward.
    #[must_use]
    pub fn with_time_source(
        limit: Duration,
        now: impl Fn() -> Instant + Send + Sync + 'static,
    ) -> Self {
        let now = Arc::new(now);
        Self {
            baseline: now(),
            accounted: Duration::ZERO,
            limit,
            now,
        }
    }

    /// Reports whether the budget has already been spent.
    ///
    /// # Errors
    ///
    /// Returns [`DeadlineExceeded`] once accounted time passes the limit.
    pub fn check(&self) -> Result<(), DeadlineExceeded> {
        self.check_elapsed(self.elapsed_at((self.now)())?)
    }

    /// Checks prospective deterministic time without committing it.
    ///
    /// # Errors
    ///
    /// Returns [`DeadlineExceeded`] when the prospective time would pass the
    /// limit, leaving the accounted total untouched.
    pub fn check_additional(&self, additional: Duration) -> Result<(), DeadlineExceeded> {
        let actual = self
            .elapsed_at((self.now)())?
            .checked_add(additional)
            .ok_or(self.overflow_error())?;
        self.check_elapsed(actual)
    }

    /// Commits wall time from prior work and begins a phase whose reported
    /// elapsed time may overlap its wall time.
    ///
    /// # Errors
    ///
    /// Returns [`DeadlineExceeded`] when committed plus prospective time passes
    /// the limit.
    pub fn start_accounting(&mut self, prospective: Duration) -> Result<(), DeadlineExceeded> {
        let now = (self.now)();
        let elapsed = self.elapsed_at(now)?;
        let actual = elapsed
            .checked_add(prospective)
            .ok_or(self.overflow_error())?;
        self.check_elapsed(actual)?;
        self.accounted = elapsed;
        self.baseline = now;
        Ok(())
    }

    fn elapsed_at(&self, now: Instant) -> Result<Duration, DeadlineExceeded> {
        self.accounted
            .checked_add(now.duration_since(self.baseline))
            .ok_or(self.overflow_error())
    }

    fn overflow_error(&self) -> DeadlineExceeded {
        DeadlineExceeded {
            actual: Duration::MAX,
            limit: self.limit,
        }
    }

    fn check_elapsed(&self, actual: Duration) -> Result<(), DeadlineExceeded> {
        if actual > self.limit {
            return Err(DeadlineExceeded {
                actual,
                limit: self.limit,
            });
        }
        Ok(())
    }

    /// Returns the wall-clock duration still available to an interruptible
    /// boundary.
    ///
    /// # Errors
    ///
    /// Returns [`DeadlineExceeded`] after the operation budget is spent.
    pub fn remaining(&self) -> Result<Duration, DeadlineExceeded> {
        let elapsed = self.elapsed_at((self.now)())?;
        self.check_elapsed(elapsed)?;
        Ok(self.limit.saturating_sub(elapsed))
    }

    /// Commits a completed phase, charging whichever of wall time or reported
    /// elapsed time is larger.
    ///
    /// # Errors
    ///
    /// Returns [`DeadlineExceeded`] when the committed total passes the limit.
    pub fn account(&mut self, elapsed: Duration) -> Result<(), DeadlineExceeded> {
        let now = (self.now)();
        let phase_elapsed = now.duration_since(self.baseline).max(elapsed);
        self.accounted = self
            .accounted
            .checked_add(phase_elapsed)
            .ok_or(self.overflow_error())?;
        self.baseline = now;
        self.check_elapsed(self.accounted)
    }
}

/// Reports the accounted time that passed a [`Deadline`] and the limit it broke.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadlineExceeded {
    pub actual: Duration,
    pub limit: Duration,
}
