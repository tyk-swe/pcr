// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Finite time budgets shared by every bounded PacketcraftR workflow.
//!
//! This module sits at the bottom of the dependency graph, so both the offline
//! analysis pipeline and the live probing workflows can bound themselves
//! without either one having to depend on the other.

use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cooperative operation deadline combining wall time with deterministic
/// elapsed-time accounting. A blocked provider cannot be interrupted; callers
/// must check immediately before and after each provider boundary.
pub struct Deadline {
    cancellation: Option<Cancellation>,
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
            cancellation: None,
            baseline: now(),
            accounted: Duration::ZERO,
            limit,
            now,
        }
    }

    /// Shares a cooperative stop signal with the operation. Deadline checks
    /// and cancellation checks remain distinct so cancellation is never reported
    /// as fabricated elapsed time.
    #[must_use]
    pub fn with_cancellation(mut self, cancellation: Option<Cancellation>) -> Self {
        self.cancellation = cancellation;
        self
    }

    pub fn check_cancelled(&self) -> Result<(), Cancelled> {
        self.cancellation
            .as_ref()
            .map_or(Ok(()), Cancellation::check)
    }

    /// Cooperative gate at a work boundary: cancellation is reported before
    /// the elapsed budget so a stop request is never reported as fabricated
    /// elapsed time.
    ///
    /// # Errors
    ///
    /// Returns [`Interrupted::Cancelled`] when the shared signal fired, else
    /// [`Interrupted::Exceeded`] once accounted time passes the limit.
    pub fn enforce(&self) -> Result<(), Interrupted> {
        self.check_cancelled()?;
        self.check()?;
        Ok(())
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

    /// Clips a child boundary's `requested` timeout to the wall-clock budget
    /// still available, so the child can never outlive the operation.
    ///
    /// # Errors
    ///
    /// Returns [`DeadlineExceeded`] after the operation budget is spent or
    /// when nothing remains for the child to spend.
    pub fn bounded_timeout(&self, requested: Duration) -> Result<Duration, DeadlineExceeded> {
        let timeout = requested.min(self.remaining()?);
        if timeout.is_zero() {
            return Err(DeadlineExceeded {
                actual: self.limit,
                limit: self.limit,
            });
        }
        Ok(timeout)
    }

    /// Starts a real-time boundary wait capped by the remaining operation
    /// budget, carrying the same cancellation signal. Deterministic parent
    /// accounting allocates the allowance; the actual wait uses wall time.
    pub fn for_wait(&self, requested: Duration) -> Result<Self, DeadlineExceeded> {
        Ok(
            Self::new(self.bounded_timeout(requested)?)
                .with_cancellation(self.cancellation.clone()),
        )
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("operation took {actual:?}, exceeding its {limit:?} budget")]
pub struct DeadlineExceeded {
    pub actual: Duration,
    pub limit: Duration,
}

/// Why a [`Deadline::enforce`] gate refused to continue.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Interrupted {
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
    #[error(transparent)]
    Exceeded(#[from] DeadlineExceeded),
}

impl Interrupted {
    /// Converts into any workflow error that already accepts both causes.
    pub fn into_error<E: From<Cancelled> + From<DeadlineExceeded>>(self) -> E {
        match self {
            Self::Cancelled(cancelled) => cancelled.into(),
            Self::Exceeded(exceeded) => exceeded.into(),
        }
    }
}

/// Cloneable cooperative stop signal. Construction starts no threads, and
/// cancelling one operation does not affect independently constructed signals.
#[derive(Clone, Debug, Default)]
pub struct Cancellation(Arc<std::sync::atomic::AtomicBool>);

impl Cancellation {
    /// Longest slice an uninterruptible wait should take between checks of
    /// the signal, so a stop request is honored promptly without spinning.
    pub const POLL_INTERVAL: Duration = Duration::from_millis(25);

    pub fn cancel(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
    pub fn check(&self) -> Result<(), Cancelled> {
        if self.is_cancelled() {
            Err(Cancelled)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("operation cancelled; previously completed external effects are not undone")]
pub struct Cancelled;

impl crate::error::Classified for Cancelled {
    fn classification(&self) -> crate::error::Classification {
        crate::error::Classification::new(
            "io.cancelled",
            crate::error::Kind::Io,
            Some(
                "account for earlier records and confirmed transmissions; the operation is incomplete",
            ),
        )
    }
}

impl Cancelled {
    pub fn into_boundary_error(self) -> crate::error::BoundaryError {
        use crate::error::Classified;
        crate::error::BoundaryError::with_source(
            self.to_string(),
            self.classification(),
            Vec::new(),
            self,
        )
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    #[test]
    fn cancellation_is_shared_only_with_clones_and_never_fakes_elapsed_time() {
        let signal = Cancellation::default();
        let independent = Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(60)).with_cancellation(Some(signal.clone()));
        let wait = deadline.for_wait(Duration::from_secs(1)).unwrap();
        signal.cancel();
        assert!(wait.check_cancelled().is_err());
        assert!(matches!(signal.check(), Err(Cancelled)));
        assert!(deadline.check_cancelled().is_err());
        assert!(deadline.check().is_ok());
        assert!(independent.check().is_ok());
    }
}
