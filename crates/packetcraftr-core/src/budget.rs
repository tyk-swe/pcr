// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Finite time budgets shared by offline analysis and live workflows.

use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cooperative operation deadline combining wall time with deterministic
/// elapsed-time accounting. A blocked provider cannot be interrupted; callers
/// must check immediately before and after each provider boundary.
pub struct Deadline {
    parents: Vec<Arc<Self>>,
    cancellation: Option<Cancellation>,
    baseline: Instant,
    accounted: Duration,
    limit: Duration,
    now: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl std::fmt::Debug for Deadline {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Deadline")
            .field("limit", &self.limit)
            .field("accounted", &self.accounted)
            .field("parent_count", &self.parents.len())
            .finish_non_exhaustive()
    }
}

impl Deadline {
    /// Applies an immutable operation-wide ceiling in addition to this
    /// phase's allowance. Accounting a child never restarts the parent.
    #[must_use]
    pub fn with_parent(mut self, parent: Option<Arc<Self>>) -> Self {
        if let Some(parent) = parent {
            self.parents.push(parent);
        }
        self
    }

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
            parents: Vec::new(),
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

    /// The operation's total allowance.
    #[must_use]
    pub fn limit(&self) -> Duration {
        self.limit
    }

    /// The cooperative stop signal shared with this operation, if any.
    #[must_use]
    pub fn cancellation(&self) -> Option<&Cancellation> {
        self.cancellation.as_ref()
    }

    pub fn check_cancelled(&self) -> Result<(), Cancelled> {
        for parent in &self.parents {
            parent.check_cancelled()?;
        }
        self.cancellation
            .as_ref()
            .map_or(Ok(()), Cancellation::check)
    }

    /// Cooperative work-boundary gate; cancellation takes precedence over
    /// elapsed time.
    ///
    /// # Errors
    ///
    /// Returns [`Interrupted::Cancelled`] if signaled, otherwise
    /// [`Interrupted::Exceeded`] when accounted time passes the limit.
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
        for parent in &self.parents {
            parent.check_additional(additional)?;
        }
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
        for parent in &self.parents {
            parent.check()?;
        }
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
        let mut remaining = self.limit.saturating_sub(elapsed);
        for parent in &self.parents {
            remaining = remaining.min(parent.remaining()?);
        }
        Ok(remaining)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("operation took {actual:?}, exceeding its {limit:?} budget")]
pub struct DeadlineExceeded {
    pub actual: Duration,
    pub limit: Duration,
}

/// Why a [`Deadline::enforce`] gate refused to continue.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
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

/// Implements the two conversions a core error with a `DurationLimit` variant
/// needs to accept [`Interrupted`] through `?`.
macro_rules! deadline_error_conversions {
    ($error:ty) => {
        impl ::std::convert::From<$crate::budget::DeadlineExceeded> for $error {
            fn from(error: $crate::budget::DeadlineExceeded) -> Self {
                Self::DurationLimit {
                    actual: error.actual,
                    limit: error.limit,
                }
            }
        }

        impl ::std::convert::From<$crate::budget::Interrupted> for $error {
            fn from(interrupted: $crate::budget::Interrupted) -> Self {
                interrupted.into_error()
            }
        }
    };
}

pub(crate) use deadline_error_conversions;

/// Cloneable cooperative stop signal. Construction starts no threads, and
/// cancelling one operation does not affect independently constructed signals.
#[derive(Clone, Debug, Default)]
pub struct Cancellation(Arc<std::sync::atomic::AtomicBool>);

impl Cancellation {
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

#[cfg(test)]
mod cancellation_tests {
    use super::*;

    #[test]
    fn cancellation_is_shared_only_with_clones_and_never_fakes_elapsed_time() {
        let signal = Cancellation::default();
        let independent = Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(60)).with_cancellation(Some(signal.clone()));
        let wait = Deadline::new(Duration::from_secs(1))
            .with_cancellation(deadline.cancellation().cloned());
        signal.cancel();
        assert!(wait.check_cancelled().is_err());
        assert!(matches!(signal.check(), Err(Cancelled)));
        assert!(deadline.check_cancelled().is_err());
        assert!(deadline.check().is_ok());
        assert!(independent.check().is_ok());
    }
}
