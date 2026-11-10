// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::clock::{Clock, SystemClock};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Whether a configured duration is zero or above its finite `maximum`.
#[must_use]
pub fn duration_violation(value: Duration, maximum: Duration) -> bool {
    value.is_zero() || value > maximum
}

/// A blocked provider cannot be interrupted; callers check before and after each provider boundary.
#[derive(Clone)]
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
    #[must_use]
    pub fn with_parent(mut self, parent: Option<Arc<Self>>) -> Self {
        if let Some(parent) = parent {
            self.parents.push(parent);
        }
        self
    }

    #[must_use]
    pub fn new(limit: Duration) -> Self {
        Self::with_time_source(limit, || SystemClock.now())
    }

    /// A spent deadline that accepts only work already queued, while preserving cancellation.
    #[must_use]
    pub fn immediate(cancellation: Option<Cancellation>) -> Self {
        Self::new(Duration::ZERO).with_cancellation(cancellation)
    }

    /// A deadline for the time remaining before `deadline`, preserving cancellation.
    #[must_use]
    pub fn until(deadline: Instant, cancellation: Option<Cancellation>) -> Self {
        Self::new(deadline.saturating_duration_since(SystemClock.now()))
            .with_cancellation(cancellation)
    }

    /// The source must never move backward.
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

    #[must_use]
    pub fn with_cancellation(mut self, cancellation: Option<Cancellation>) -> Self {
        self.cancellation = cancellation;
        self
    }

    #[must_use]
    pub fn limit(&self) -> Duration {
        self.limit
    }

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

    /// Cooperative work-boundary gate; cancellation takes precedence over elapsed time.
    pub fn enforce(&self) -> Result<(), Interrupted> {
        self.check_cancelled()?;
        self.check()?;
        Ok(())
    }

    pub fn check(&self) -> Result<(), DeadlineExceeded> {
        self.check_elapsed(self.elapsed_at((self.now)())?)
    }

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

    pub fn remaining(&self) -> Result<Duration, DeadlineExceeded> {
        let elapsed = self.elapsed_at((self.now)())?;
        self.check_elapsed(elapsed)?;
        let mut remaining = self.limit.saturating_sub(elapsed);
        for parent in &self.parents {
            remaining = remaining.min(parent.remaining()?);
        }
        Ok(remaining)
    }

    /// Nonzero remainder bounded by `requested`; does not check cancellation.
    pub fn bounded_timeout(&self, requested: Duration) -> Result<Duration, DeadlineExceeded> {
        let timeout = requested.min(self.remaining()?);
        if timeout.is_zero() {
            return Err(DeadlineExceeded {
                actual: self.limit(),
                limit: self.limit(),
            });
        }
        Ok(timeout)
    }

    /// Child deadline for one wait: bounded remainder, same cancellation, this deadline as parent.
    pub fn for_wait(&self, requested: Duration) -> Result<Self, DeadlineExceeded> {
        // Sampling `remaining` and preparing the send take time the child's
        // own limit cannot see, so the parent stays attached too: the
        // child's cooperative boundaries keep enforcing it.
        Ok(Self::new(self.bounded_timeout(requested)?)
            .with_cancellation(self.cancellation().cloned())
            .with_parent(Some(Arc::new(self.clone()))))
    }

    /// Cancellation first, then the nonzero remainder.
    pub fn live_remaining(&self) -> Result<Duration, Interrupted> {
        self.check_cancelled()?;
        Ok(self.bounded_timeout(Duration::MAX)?)
    }

    /// Cancellation first, then a child holding the whole remainder.
    pub fn detach(&self) -> Result<Self, Interrupted> {
        self.check_cancelled()?;
        Ok(self.for_wait(Duration::MAX)?)
    }

    /// Commits a completed phase, charging whichever of wall time or reported
    /// elapsed time is larger.
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

impl crate::error::Classified for DeadlineExceeded {
    fn classification(&self) -> crate::error::Classification {
        crate::error::Classification::new(
            crate::error::Code::PolicyDurationLimit,
            crate::error::Kind::Policy,
            Some("reduce input or raise the finite invocation duration"),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Interrupted {
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
    #[error(transparent)]
    Exceeded(#[from] DeadlineExceeded),
}

impl Interrupted {
    pub fn into_error<E: From<Cancelled> + From<DeadlineExceeded>>(self) -> E {
        match self {
            Self::Cancelled(cancelled) => cancelled.into(),
            Self::Exceeded(exceeded) => exceeded.into(),
        }
    }
}

impl crate::error::Classified for Interrupted {
    fn classification(&self) -> crate::error::Classification {
        match self {
            Self::Cancelled(source) => source.classification(),
            Self::Exceeded(source) => source.classification(),
        }
    }
}

#[doc(hidden)]
#[macro_export]
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
            crate::error::Code::IoCancelled,
            crate::error::Kind::Io,
            Some(
                "account for earlier records and confirmed transmissions; the operation is incomplete",
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Classified, Code, Kind};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn clocked(limit: Duration) -> (Deadline, Arc<AtomicU64>) {
        let origin = Instant::now();
        let elapsed = Arc::new(AtomicU64::new(0));
        let clock = Arc::clone(&elapsed);
        let deadline = Deadline::with_time_source(limit, move || {
            origin + Duration::from_millis(clock.load(Ordering::SeqCst))
        });
        (deadline, elapsed)
    }

    #[test]
    fn duration_bounds_allow_the_exact_maximum() {
        let maximum = Duration::from_millis(10);
        assert!(duration_violation(Duration::ZERO, maximum));
        assert!(!duration_violation(Duration::from_millis(1), maximum));
        assert!(!duration_violation(maximum, maximum));
        assert!(duration_violation(
            maximum + Duration::from_millis(1),
            maximum
        ));
    }

    #[test]
    fn accounting_charges_prior_wall_time_and_the_larger_phase_duration() {
        let limit = Duration::from_millis(10);
        let (mut deadline, elapsed) = clocked(limit);
        assert_eq!(deadline.limit(), limit);
        elapsed.store(3, Ordering::SeqCst);
        deadline.start_accounting(Duration::from_millis(7)).unwrap();
        elapsed.store(5, Ordering::SeqCst);
        deadline.account(Duration::from_millis(4)).unwrap();
        assert_eq!(deadline.remaining(), Ok(Duration::from_millis(3)));
        deadline.account(Duration::from_millis(1)).unwrap();
        assert_eq!(deadline.remaining(), Ok(Duration::from_millis(2)));
        deadline.check_additional(Duration::from_millis(2)).unwrap();
        let expected = DeadlineExceeded {
            actual: Duration::from_millis(11),
            limit,
        };
        assert_eq!(
            deadline.check_additional(Duration::from_millis(3)),
            Err(expected)
        );
        assert_eq!(
            deadline.start_accounting(Duration::from_millis(3)),
            Err(expected)
        );
        assert_eq!(deadline.remaining(), Ok(Duration::from_millis(2)));
        elapsed.store(8, Ordering::SeqCst);
        assert_eq!(deadline.check(), Err(expected));
        assert_eq!(deadline.remaining(), Err(expected));
        assert_eq!(deadline.enforce(), Err(Interrupted::Exceeded(expected)));
    }

    #[test]
    fn elapsed_wall_time_can_exceed_reported_time() {
        let (mut deadline, elapsed) = clocked(Duration::from_millis(10));
        elapsed.store(4, Ordering::SeqCst);
        deadline.account(Duration::from_millis(1)).unwrap();
        assert_eq!(deadline.remaining(), Ok(Duration::from_millis(6)));
        elapsed.store(10, Ordering::SeqCst);
        assert_eq!(deadline.check(), Ok(()));
        assert_eq!(deadline.remaining(), Ok(Duration::ZERO));
        assert!(deadline.bounded_timeout(Duration::from_millis(1)).is_err());
        assert!(deadline.live_remaining().is_err());
    }

    #[test]
    fn parent_deadlines_bound_children_and_reject_additional_work() {
        let (parent, elapsed) = clocked(Duration::from_millis(10));
        let (child, _) = clocked(Duration::from_secs(30));
        let child = child.with_parent(Some(Arc::new(parent)));
        assert_eq!(child.remaining(), Ok(Duration::from_millis(10)));
        assert_eq!(
            child.bounded_timeout(Duration::from_millis(4)),
            Ok(Duration::from_millis(4))
        );
        assert_eq!(
            child.bounded_timeout(Duration::from_secs(1)),
            Ok(Duration::from_millis(10))
        );
        let wait = child.for_wait(Duration::from_secs(1)).unwrap();
        let detached = child.detach().unwrap();
        elapsed.store(8, Ordering::SeqCst);
        assert!(child.check_additional(Duration::from_millis(3)).is_err());
        elapsed.store(11, Ordering::SeqCst);
        assert!(child.check().is_err());
        assert!(wait.enforce().is_err());
        assert!(detached.enforce().is_err());
    }

    #[test]
    fn cancellation_propagates_through_waits_and_takes_precedence_over_expiry() {
        let signal = Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(60)).with_cancellation(Some(signal.clone()));
        let wait = deadline.for_wait(Duration::from_secs(10)).unwrap();
        let detached = deadline.detach().unwrap();
        assert!(!signal.is_cancelled());
        assert!(signal.check().is_ok());
        assert!(deadline.check_cancelled().is_ok());
        assert!(
            Deadline::new(Duration::from_secs(1))
                .cancellation()
                .is_none()
        );
        let child = Deadline::immediate(None).with_parent(Some(Arc::new(deadline.clone())));
        deadline.cancellation().unwrap().cancel();
        assert!(signal.is_cancelled());
        assert_eq!(signal.check(), Err(Cancelled));
        for deadline in [deadline, wait, detached, child] {
            assert_eq!(deadline.check_cancelled(), Err(Cancelled));
            assert_eq!(deadline.enforce(), Err(Interrupted::Cancelled(Cancelled)));
            assert_eq!(
                deadline.live_remaining(),
                Err(Interrupted::Cancelled(Cancelled))
            );
            assert!(matches!(deadline.detach(), Err(Interrupted::Cancelled(_))));
        }
    }

    #[test]
    fn accounting_overflow_is_a_duration_limit_failure() {
        let (mut deadline, _) = clocked(Duration::MAX);
        deadline.account(Duration::MAX).unwrap();
        let expected = DeadlineExceeded {
            actual: Duration::MAX,
            limit: Duration::MAX,
        };
        assert_eq!(
            deadline.check_additional(Duration::from_nanos(1)),
            Err(expected)
        );
        assert_eq!(
            deadline.start_accounting(Duration::from_nanos(1)),
            Err(expected)
        );
        assert_eq!(deadline.account(Duration::from_nanos(1)), Err(expected));
    }

    #[test]
    fn interrupted_errors_preserve_failure_classification() {
        let exceeded = DeadlineExceeded {
            actual: Duration::from_secs(2),
            limit: Duration::from_secs(1),
        };
        assert_eq!(exceeded.classification().code, Code::PolicyDurationLimit);
        assert_eq!(exceeded.classification().kind, Kind::Policy);
        assert_eq!(Cancelled.classification().code, Code::IoCancelled);
        assert_eq!(Cancelled.classification().kind, Kind::Io);
        for interrupted in [
            Interrupted::Cancelled(Cancelled),
            Interrupted::Exceeded(exceeded),
        ] {
            let error: Interrupted = interrupted.into_error();
            assert_eq!(error.classification(), interrupted.classification());
        }
    }
}
