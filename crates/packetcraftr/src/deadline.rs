// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, Instant};

use packetcraftr_core::budget::{Cancellation, Deadline, DeadlineExceeded};

/// Allowance for a passive route or interface lookup whose operation has no deadline.
pub const PASSIVE_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) fn until(deadline: Instant, cancellation: Option<Cancellation>) -> Deadline {
    Deadline::new(deadline.saturating_duration_since(Instant::now()))
        .with_cancellation(cancellation)
}

/// A spent deadline: a capture read given it takes only what is already queued.
pub(crate) fn immediate(cancellation: Option<Cancellation>) -> Deadline {
    Deadline::new(Duration::ZERO).with_cancellation(cancellation)
}

pub trait DeadlineExt {
    fn bounded_timeout(&self, requested: Duration) -> Result<Duration, DeadlineExceeded>;

    fn for_wait(&self, requested: Duration) -> Result<Deadline, DeadlineExceeded>;
}

impl DeadlineExt for Deadline {
    fn bounded_timeout(&self, requested: Duration) -> Result<Duration, DeadlineExceeded> {
        let timeout = requested.min(self.remaining()?);
        if timeout.is_zero() {
            return Err(DeadlineExceeded {
                actual: self.limit(),
                limit: self.limit(),
            });
        }
        Ok(timeout)
    }

    fn for_wait(&self, requested: Duration) -> Result<Self, DeadlineExceeded> {
        // Sampling `remaining` and preparing the send take time the child's
        // own limit cannot see, so the parent stays attached too: the
        // child's cooperative boundaries keep enforcing it.
        Ok(Self::new(self.bounded_timeout(requested)?)
            .with_cancellation(self.cancellation().cloned())
            .with_parent(Some(std::sync::Arc::new(self.clone()))))
    }
}

macro_rules! deadline_error_conversions {
    ($error:ty) => {
        impl ::std::convert::From<::packetcraftr_core::budget::DeadlineExceeded> for $error {
            fn from(error: ::packetcraftr_core::budget::DeadlineExceeded) -> Self {
                Self::DurationLimit {
                    actual: error.actual,
                    limit: error.limit,
                }
            }
        }

        impl ::std::convert::From<::packetcraftr_core::budget::Interrupted> for $error {
            fn from(interrupted: ::packetcraftr_core::budget::Interrupted) -> Self {
                interrupted.into_error()
            }
        }
    };
}

pub(crate) use deadline_error_conversions;

#[cfg(test)]
mod tests {
    use packetcraftr_core::budget::Cancellation;

    use super::*;

    #[test]
    fn a_wait_shares_the_operation_cancellation_but_not_its_accounting() {
        let signal = Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(60)).with_cancellation(Some(signal.clone()));
        let wait = deadline.for_wait(Duration::from_secs(1)).unwrap();
        assert!(wait.limit() <= Duration::from_secs(1));
        signal.cancel();
        assert!(wait.check_cancelled().is_err());
        assert!(deadline.check().is_ok());
    }

    #[test]
    fn a_wait_inherits_an_expired_parent_even_before_its_own_time() {
        let clock = crate::test_support::RecordingClock::default();
        let parent = clock.deadline(Duration::from_secs(1));
        // A fresh child would still own up to its share of the remaining
        // second, but the parent's clock already passed the operation's
        // end.
        let child = parent.for_wait(Duration::from_secs(30)).unwrap();
        clock.advance(Duration::from_secs(2));
        assert!(child.enforce().is_err());
        // A child with no parent still lives: the parent was what expired.
        assert!(
            Deadline::new(Duration::from_secs(30))
                .for_wait(Duration::from_secs(10))
                .unwrap()
                .enforce()
                .is_ok()
        );
    }

    #[test]
    fn a_spent_operation_refuses_a_child_boundary() {
        let deadline = Deadline::new(Duration::ZERO);
        let error = deadline
            .bounded_timeout(Duration::from_secs(1))
            .expect_err("nothing remains for the child");
        assert_eq!(error.limit, Duration::ZERO);
    }
}
