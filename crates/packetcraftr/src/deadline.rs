// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Clipping live boundary waits to an operation [`Deadline`].

use std::time::Duration;

use packetcraftr_core::budget::{Deadline, DeadlineExceeded};

/// Boundary waits bounded by what remains of an operation [`Deadline`].
pub trait DeadlineExt {
    /// Clips a child boundary's `requested` timeout to the wall-clock budget
    /// still available, so the child can never outlive the operation.
    ///
    /// # Errors
    ///
    /// Returns [`DeadlineExceeded`] after the operation budget is spent or
    /// when nothing remains for the child to spend.
    fn bounded_timeout(&self, requested: Duration) -> Result<Duration, DeadlineExceeded>;

    /// Starts a real-time boundary wait capped by the remaining operation
    /// budget, carrying the same cancellation signal. Deterministic parent
    /// accounting allocates the allowance; the actual wait uses wall time.
    ///
    /// # Errors
    ///
    /// Returns [`DeadlineExceeded`] under the same conditions as
    /// [`bounded_timeout`](Self::bounded_timeout).
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
        Ok(Self::new(self.bounded_timeout(requested)?)
            .with_cancellation(self.cancellation().cloned()))
    }
}

/// Implements the two conversions a workflow error with a `DurationLimit`
/// variant needs to accept [`Interrupted`](packetcraftr_core::budget::Interrupted)
/// through `?`.
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
    fn a_spent_operation_refuses_a_child_boundary() {
        let deadline = Deadline::new(Duration::ZERO);
        let error = deadline
            .bounded_timeout(Duration::from_secs(1))
            .expect_err("nothing remains for the child");
        assert_eq!(error.limit, Duration::ZERO);
    }
}
