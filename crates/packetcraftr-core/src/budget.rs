// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

pub use crate::clock::deadline::{
    Cancellation, Cancelled, Deadline, DeadlineExceeded, Interrupted, POLL_INTERVAL,
};

/// Whether a configured duration is zero or above its finite `maximum`.
#[must_use]
pub fn duration_violation(value: Duration, maximum: Duration) -> bool {
    value.is_zero() || value > maximum
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
