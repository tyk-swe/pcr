// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The one deadline and cancellation convention for provider calls, and the
//! wall-clock helpers providers use to follow it.
//!
//! Every provider call that can block takes the caller's core
//! [`Deadline`] by reference. The deadline carries the caller's
//! [`Cancellation`](packetcraftr_core::budget::Cancellation) too, so there is
//! no separate cancellation input. A provider:
//!
//! - checks cancellation before it starts and while it waits;
//! - treats a zero remainder as expired: an expired call starts no work and
//!   reports its error type's deadline variant, classified
//!   `io.deadline_exceeded`;
//! - never waits past the remainder, and never replaces it with a timeout of
//!   its own.
//!
//! A capture read is the one call whose expiry is not a failure: it ends the
//! wait, so an expired read delivers an already queued record or `Ok(None)`.
//! See [`capture::Session`](crate::capture::Session).

use std::time::{Duration, Instant};

use packetcraftr_core::budget::{Deadline, DeadlineExceeded, Interrupted};

/// Longest slice an uninterruptible wait should take between checks of a
/// cancellation signal, so a stop request is honored promptly without
/// spinning.
pub const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Longest single wall-clock wait a provider derives from a deadline. A
/// longer remainder is clipped so its instant stays inside the monotonic
/// clock's range; callers re-check the deadline after each wait.
const MAX_WALL_CLOCK_WAIT: Duration = Duration::from_secs(60 * 60);

/// Wall-clock time remaining, or `None` at or after `deadline`. Treat `None` as
/// expiry before calling providers that reject a zero timeout.
#[must_use]
pub fn remaining_before(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
}

/// What `deadline` still allows a provider call to spend.
///
/// # Errors
///
/// Returns [`Interrupted::Cancelled`] when the caller's cancellation is
/// signaled, otherwise [`Interrupted::Exceeded`] once the deadline is spent,
/// including when exactly nothing remains.
pub fn remaining(deadline: &Deadline) -> Result<Duration, Interrupted> {
    deadline.check_cancelled()?;
    let remaining = deadline.remaining()?;
    if remaining.is_zero() {
        return Err(DeadlineExceeded {
            actual: deadline.limit(),
            limit: deadline.limit(),
        }
        .into());
    }
    Ok(remaining)
}

/// The wall-clock instant at which `deadline` expires, for a backend that
/// bounds its own waits by an [`Instant`].
///
/// # Errors
///
/// Returns the same interruptions as [`remaining`].
pub fn expires_at(deadline: &Deadline) -> Result<Instant, Interrupted> {
    let remaining = remaining(deadline)?.min(MAX_WALL_CLOCK_WAIT);
    let now = Instant::now();
    Ok(now.checked_add(remaining).unwrap_or(now))
}

/// An owned deadline with what `deadline` still allows and the same
/// cancellation signal, for work handed to another thread.
///
/// # Errors
///
/// Returns the same interruptions as [`remaining`].
pub fn detach(deadline: &Deadline) -> Result<Deadline, Interrupted> {
    Ok(Deadline::new(remaining(deadline)?).with_cancellation(deadline.cancellation().cloned()))
}

#[cfg(test)]
mod tests {
    use packetcraftr_core::budget::Cancellation;

    use super::*;

    #[test]
    fn remaining_before_treats_the_boundary_as_arrived() {
        let now = Instant::now();
        assert!(remaining_before(now - Duration::from_secs(1)).is_none());
        assert!(remaining_before(now).is_none());
        let remaining = remaining_before(now + Duration::from_secs(3600)).expect("future deadline");
        assert!(remaining > Duration::from_secs(3599));
    }

    #[test]
    fn a_zero_remainder_is_expired_and_cancellation_comes_first() {
        let frozen = Instant::now();
        let spent = Deadline::with_time_source(Duration::ZERO, move || frozen);
        assert!(matches!(remaining(&spent), Err(Interrupted::Exceeded(_))));
        assert!(matches!(expires_at(&spent), Err(Interrupted::Exceeded(_))));

        let signal = Cancellation::default();
        let live = Deadline::new(Duration::from_secs(60)).with_cancellation(Some(signal.clone()));
        assert!(remaining(&live).unwrap() <= Duration::from_secs(60));
        signal.cancel();
        assert!(matches!(remaining(&live), Err(Interrupted::Cancelled(_))));
    }

    #[test]
    fn a_detached_deadline_keeps_the_remainder_and_the_signal() {
        let signal = Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(60)).with_cancellation(Some(signal.clone()));
        let detached = detach(&deadline).unwrap();
        assert!(detached.limit() <= Duration::from_secs(60));
        signal.cancel();
        assert!(detached.check_cancelled().is_err());
    }
}
