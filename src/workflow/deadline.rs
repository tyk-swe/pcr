// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, Instant};

/// Cooperative operation deadline combining wall time with deterministic
/// elapsed-time accounting. A blocked provider cannot be interrupted; callers
/// must check immediately before and after each provider boundary.
pub(super) struct Deadline {
    baseline: Instant,
    accounted: Duration,
    limit: Duration,
}

impl Deadline {
    pub(super) fn new(limit: Duration) -> Self {
        Self {
            baseline: Instant::now(),
            accounted: Duration::ZERO,
            limit,
        }
    }

    pub(super) fn check(&self) -> Result<(), DeadlineExceeded> {
        self.check_elapsed(self.elapsed_at(Instant::now()))
    }

    /// Checks prospective deterministic time without committing it.
    pub(super) fn check_additional(&self, additional: Duration) -> Result<(), DeadlineExceeded> {
        let actual = self
            .elapsed_at(Instant::now())
            .checked_add(additional)
            .unwrap_or(Duration::MAX);
        self.check_elapsed(actual)
    }

    /// Commits wall time from prior work and begins a phase whose reported
    /// elapsed time may overlap its wall time.
    pub(super) fn start_accounting(
        &mut self,
        prospective: Duration,
    ) -> Result<(), DeadlineExceeded> {
        let now = Instant::now();
        let elapsed = self.elapsed_at(now);
        let actual = elapsed.checked_add(prospective).unwrap_or(Duration::MAX);
        self.check_elapsed(actual)?;
        self.accounted = elapsed;
        self.baseline = now;
        Ok(())
    }

    fn elapsed_at(&self, now: Instant) -> Duration {
        self.accounted
            .checked_add(now.duration_since(self.baseline))
            .unwrap_or(Duration::MAX)
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

    pub(super) fn account(&mut self, elapsed: Duration) -> Result<(), DeadlineExceeded> {
        let now = Instant::now();
        let phase_elapsed = now.duration_since(self.baseline).max(elapsed);
        self.accounted = self
            .accounted
            .checked_add(phase_elapsed)
            .ok_or(DeadlineExceeded {
                actual: Duration::MAX,
                limit: self.limit,
            })?;
        self.baseline = now;
        self.check_elapsed(self.accounted)
    }
}

pub(super) struct DeadlineExceeded {
    pub(super) actual: Duration,
    pub(super) limit: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prospective_check_does_not_commit_elapsed_time() {
        let mut deadline = Deadline::new(Duration::from_secs(1));

        assert!(deadline.check_additional(Duration::from_secs(2)).is_err());
        assert_eq!(deadline.accounted, Duration::ZERO);
        assert!(deadline.start_accounting(Duration::from_millis(1)).is_ok());
        assert!(deadline.account(Duration::from_millis(1)).is_ok());
    }

    #[test]
    fn prospective_check_rejects_time_beyond_remaining_wall_time() {
        let deadline = Deadline::new(Duration::from_millis(100));
        let additional = Duration::from_millis(90);

        std::thread::sleep(Duration::from_millis(20));
        assert!(additional <= deadline.limit);
        assert!(
            deadline
                .baseline
                .elapsed()
                .checked_add(additional)
                .is_some_and(|elapsed| elapsed > deadline.limit)
        );
        assert!(deadline.check_additional(additional).is_err());
        assert_eq!(deadline.accounted, Duration::ZERO);
    }

    #[test]
    fn wall_time_before_virtual_phases_remains_committed() {
        let mut deadline = Deadline::new(Duration::from_secs(10));

        deadline.baseline = deadline
            .baseline
            .checked_sub(Duration::from_secs(2))
            .unwrap();
        assert!(deadline.start_accounting(Duration::from_secs(3)).is_ok());
        assert!(deadline.account(Duration::from_secs(3)).is_ok());

        let error = deadline
            .start_accounting(Duration::from_secs(6))
            .unwrap_err();
        assert!(error.actual > deadline.limit);
    }

    #[test]
    fn reported_time_overlapping_wall_time_is_not_counted_twice() {
        let mut deadline = Deadline::new(Duration::from_secs(20));

        assert!(deadline.start_accounting(Duration::from_secs(5)).is_ok());
        deadline.baseline = deadline
            .baseline
            .checked_sub(Duration::from_secs(5))
            .unwrap();
        assert!(deadline.account(Duration::from_secs(5)).is_ok());

        assert!(deadline.accounted < Duration::from_secs(6));
    }
}
