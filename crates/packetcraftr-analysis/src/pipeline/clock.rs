// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture clock and timestamp mapping.

use std::time::{Duration, Instant, SystemTime};

use crate::AnalysisError;

/// Maps capture timestamps onto the monotonic instants reassembly expects.
///
/// The first frame anchors the scale and later frames advance by their
/// distance from it, so idle expiry follows the capture's own clock. A
/// timestamp that runs backwards clamps to the latest instant already
/// issued, never rewinding idle accounting.
pub(super) struct CaptureClock {
    base: Instant,
    origin: Option<SystemTime>,
    latest: Instant,
    swept: Option<Instant>,
}

/// How far capture time must advance before a pushless frame sweeps again.
///
/// Sweeping scans every buffered flow, so doing it on every frame would make
/// a dense capture quadratic. Frames that push into a reassembler always
/// expire first regardless of this throttle — that is what keeps expiry
/// boundaries exact — so the throttle only paces the release of idle state
/// while nothing is being pushed, where a one-second lag is harmless.
const SWEEP_GRANULARITY: Duration = Duration::from_secs(1);

impl CaptureClock {
    pub(super) fn new() -> Self {
        let base = Instant::now();
        Self {
            base,
            origin: None,
            latest: base,
            swept: None,
        }
    }

    /// Returns a monotonic instant for `timestamp`: never earlier than any
    /// instant already returned, so a capture whose timestamps run backwards
    /// cannot rewind idle accounting and expire still-active state early.
    pub(super) fn at(
        &mut self,
        timestamp: SystemTime,
        number: u64,
    ) -> Result<Instant, AnalysisError> {
        let origin = *self.origin.get_or_insert(timestamp);
        let offset = timestamp.duration_since(origin).unwrap_or(Duration::ZERO);
        self.latest = self
            .base
            .checked_add(offset)
            .ok_or(AnalysisError::TimestampRange { number })?
            .max(self.latest);
        Ok(self.latest)
    }

    /// Whether capture time has advanced enough to justify an expiry sweep.
    pub(super) fn should_sweep(&mut self, now: Instant) -> bool {
        let due = self
            .swept
            .is_none_or(|swept| now.saturating_duration_since(swept) >= SWEEP_GRANULARITY);
        if due {
            self.swept = Some(now);
        }
        due
    }
}

#[cfg(test)]
mod clock_tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    #[test]
    fn capture_clock_rejects_unrepresentable_offsets_instead_of_freezing() {
        let mut clock = CaptureClock::new();
        let mut low = 0_u64;
        let mut high = u64::MAX;
        while low < high {
            let distance = high - low;
            let midpoint = low + distance / 2 + distance % 2;
            if clock
                .base
                .checked_add(Duration::from_secs(midpoint))
                .is_some()
            {
                low = midpoint;
            } else {
                high = midpoint - 1;
            }
        }
        clock.base = clock
            .base
            .checked_add(Duration::from_secs(low))
            .expect("the search retains only representable instants");
        clock.origin = Some(UNIX_EPOCH);
        let far_future = UNIX_EPOCH
            .checked_add(Duration::from_secs(1))
            .expect("one second after the Unix epoch is portable");

        assert!(matches!(
            clock.at(far_future, 7),
            Err(AnalysisError::TimestampRange { number: 7 })
        ));
    }
}
