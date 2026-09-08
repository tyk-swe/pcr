// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture clock and timestamp mapping.

use std::time::{Duration, Instant, SystemTime};

use crate::analysis::Error;

/// Capture-global clock evidence, including filtered-out physical frames.
/// Expiry uses the maximum timestamp offset from the first frame. Regressions
/// clamp expiry to that high-water mark; forward jumps advance it immediately.
/// Original timestamps are never rewritten. Mixed-interface clocks share this
/// policy: these observations describe skew as well as clock discontinuities.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ClockReport {
    /// Frames earlier than the greatest timestamp already observed.
    pub regressions: u64,
    pub max_regression: Duration,
    /// Largest advance beyond the high-water mark; can indicate an outlier
    /// or a legitimate capture gap. No arbitrary anomaly threshold is applied.
    pub max_forward_step: Duration,
    pub max_forward_step_frame: Option<u64>,
}

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
    latest_timestamp: Option<SystemTime>,
    report: ClockReport,
}

/// How far capture time must advance before a pushless frame sweeps again.
///
/// Frames that push into a reassembler always expire first regardless of this
/// throttle — that is what keeps expiry boundaries exact. The throttle avoids
/// even an indexed expiry lookup on every pushless frame, where a one-second
/// lag in releasing idle state is harmless.
const SWEEP_GRANULARITY: Duration = Duration::from_secs(1);

impl CaptureClock {
    pub(super) fn new() -> Self {
        let base = Instant::now();
        Self {
            base,
            origin: None,
            latest: base,
            swept: None,
            latest_timestamp: None,
            report: ClockReport::default(),
        }
    }

    /// Returns a monotonic instant for `timestamp`: never earlier than any
    /// instant already returned, so a capture whose timestamps run backwards
    /// cannot rewind idle accounting and expire still-active state early.
    pub(super) fn at(&mut self, timestamp: SystemTime, number: u64) -> Result<Instant, Error> {
        if let Some(latest) = self.latest_timestamp {
            match timestamp.duration_since(latest) {
                Ok(step) if step > self.report.max_forward_step => {
                    self.report.max_forward_step = step;
                    self.report.max_forward_step_frame = Some(number);
                }
                Err(rollback) => {
                    self.report.regressions = self.report.regressions.saturating_add(1);
                    self.report.max_regression =
                        self.report.max_regression.max(rollback.duration());
                }
                _ => {}
            }
        }
        self.latest_timestamp = Some(
            self.latest_timestamp
                .map_or(timestamp, |latest| latest.max(timestamp)),
        );
        let origin = *self.origin.get_or_insert(timestamp);
        let offset = timestamp.duration_since(origin).unwrap_or(Duration::ZERO);
        self.latest = self
            .base
            .checked_add(offset)
            .ok_or(Error::TimestampRange { number })?
            .max(self.latest);
        Ok(self.latest)
    }

    pub(super) fn report(&self) -> &ClockReport {
        &self.report
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
mod tests {
    use super::*;

    #[test]
    fn capture_time_advances_from_the_first_frame_and_never_rewinds() {
        let mut clock = CaptureClock::new();
        let origin = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

        let first = clock.at(origin, 1).expect("origin timestamp fits");
        let advanced = clock
            .at(origin + Duration::from_secs(3), 2)
            .expect("later timestamp fits");
        let rewound = clock
            .at(origin + Duration::from_secs(1), 3)
            .expect("out-of-order timestamp is clamped");

        assert_eq!(advanced.duration_since(first), Duration::from_secs(3));
        assert_eq!(rewound, advanced);
    }

    #[test]
    fn sweep_throttle_is_inclusive_and_tolerates_out_of_order_instants() {
        let mut clock = CaptureClock::new();
        let first = clock.base;

        assert!(clock.should_sweep(first));
        assert!(!clock.should_sweep(first + Duration::from_millis(999)));
        assert!(clock.should_sweep(first + SWEEP_GRANULARITY));
        assert!(!clock.should_sweep(first));
        assert!(clock.should_sweep(first + SWEEP_GRANULARITY * 2));
    }
}

#[cfg(test)]
mod anomaly_tests {
    use super::*;
    #[test]
    fn forward_outlier_pins_expiry_and_reports_subsequent_rollbacks() {
        let mut clock = CaptureClock::new();
        let time = |seconds| SystemTime::UNIX_EPOCH + Duration::from_secs(seconds);
        let first = clock.at(time(100), 1).unwrap();
        let outlier = clock.at(time(10_000), 2).unwrap();
        assert_eq!(outlier.duration_since(first), Duration::from_secs(9900));
        assert_eq!(clock.at(time(90), 3).unwrap(), outlier);
        assert_eq!(clock.at(time(101), 4).unwrap(), outlier);
        assert_eq!(clock.report().regressions, 2);
        assert_eq!(clock.report().max_regression, Duration::from_secs(9910));
        assert_eq!(clock.report().max_forward_step_frame, Some(2));
    }
}
