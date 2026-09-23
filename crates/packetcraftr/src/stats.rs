// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_netio::capture::Statistics;

/// A counter in [`Stats`] would exceed its range; the counters were left
/// untouched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("statistic accounting overflowed")]
pub struct StatsOverflow;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Stats {
    pub packets_attempted: u64,
    pub packets_completed: u64,
    pub bytes: u64,
    pub elapsed: Duration,
    pub capture: Statistics,
}

impl Stats {
    /// Accumulates `value` into these counters, or leaves them untouched and
    /// reports [`StatsOverflow`] if any single counter would overflow.
    pub fn checked_add_assign(&mut self, value: &Self) -> Result<(), StatsOverflow> {
        let sum = Self {
            packets_attempted: self
                .packets_attempted
                .checked_add(value.packets_attempted)
                .ok_or(StatsOverflow)?,
            packets_completed: self
                .packets_completed
                .checked_add(value.packets_completed)
                .ok_or(StatsOverflow)?,
            bytes: self.bytes.checked_add(value.bytes).ok_or(StatsOverflow)?,
            elapsed: self
                .elapsed
                .checked_add(value.elapsed)
                .ok_or(StatsOverflow)?,
            capture: self
                .capture
                .checked_add(value.capture)
                .ok_or(StatsOverflow)?,
        };
        *self = sum;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merging_adds_every_counter_or_leaves_all_untouched() {
        let mut total = Stats {
            packets_attempted: 1,
            packets_completed: 2,
            bytes: 3,
            elapsed: Duration::from_secs(4),
            capture: Statistics {
                received_frames: 5,
                dropped_frames: 6,
                receiver_dropped_frames: 4,
                ..Statistics::default()
            },
        };
        total
            .checked_add_assign(&Stats {
                packets_attempted: 10,
                packets_completed: 20,
                bytes: 30,
                elapsed: Duration::from_secs(40),
                capture: Statistics {
                    received_frames: 50,
                    dropped_frames: 60,
                    receiver_dropped_frames: 40,
                    ..Statistics::default()
                },
            })
            .expect("bounded statistics");
        assert_eq!(
            total,
            Stats {
                packets_attempted: 11,
                packets_completed: 22,
                bytes: 33,
                elapsed: Duration::from_secs(44),
                capture: Statistics {
                    received_frames: 55,
                    dropped_frames: 66,
                    receiver_dropped_frames: 44,
                    ..Statistics::default()
                },
            }
        );

        let before = total.clone();
        let error = total
            .checked_add_assign(&Stats {
                packets_attempted: 1,
                capture: Statistics {
                    receiver_dropped_frames: u64::MAX,
                    ..Statistics::default()
                },
                ..Stats::default()
            })
            .expect_err("a capture counter must overflow");
        assert_eq!(error, StatsOverflow);
        assert_eq!(total, before);
    }
}
