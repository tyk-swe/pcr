// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::model::{Error, Policy};

/// Frame and byte accounting for one live capture.
///
/// A capture cannot know its totals up front the way a send or a scan can, so
/// it charges the policy's operation budgets one frame at a time. Callers stop
/// pulling frames once [`CaptureBudget::is_exhausted`] reports the frame budget
/// spent; [`CaptureBudget::account`] is the enforcement that rejects a frame the
/// budget cannot pay for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureBudget {
    max_frames: u64,
    max_bytes: u64,
    frames: u64,
    bytes: u64,
}

impl CaptureBudget {
    /// Starts an empty budget from the policy's per-operation limits.
    #[must_use]
    pub const fn new(policy: &Policy) -> Self {
        Self {
            max_frames: policy.max_packets_per_operation,
            max_bytes: policy.max_bytes_per_operation,
            frames: 0,
            bytes: 0,
        }
    }

    /// The frame ceiling this budget was built with.
    #[must_use]
    pub const fn max_frames(&self) -> u64 {
        self.max_frames
    }

    /// The byte ceiling this budget was built with.
    #[must_use]
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Frames charged so far.
    #[must_use]
    pub const fn frames(&self) -> u64 {
        self.frames
    }

    /// Bytes charged so far.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Whether the frame budget leaves room for another frame.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.frames >= self.max_frames
    }

    /// Charges one captured frame and its wire bytes. The budget is left
    /// untouched when either limit would be exceeded, so a rejected frame never
    /// half-spends it. Counter overflow is charged as a spent budget rather
    /// than wrapped.
    pub fn account(&mut self, frame_bytes: u64) -> Result<(), Error> {
        let frames = self
            .frames
            .checked_add(1)
            .filter(|frames| *frames <= self.max_frames)
            .ok_or(Error::PacketLimit {
                actual: self.frames.saturating_add(1),
                limit: self.max_frames,
            })?;
        let bytes = self
            .bytes
            .checked_add(frame_bytes)
            .filter(|bytes| *bytes <= self.max_bytes)
            .ok_or(Error::ByteLimit {
                actual: self.bytes.saturating_add(frame_bytes),
                limit: self.max_bytes,
            })?;
        self.frames = frames;
        self.bytes = bytes;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::*;

    fn policy(max_packets_per_operation: u64, max_bytes_per_operation: u64) -> Policy {
        Policy {
            max_packets_per_operation,
            max_bytes_per_operation,
            ..Policy::default()
        }
    }

    #[test]
    fn frames_are_charged_until_the_frame_budget_is_spent() {
        let mut budget = CaptureBudget::new(&policy(2, 1_000));
        assert!(!budget.is_exhausted());
        budget.account(10).expect("first frame fits");
        assert!(!budget.is_exhausted());
        budget.account(10).expect("second frame fits");
        assert!(budget.is_exhausted());
        assert_eq!(budget.frames(), 2);
        assert_eq!(budget.bytes(), 20);

        assert_eq!(
            budget.account(10),
            Err(Error::PacketLimit {
                actual: 3,
                limit: 2
            })
        );
        assert_eq!(budget.frames(), 2);
        assert_eq!(budget.bytes(), 20);
    }

    #[test]
    fn an_unaffordable_frame_is_rejected_without_spending_the_byte_budget() {
        let mut budget = CaptureBudget::new(&policy(10, 64));
        budget.account(60).expect("first frame fits");

        assert_eq!(
            budget.account(5),
            Err(Error::ByteLimit {
                actual: 65,
                limit: 64
            })
        );
        assert_eq!(budget.frames(), 1);
        assert_eq!(budget.bytes(), 60);
    }

    #[test]
    fn byte_counter_overflow_is_charged_as_a_spent_budget() {
        let mut budget = CaptureBudget::new(&policy(u64::MAX, u64::MAX));
        budget.account(u64::MAX).expect("first frame fits exactly");

        assert_eq!(
            budget.account(1),
            Err(Error::ByteLimit {
                actual: u64::MAX,
                limit: u64::MAX
            })
        );
        assert_eq!(budget.bytes(), u64::MAX);
    }

    #[test]
    fn frame_counter_overflow_is_charged_as_a_spent_budget() {
        let mut budget = CaptureBudget {
            max_frames: u64::MAX,
            max_bytes: u64::MAX,
            frames: u64::MAX,
            bytes: 0,
        };

        assert_eq!(
            budget.account(0),
            Err(Error::PacketLimit {
                actual: u64::MAX,
                limit: u64::MAX
            })
        );
        assert_eq!(budget.frames(), u64::MAX);
    }

    #[test]
    fn a_zero_budget_is_exhausted_before_the_first_frame() {
        let mut budget = CaptureBudget::new(&policy(0, 0));
        assert!(budget.is_exhausted());

        assert_eq!(
            budget.account(0),
            Err(Error::PacketLimit {
                actual: 1,
                limit: 0
            })
        );
        assert_eq!(budget.frames(), 0);
        assert_eq!(budget.bytes(), 0);
    }

    #[test]
    fn a_single_frame_budget_pays_for_exactly_one_one_byte_frame() {
        let mut budget = CaptureBudget::new(&policy(1, 1));
        assert!(!budget.is_exhausted());
        budget.account(1).expect("the only affordable frame");

        assert!(budget.is_exhausted());
        assert_eq!(budget.frames(), 1);
        assert_eq!(budget.bytes(), 1);
        assert_eq!(
            budget.account(1),
            Err(Error::PacketLimit {
                actual: 2,
                limit: 1
            })
        );
    }
}
