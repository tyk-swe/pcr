// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::model::{Error, Policy};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureBudget {
    max_frames: u64,
    max_bytes: u64,
    frames: u64,
    bytes: u64,
}

impl CaptureBudget {
    #[must_use]
    pub const fn new(policy: &Policy) -> Self {
        Self {
            max_frames: policy.max_packets_per_operation,
            max_bytes: policy.max_bytes_per_operation,
            frames: 0,
            bytes: 0,
        }
    }

    #[must_use]
    pub const fn max_frames(&self) -> u64 {
        self.max_frames
    }

    #[must_use]
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    #[must_use]
    pub const fn frames(&self) -> u64 {
        self.frames
    }

    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.frames >= self.max_frames
    }

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
    use super::*;

    #[test]
    fn capture_spending_is_atomic_and_accepts_exact_limits() {
        let policy = Policy {
            max_packets_per_operation: 3,
            max_bytes_per_operation: 10,
            ..Policy::default()
        };
        let mut budget = CaptureBudget::new(&policy);
        assert_eq!(budget.max_frames(), policy.max_packets_per_operation);
        assert_eq!(budget.max_bytes(), policy.max_bytes_per_operation);
        assert_eq!((budget.frames(), budget.bytes()), (0, 0));
        assert!(!budget.is_exhausted());

        budget.account(4).unwrap();
        assert_eq!((budget.frames(), budget.bytes()), (1, 4));
        assert!(matches!(
            budget.account(7),
            Err(Error::ByteLimit {
                actual: 11,
                limit: 10
            })
        ));
        assert_eq!((budget.frames(), budget.bytes()), (1, 4));
        budget.account(6).unwrap();
        assert_eq!((budget.frames(), budget.bytes()), (2, 10));
        assert!(!budget.is_exhausted());
        budget.account(0).unwrap();
        assert_eq!((budget.frames(), budget.bytes()), (3, 10));
        assert!(budget.is_exhausted());
        assert!(matches!(
            budget.account(0),
            Err(Error::PacketLimit {
                actual: 4,
                limit: 3
            })
        ));
        assert_eq!((budget.frames(), budget.bytes()), (3, 10));
    }

    #[test]
    fn capture_byte_overflow_preserves_spending() {
        let policy = Policy {
            max_packets_per_operation: 3,
            max_bytes_per_operation: u64::MAX,
            ..Policy::default()
        };
        let mut budget = CaptureBudget::new(&policy);
        budget.account(u64::MAX).unwrap();
        assert!(matches!(
            budget.account(1),
            Err(Error::ByteLimit {
                actual: u64::MAX,
                limit: u64::MAX
            })
        ));
        assert_eq!((budget.frames(), budget.bytes()), (1, u64::MAX));
        budget.account(0).unwrap();
        assert_eq!((budget.frames(), budget.bytes()), (2, u64::MAX));
    }

    #[test]
    fn zero_capture_budget_denies_frames_without_spending() {
        let policy = Policy {
            max_packets_per_operation: 0,
            max_bytes_per_operation: 0,
            ..Policy::default()
        };
        let mut budget = CaptureBudget::new(&policy);
        assert!(budget.is_exhausted());
        assert!(matches!(
            budget.account(0),
            Err(Error::PacketLimit {
                actual: 1,
                limit: 0
            })
        ));
        assert_eq!((budget.frames(), budget.bytes()), (0, 0));
    }
}
