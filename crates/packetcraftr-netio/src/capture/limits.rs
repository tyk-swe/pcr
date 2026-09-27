// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::Error;

pub const MAX_CAPTURE_QUEUE_FRAMES: usize = 4_096;
pub const MAX_CAPTURE_QUEUE_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_SNAP_LENGTH: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OverflowPolicy {
    #[default]
    Fail,
    DropNewest,
    DropOldest,
}

impl OverflowPolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fail => "fail",
            Self::DropNewest => "drop-newest",
            Self::DropOldest => "drop-oldest",
        }
    }
}

impl std::fmt::Display for OverflowPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_frames: usize,
    pub max_bytes: usize,
    pub snap_length: usize,
    pub overflow_policy: OverflowPolicy,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frames: MAX_CAPTURE_QUEUE_FRAMES,
            max_bytes: MAX_CAPTURE_QUEUE_BYTES,
            snap_length: MAX_SNAP_LENGTH,
            overflow_policy: OverflowPolicy::Fail,
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<(), Error> {
        for (field, value) in [
            ("max_frames", self.max_frames),
            ("max_bytes", self.max_bytes),
            ("snap_length", self.snap_length),
        ] {
            if value == 0 {
                return Err(Error::InvalidCaptureQueueLimit {
                    field,
                    value,
                    reason: "must be greater than zero",
                });
            }
        }
        for (field, value, maximum) in [
            ("max_frames", self.max_frames, MAX_CAPTURE_QUEUE_FRAMES),
            ("max_bytes", self.max_bytes, MAX_CAPTURE_QUEUE_BYTES),
            ("snap_length", self.snap_length, MAX_SNAP_LENGTH),
        ] {
            if value > maximum {
                return Err(Error::InvalidCaptureQueueLimit {
                    field,
                    value,
                    reason: "exceeds the stable configured maximum",
                });
            }
        }
        if self.snap_length > self.max_bytes {
            return Err(Error::InvalidCaptureQueueLimit {
                field: "snap_length",
                value: self.snap_length,
                reason: "cannot exceed max_bytes",
            });
        }
        Ok(())
    }
}
