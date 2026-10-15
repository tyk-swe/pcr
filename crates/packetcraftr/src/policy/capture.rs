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
