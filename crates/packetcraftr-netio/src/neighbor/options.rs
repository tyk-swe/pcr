// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use super::error::invalid_options;
use crate::capture;

const MAX_CONFIGURED_ATTEMPTS: u32 = 10;
const MAX_CONFIGURED_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONFIGURED_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const MAX_CONFIGURED_CACHE_ENTRIES: usize = 65_536;
const MIN_NEIGHBOR_SNAPSHOT_LENGTH: usize = 128;

/// Finite work, retention, and cache bounds for active neighbor resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub max_attempts: u32,
    pub attempt_timeout: Duration,
    pub cache_ttl: Duration,
    pub max_cache_entries: usize,
    pub max_capture_queue_frames: usize,
    pub max_captured_bytes: usize,
    pub snap_length: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            attempt_timeout: Duration::from_secs(1),
            cache_ttl: Duration::from_secs(30),
            max_cache_entries: 4_096,
            max_capture_queue_frames: 256,
            max_captured_bytes: 1024 * 1024,
            snap_length: 2_048,
        }
    }
}

impl Options {
    /// Validates every finite bound; returns nothing, so a caller keeps the
    /// options it already owns.
    pub fn validate(&self) -> Result<(), crate::neighbor::Error> {
        if !(1..=MAX_CONFIGURED_ATTEMPTS).contains(&self.max_attempts) {
            return Err(invalid_options(format!(
                "max_attempts must be within 1..={MAX_CONFIGURED_ATTEMPTS}"
            )));
        }
        if self.attempt_timeout.is_zero() || self.attempt_timeout > MAX_CONFIGURED_ATTEMPT_TIMEOUT {
            return Err(invalid_options(format!(
                "attempt_timeout must be within 1ns..={MAX_CONFIGURED_ATTEMPT_TIMEOUT:?}"
            )));
        }
        if self.cache_ttl.is_zero() || self.cache_ttl > MAX_CONFIGURED_CACHE_TTL {
            return Err(invalid_options(format!(
                "cache_ttl must be within 1ns..={MAX_CONFIGURED_CACHE_TTL:?}"
            )));
        }
        if !(1..=MAX_CONFIGURED_CACHE_ENTRIES).contains(&self.max_cache_entries) {
            return Err(invalid_options(format!(
                "max_cache_entries must be within 1..={MAX_CONFIGURED_CACHE_ENTRIES}"
            )));
        }
        if self.snap_length < MIN_NEIGHBOR_SNAPSHOT_LENGTH {
            return Err(invalid_options(format!(
                "snap_length must be at least {MIN_NEIGHBOR_SNAPSHOT_LENGTH} bytes"
            )));
        }
        capture::Limits {
            max_frames: self.max_capture_queue_frames,
            max_bytes: self.max_captured_bytes,
            snap_length: self.snap_length,
            overflow_policy: capture::OverflowPolicy::Fail,
        }
        .validate()
        .map_err(|error| invalid_options(error.to_string()))?;
        Ok(())
    }
}
