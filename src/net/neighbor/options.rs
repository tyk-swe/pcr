use std::time::Duration;

use crate::net::{
    capture::{CaptureOverflowPolicy, CaptureQueueLimits},
    neighbor::Error as NeighborError,
};

const MAX_CONFIGURED_ATTEMPTS: u32 = 10;
const MAX_CONFIGURED_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONFIGURED_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const MAX_CONFIGURED_CACHE_ENTRIES: usize = 65_536;
const MAX_CONFIGURED_CAPTURE_FRAMES: usize = 4_096;
const MAX_CONFIGURED_CAPTURE_BYTES: usize = 256 * 1024 * 1024;
const MIN_NEIGHBOR_SNAPSHOT_LENGTH: usize = 128;

/// Finite work, retention, and cache bounds for active neighbor resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeighborResolutionOptions {
    pub max_attempts: u32,
    pub attempt_timeout: Duration,
    pub cache_ttl: Duration,
    pub max_cache_entries: usize,
    pub max_capture_queue_frames: usize,
    pub max_captured_bytes: usize,
    pub snap_length: usize,
}

impl Default for NeighborResolutionOptions {
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

impl NeighborResolutionOptions {
    pub fn validate(self) -> Result<Self, NeighborError> {
        if !(1..=MAX_CONFIGURED_ATTEMPTS).contains(&self.max_attempts) {
            return Err(invalid_configuration(format!(
                "max_attempts must be within 1..={MAX_CONFIGURED_ATTEMPTS}"
            )));
        }
        if self.attempt_timeout.is_zero() || self.attempt_timeout > MAX_CONFIGURED_ATTEMPT_TIMEOUT {
            return Err(invalid_configuration(format!(
                "attempt_timeout must be within 1ns..={MAX_CONFIGURED_ATTEMPT_TIMEOUT:?}"
            )));
        }
        if self.cache_ttl.is_zero() || self.cache_ttl > MAX_CONFIGURED_CACHE_TTL {
            return Err(invalid_configuration(format!(
                "cache_ttl must be within 1ns..={MAX_CONFIGURED_CACHE_TTL:?}"
            )));
        }
        if !(1..=MAX_CONFIGURED_CACHE_ENTRIES).contains(&self.max_cache_entries) {
            return Err(invalid_configuration(format!(
                "max_cache_entries must be within 1..={MAX_CONFIGURED_CACHE_ENTRIES}"
            )));
        }
        if !(1..=MAX_CONFIGURED_CAPTURE_FRAMES).contains(&self.max_capture_queue_frames) {
            return Err(invalid_configuration(format!(
                "max_capture_queue_frames must be within 1..={MAX_CONFIGURED_CAPTURE_FRAMES}"
            )));
        }
        if self.max_captured_bytes == 0 || self.max_captured_bytes > MAX_CONFIGURED_CAPTURE_BYTES {
            return Err(invalid_configuration(format!(
                "max_captured_bytes must be within 1..={MAX_CONFIGURED_CAPTURE_BYTES}"
            )));
        }
        if self.snap_length < MIN_NEIGHBOR_SNAPSHOT_LENGTH {
            return Err(invalid_configuration(format!(
                "snap_length must be at least {MIN_NEIGHBOR_SNAPSHOT_LENGTH} bytes"
            )));
        }
        CaptureQueueLimits {
            max_frames: self.max_capture_queue_frames,
            max_bytes: self.max_captured_bytes,
            snap_length: self.snap_length,
            overflow_policy: CaptureOverflowPolicy::Fail,
        }
        .validate()
        .map_err(|error| invalid_configuration(error.to_string()))?;
        Ok(self)
    }
}

fn invalid_configuration(message: String) -> NeighborError {
    NeighborError::InvalidConfiguration { message }
}
