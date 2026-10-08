// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use super::Error;
use super::error::invalid_options;
use packetcraftr_netio::capture;

const MAX_CONFIGURED_ATTEMPTS: u32 = 10;
const MAX_CONFIGURED_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONFIGURED_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const MAX_CONFIGURED_CACHE_ENTRIES: usize = 65_536;
const MIN_NEIGHBOR_SNAPSHOT_LENGTH: usize = 128;

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
    pub fn validate(&self) -> Result<(), Error> {
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
        self.capture_limits()
            .validate()
            .map_err(|source| Error::InvalidOptions {
                message: "capture bounds are invalid".to_owned(),
                source: Some(source),
            })?;
        Ok(())
    }

    /// These options narrowed to one request that waits `attempt_timeout`,
    /// capturing at most `max_frames` frames and `max_bytes` bytes.
    #[must_use]
    pub(crate) fn single_attempt(
        &self,
        attempt_timeout: Duration,
        max_frames: usize,
        max_bytes: usize,
    ) -> Self {
        Self {
            max_attempts: 1,
            attempt_timeout,
            max_capture_queue_frames: self.max_capture_queue_frames.min(max_frames),
            max_captured_bytes: self.max_captured_bytes.min(max_bytes),
            snap_length: self.snap_length.min(max_bytes),
            ..self.clone()
        }
    }

    /// These options narrowed to one request per fresh resolution, waiting
    /// at most `attempt_timeout` for a reply and capturing within
    /// `max_frames` frames and `max_bytes` bytes. Limits too small for a
    /// decodable reply fail validation rather than being raised.
    #[must_use]
    pub(crate) fn one_attempt(
        &self,
        attempt_timeout: Duration,
        max_frames: usize,
        max_bytes: usize,
    ) -> Self {
        Self {
            attempt_timeout: attempt_timeout
                .min(MAX_CONFIGURED_ATTEMPT_TIMEOUT)
                .max(Duration::from_nanos(1)),
            ..self.single_attempt(attempt_timeout, max_frames, max_bytes)
        }
    }

    /// These options with cache limits that keep every answer for a whole
    /// operation resolving up to `max_neighbors` neighbors: an entry that
    /// expired or was evicted mid-operation would invite a second request
    /// beyond the first.
    #[must_use]
    pub(super) fn for_operation(&self, max_neighbors: usize) -> Self {
        Self {
            cache_ttl: MAX_CONFIGURED_CACHE_TTL,
            max_cache_entries: max_neighbors.max(self.max_cache_entries),
            ..self.clone()
        }
    }

    /// The capture bounds a discovery session runs under. Overflow always
    /// fails: a lost frame would make a negative result unverifiable.
    #[must_use]
    pub fn capture_limits(&self) -> capture::Limits {
        capture::Limits {
            max_frames: self.max_capture_queue_frames,
            max_bytes: self.max_captured_bytes,
            snap_length: self.snap_length,
            overflow_policy: capture::OverflowPolicy::Fail,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_attempt_keeps_the_operation_evidence_bounds() {
        let options = Options::default().one_attempt(Duration::from_secs(5), 4, 256);
        options.validate().expect("the narrowed options stay valid");
        assert_eq!(options.max_attempts, 1);
        assert_eq!(options.max_capture_queue_frames, 4);
        assert_eq!(options.max_captured_bytes, 256);
        assert_eq!(options.snap_length, 256);
        assert_eq!(options.cache_ttl, Options::default().cache_ttl);
        assert_eq!(
            options.max_cache_entries,
            Options::default().max_cache_entries
        );
        assert_eq!(options.attempt_timeout, Duration::from_secs(5));
    }

    #[test]
    fn an_operation_keeps_an_answer_for_every_neighbor_it_may_resolve() {
        let options = Options::default();
        let neighbors = MAX_CONFIGURED_CACHE_ENTRIES + 1;
        assert_eq!(
            options.for_operation(neighbors).max_cache_entries,
            neighbors
        );
        assert_eq!(
            options.for_operation(1).max_cache_entries,
            options.max_cache_entries
        );
        assert_eq!(options.for_operation(1).cache_ttl, MAX_CONFIGURED_CACHE_TTL);
    }

    #[test]
    fn one_attempt_rejects_limits_too_small_for_a_reply() {
        let unsnappable = Options::default().one_attempt(Duration::from_secs(5), 4, 40);
        assert_eq!(unsnappable.max_captured_bytes, 40);
        assert_eq!(unsnappable.snap_length, 40);
        assert!(unsnappable.validate().is_err());
        assert!(
            Options::default()
                .one_attempt(Duration::from_secs(5), 0, 256)
                .validate()
                .is_err()
        );
    }
}
