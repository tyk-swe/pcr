// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_netio::capture::{MAX_CAPTURE_QUEUE_BYTES, MAX_CAPTURE_QUEUE_FRAMES};

use crate::probe::evidence::check_limits;

use super::{MAX_RATE, error::Error};

/// Bounds exact response evidence retained by a live fuzz campaign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveLimits {
    pub max_evidence_frames: usize,
    pub max_evidence_bytes: usize,
}

impl Default for LiveLimits {
    fn default() -> Self {
        Self {
            max_evidence_frames: MAX_CAPTURE_QUEUE_FRAMES,
            max_evidence_bytes: MAX_CAPTURE_QUEUE_BYTES,
        }
    }
}

impl LiveLimits {
    /// Rejects any retention bound above the ceiling this crate enforces.
    pub fn validate(&self) -> Result<(), Error> {
        check_limits(
            &[
                (
                    "max_evidence_frames",
                    self.max_evidence_frames,
                    MAX_CAPTURE_QUEUE_FRAMES,
                ),
                (
                    "max_evidence_bytes",
                    self.max_evidence_bytes,
                    MAX_CAPTURE_QUEUE_BYTES,
                ),
            ],
            &[],
            |field, value, reason| Error::InvalidLimit {
                field,
                value,
                reason,
            },
        )?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveOptions {
    pub timeout: Duration,
    pub cases_per_second: Option<u32>,
    pub destination: Option<IpAddr>,
    /// Independent call-site opt-in for a permissive/malformed live frame.
    pub allow_malformed_live: bool,
    pub limits: LiveLimits,
}

impl Default for LiveOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(1),
            cases_per_second: None,
            destination: None,
            allow_malformed_live: false,
            limits: LiveLimits::default(),
        }
    }
}

impl LiveOptions {
    /// Rejects every live campaign option this workflow cannot execute: an
    /// out-of-range retention bound, timeout, or rate.
    pub fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        if self.timeout.is_zero() || self.timeout > packetcraftr_netio::capture::MAX_TIMEOUT {
            return Err(Error::InvalidTimeout {
                value: self.timeout,
                maximum: packetcraftr_netio::capture::MAX_TIMEOUT,
            });
        }
        if let Some(rate) = self.cases_per_second
            && (rate == 0 || rate > MAX_RATE)
        {
            return Err(Error::InvalidLimit {
                field: "cases_per_second",
                value: u64::from(rate),
                reason: format!("must be within 1..={MAX_RATE}"),
            });
        }
        Ok(())
    }
}
