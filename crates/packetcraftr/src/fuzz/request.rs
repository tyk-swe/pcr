// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_netio::capture::{DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES};

use super::MAX_RATE;
use crate::Error;

/// Bounds exact response evidence retained by a live fuzz campaign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveLimits {
    pub max_evidence_frames: usize,
    pub max_evidence_bytes: usize,
}

impl Default for LiveLimits {
    fn default() -> Self {
        Self {
            max_evidence_frames: DEFAULT_CAPTURE_QUEUE_FRAMES,
            max_evidence_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
        }
    }
}

impl LiveLimits {
    pub fn validate(self) -> Result<Self, Error> {
        for (field, value, maximum) in [
            (
                "max_evidence_frames",
                self.max_evidence_frames,
                DEFAULT_CAPTURE_QUEUE_FRAMES,
            ),
            (
                "max_evidence_bytes",
                self.max_evidence_bytes,
                DEFAULT_CAPTURE_QUEUE_BYTES,
            ),
        ] {
            if value == 0 || value > maximum {
                return Err(Error::InvalidRequest {
                    field,
                    message: format!("must be within 1..={maximum}; received {value}"),
                });
            }
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveOptions {
    pub timeout: Duration,
    pub cases_per_second: Option<u32>,
    pub destination: Option<IpAddr>,
    /// Independent call-site opt-in for a permissive live frame.
    pub allow_permissive_live: bool,
    pub limits: LiveLimits,
}

impl Default for LiveOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(1),
            cases_per_second: None,
            destination: None,
            allow_permissive_live: false,
            limits: LiveLimits::default(),
        }
    }
}

impl LiveOptions {
    pub fn validate(self) -> Result<Self, Error> {
        self.limits.validate()?;
        if self.timeout.is_zero() || self.timeout > packetcraftr_netio::capture::MAX_TIMEOUT {
            return Err(Error::InvalidRequest {
                field: "timeout",
                message: format!(
                    "must be finite, non-zero, and no greater than {:?}; received {:?}",
                    packetcraftr_netio::capture::MAX_TIMEOUT,
                    self.timeout
                ),
            });
        }
        if let Some(rate) = self.cases_per_second
            && (rate == 0 || rate > MAX_RATE)
        {
            return Err(Error::InvalidRequest {
                field: "cases_per_second",
                message: format!("must be within 1..={MAX_RATE}; received {rate}"),
            });
        }
        Ok(self)
    }
}
