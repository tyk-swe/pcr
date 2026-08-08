// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{MAX_RATE, error::FuzzError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveOptions {
    pub timeout: Duration,
    pub cases_per_second: Option<u32>,
    pub destination: Option<IpAddr>,
    /// Independent call-site opt-in for a permissive/malformed live frame.
    pub allow_malformed_live: bool,
}

impl Default for LiveOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(1),
            cases_per_second: None,
            destination: None,
            allow_malformed_live: false,
        }
    }
}

impl LiveOptions {
    pub fn validate(self) -> Result<Self, FuzzError> {
        if self.timeout.is_zero() || self.timeout > packetcraftr_network::capture::MAX_TIMEOUT {
            return Err(FuzzError::InvalidTimeout {
                value: self.timeout,
                maximum: packetcraftr_network::capture::MAX_TIMEOUT,
            });
        }
        if let Some(rate) = self.cases_per_second
            && (rate == 0 || rate > MAX_RATE)
        {
            return Err(FuzzError::InvalidLimit {
                field: "cases_per_second",
                value: u64::from(rate),
                reason: format!("must be within 1..={MAX_RATE}"),
            });
        }
        Ok(self)
    }
}
