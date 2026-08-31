// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Validation of bounded exchange options.

use std::time::Instant;

use super::MAX_EXCHANGE_TIMEOUT;
use crate::Error;

impl super::Options {
    /// Validates finite options and retention bounds before live providers run.
    ///
    /// Once this returns, [`Options::capture`](super::Options::capture) is
    /// exactly the bounded queue configuration a capture provider may be armed
    /// with, and every retention ceiling fits inside it.
    pub fn validate(&self) -> Result<(), Error> {
        if self.timeout > MAX_EXCHANGE_TIMEOUT {
            return Err(Error::InvalidExchangeOption {
                field: "timeout",
                message: format!("must not exceed {MAX_EXCHANGE_TIMEOUT:?}"),
            });
        }
        if self.max_template_packets == 0 {
            return Err(Error::InvalidExchangeOption {
                field: "max_template_packets",
                message: "must be greater than zero".to_owned(),
            });
        }
        for (field, value) in [
            ("max_responses", self.max_responses),
            ("max_unmatched_frames", self.max_unmatched_frames),
        ] {
            if value > self.capture.max_frames {
                return Err(Error::InvalidExchangeOption {
                    field,
                    message: format!(
                        "{value} exceeds aggregate capture frame ceiling {}",
                        self.capture.max_frames
                    ),
                });
            }
        }
        Instant::now()
            .checked_add(self.timeout)
            .ok_or_else(|| Error::InvalidExchangeOption {
                field: "timeout",
                message: "cannot be represented by the platform monotonic clock".to_owned(),
            })?;
        self.capture.validate().map_err(Error::from)
    }
}
