// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Validation of bounded exchange options.

use std::time::Instant;

use packetcraftr_network::capture::Limits as CaptureQueueLimits;

use super::super::send::ClientError;
use super::{ExchangeOptions, MAX_EXCHANGE_TIMEOUT};

impl ExchangeOptions {
    /// Validates every finite timeout and aggregate retention bound before a
    /// resolver, route, neighbor, capture, or transmission provider is used.
    pub fn validate(&self) -> Result<CaptureQueueLimits, ClientError> {
        if self.timeout > MAX_EXCHANGE_TIMEOUT {
            return Err(ClientError::InvalidExchangeOption {
                field: "timeout",
                message: format!("must not exceed {MAX_EXCHANGE_TIMEOUT:?}"),
            });
        }
        if self.max_template_packets == 0 {
            return Err(ClientError::InvalidExchangeOption {
                field: "max_template_packets",
                message: "must be greater than zero".to_owned(),
            });
        }
        for (field, value) in [
            ("max_responses", self.max_responses),
            ("max_unsolicited", self.max_unsolicited),
        ] {
            if value > self.max_capture_queue_frames {
                return Err(ClientError::InvalidExchangeOption {
                    field,
                    message: format!(
                        "{value} exceeds aggregate capture frame ceiling {}",
                        self.max_capture_queue_frames
                    ),
                });
            }
        }
        Instant::now().checked_add(self.timeout).ok_or_else(|| {
            ClientError::InvalidExchangeOption {
                field: "timeout",
                message: "cannot be represented by the platform monotonic clock".to_owned(),
            }
        })?;
        CaptureQueueLimits {
            max_frames: self.max_capture_queue_frames,
            max_bytes: self.max_captured_bytes,
            snap_length: self.decode.max_packet_size,
            overflow_policy: self.capture_overflow_policy,
        }
        .validate()
        .map_err(ClientError::from)
    }
}
