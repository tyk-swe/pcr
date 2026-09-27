// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The finite packet count and pacing schedule, checked before admission.

use super::request::invalid;
use super::{Error, Request};
use packetcraftr_netio::deadline::MAX_WAIT;
use std::time::Duration;

pub(super) struct Plan {
    pub(super) packet_count: u64,
    pub(super) delay: Duration,
}

impl TryFrom<&Request> for Plan {
    type Error = Error;

    fn try_from(request: &Request) -> Result<Self, Error> {
        request.validate()?;
        let count = request
            .template
            .expansion_len()
            .map_err(crate::Error::from)?;
        if count == 0 || count > request.max_template_packets {
            return Err(invalid(
                "max_template_packets",
                "expansion must be non-empty and within the packet ceiling",
            ));
        }
        let total = u64::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(u64::from(request.repeat)))
            .ok_or_else(|| invalid("repeat", "expansion times repetition overflows u64"))?;
        let delay = crate::clock::rate_delay(1, request.rate)
            .ok_or_else(|| invalid("rate", "rate-delay arithmetic overflowed"))?;
        let scheduled_nanos = u128::from(total - 1) * delay.as_nanos();
        if scheduled_nanos > MAX_WAIT.as_nanos() {
            return Err(Error::InvalidRequest {
                field: "rate",
                message: format!(
                    "scheduled pacing {scheduled_nanos} ns exceeds the {MAX_WAIT:?} ceiling"
                ),
            });
        }
        Ok(Self {
            packet_count: total,
            delay,
        })
    }
}
