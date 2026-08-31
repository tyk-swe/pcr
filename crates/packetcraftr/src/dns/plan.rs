// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded DNS operation budget and worst-case duration planning.

use std::time::Duration;

use crate::authorization::SocketBudget;

use super::MAX_PROBE_OVERHEAD;
use super::error::Error;
use super::model::Request;

/// The complete finite cost one DNS operation may incur, approved before any
/// resolver, route, capture, or socket side effect.
pub(super) struct OperationBudget {
    pub(super) packet_count: u64,
    pub(super) maximum_wire_bytes: u64,
    /// The socket cost of a possible TCP continuation, or
    /// [`SocketBudget::none`] when no continuation is configured. DNS always
    /// states the shape, so the same overrun is charged and classified the
    /// same way whether or not fallback is enabled.
    pub(super) tcp: SocketBudget,
    /// Intentional delay between attempts at the requested rate.
    pub(super) delay: Duration,
}

pub(super) fn operation_budget(
    request: &Request,
    query_bytes: usize,
) -> Result<OperationBudget, Error> {
    let packet_count = u64::from(request.attempts);
    let query_bytes = u64::try_from(query_bytes).unwrap_or(u64::MAX);
    let udp_probe_bytes = query_bytes.saturating_add(MAX_PROBE_OVERHEAD);
    let maximum_wire_bytes =
        packet_count
            .checked_mul(udp_probe_bytes)
            .ok_or(Error::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            })?;
    let tcp = if request.tcp_fallback {
        socket_budget(packet_count, query_bytes)?
    } else {
        SocketBudget::none()
    };
    let delay = rate_delay(request.queries_per_second)?;
    let worst_case = worst_case_duration(request, delay)?;
    if worst_case > request.limits.max_duration {
        return Err(Error::DurationLimit {
            actual: worst_case,
            limit: request.limits.max_duration,
        });
    }
    Ok(OperationBudget {
        packet_count,
        maximum_wire_bytes,
        tcp,
        delay,
    })
}

fn socket_budget(packet_count: u64, query_bytes: u64) -> Result<SocketBudget, Error> {
    let framed_query_bytes = query_bytes.checked_add(2).ok_or(Error::InvalidLimit {
        field: "socket_bytes",
        value: u64::MAX,
        reason: "DNS-over-TCP framing accounting overflowed".to_owned(),
    })?;
    let application_bytes =
        packet_count
            .checked_mul(framed_query_bytes)
            .ok_or(Error::InvalidLimit {
                field: "socket_bytes",
                value: u64::MAX,
                reason: "DNS-over-TCP byte accounting overflowed".to_owned(),
            })?;
    Ok(SocketBudget::new(
        packet_count,
        packet_count,
        application_bytes,
    ))
}

fn worst_case_duration(request: &Request, delay: Duration) -> Result<Duration, Error> {
    request
        .timeout
        .checked_mul(request.attempts)
        .and_then(|duration| {
            delay
                .checked_mul(request.attempts.saturating_sub(1))
                .and_then(|delays| duration.checked_add(delays))
        })
        .ok_or(Error::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })
}

pub(super) fn rate_delay(rate: Option<u32>) -> Result<Duration, Error> {
    crate::clock::rate_delay(1, rate).ok_or(Error::InvalidLimit {
        field: "queries_per_second",
        value: u64::from(rate.unwrap_or_default()),
        reason: "rate-delay arithmetic overflowed".to_owned(),
    })
}
