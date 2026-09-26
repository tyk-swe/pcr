// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::policy::{DnsOperation, LimitOverflow, SocketLimits, WireLimits};

use super::MAX_PROBE_OVERHEAD;
use super::error::Error;
use super::{Request, TransportMode};

/// The complete finite cost one DNS operation may incur, approved before any
/// resolver, route, capture, or socket side effect.
pub(super) struct OperationLimits {
    pub(super) packet_count: u64,
    pub(super) maximum_wire_bytes: u64,
    /// The socket cost of direct TCP or a possible continuation, or
    /// [`SocketLimits::none`] for UDP-only queries. DNS always
    /// states the shape, so the same overrun is charged and classified the
    /// same way whether or not fallback is enabled.
    pub(super) tcp: SocketLimits,
    /// Intentional delay between attempts at the requested rate.
    pub(super) delay: Duration,
}

/// Sum every question's worst-case UDP and TCP cost before any batch traffic.
pub(super) fn batch_limits(
    mut operations: impl Iterator<Item = DnsOperation>,
) -> Result<DnsOperation, Error> {
    operations.try_fold(
        DnsOperation::new(WireLimits::new(0, 0), SocketLimits::none())?,
        |total, operation| {
            let udp = total.udp();
            let tcp = total.tcp();
            Ok(DnsOperation::new(
                WireLimits::new(
                    udp.packets()
                        .checked_add(operation.udp().packets())
                        .ok_or(LimitOverflow)?,
                    udp.wire_bytes()
                        .checked_add(operation.udp().wire_bytes())
                        .ok_or(LimitOverflow)?,
                ),
                SocketLimits::new(
                    tcp.connections()
                        .checked_add(operation.tcp().connections())
                        .ok_or(LimitOverflow)?,
                    tcp.messages()
                        .checked_add(operation.tcp().messages())
                        .ok_or(LimitOverflow)?,
                    tcp.application_bytes()
                        .checked_add(operation.tcp().application_bytes())
                        .ok_or(LimitOverflow)?,
                ),
            )?)
        },
    )
}

pub(super) fn operation_limits(
    request: &Request,
    query_bytes: usize,
) -> Result<OperationLimits, Error> {
    let attempts = u64::from(request.attempts);
    let packet_count = if request.transport == TransportMode::Tcp {
        0
    } else {
        attempts
    };
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
    let tcp = if request.transport != TransportMode::Udp {
        socket_limits(attempts, query_bytes)?
    } else {
        SocketLimits::none()
    };
    let delay = rate_delay(request.queries_per_second)?;
    let worst_case = worst_case_duration(request, delay)?;
    if worst_case > request.limits.max_duration {
        return Err(Error::DurationLimit {
            actual: worst_case,
            limit: request.limits.max_duration,
        });
    }
    Ok(OperationLimits {
        packet_count,
        maximum_wire_bytes,
        tcp,
        delay,
    })
}

fn socket_limits(packet_count: u64, query_bytes: u64) -> Result<SocketLimits, Error> {
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
    Ok(SocketLimits::new(
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
