// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded traceroute hop-batch and duration planning.

use std::net::IpAddr;
use std::time::Duration;

use super::error::TracerouteError;
use super::model::{TracerouteBatch, TracerouteProbe, TracerouteRequest, TracerouteStrategy};

#[expect(
    clippy::cast_possible_truncation,
    reason = "the sequence is reduced to a 16-bit port offset; the checked_add below rejects any \
              value that would leave the validated UDP probe port range"
)]
pub(super) fn build_batches(
    request: &TracerouteRequest,
    destination: IpAddr,
) -> Result<Vec<TracerouteBatch>, TracerouteError> {
    let mut batches = Vec::with_capacity(request.hop_count());
    let mut sequence = 0_u64;
    for hop_limit in request.first_hop..=request.max_hops {
        let mut probes =
            Vec::with_capacity(usize::try_from(request.probes_per_hop).unwrap_or(usize::MAX));
        for attempt in 1..=request.probes_per_hop {
            let destination_port = match request.strategy {
                TracerouteStrategy::Udp => Some(
                    request
                        .destination_port
                        .expect("validated UDP port")
                        .checked_add(sequence as u16)
                        .expect("validated UDP probe port range"),
                ),
                TracerouteStrategy::Tcp => request.destination_port,
                TracerouteStrategy::Icmp => None,
            };
            probes.push(TracerouteProbe {
                sequence,
                address: destination,
                strategy: request.strategy,
                destination_port,
                hop_limit,
                attempt,
            });
            sequence = sequence
                .checked_add(1)
                .ok_or(TracerouteError::InvalidLimit {
                    field: "probes",
                    value: u64::MAX,
                    reason: "probe sequence overflowed".to_owned(),
                })?;
        }
        batches.push(TracerouteBatch {
            probes,
            timeout: request.timeout,
            permit: crate::evidence::ExecutionPermit::new(),
        });
    }
    Ok(batches)
}

pub(super) fn worst_case_duration(
    request: &TracerouteRequest,
) -> Result<Duration, TracerouteError> {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "hop_count is usize::from(max_hops - first_hop) + 1 with both bounds u8, so it \
                  never exceeds 256"
    )]
    let hops = request.hop_count() as u32;
    let exchange = request
        .timeout
        .checked_mul(hops)
        .ok_or(TracerouteError::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })?;
    let delay = rate_delay(
        usize::try_from(request.probes_per_hop).unwrap_or(usize::MAX),
        request.probes_per_second,
    )?
    .checked_mul(hops.saturating_sub(1))
    .ok_or(TracerouteError::DurationLimit {
        actual: Duration::MAX,
        limit: request.limits.max_duration,
    })?;
    exchange
        .checked_add(delay)
        .ok_or(TracerouteError::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })
}

fn rate_delay(probes: usize, rate: Option<u32>) -> Result<Duration, TracerouteError> {
    crate::clock::rate_delay(probes, rate).ok_or(TracerouteError::InvalidLimit {
        field: "probes_per_second",
        value: u64::from(rate.unwrap_or_default()),
        reason: "rate-delay arithmetic overflowed".to_owned(),
    })
}
