// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded scan batch and duration planning before live execution.

use std::net::IpAddr;
use std::time::Duration;

use super::error::ScanError;
use super::model::{ScanBatch, ScanProbe, ScanRequest};

pub(super) fn build_batches(
    request: &ScanRequest,
    addresses: &[IpAddr],
    endpoint_ports: &[Option<u16>],
) -> Result<Vec<ScanBatch>, ScanError> {
    let mut batches = Vec::new();
    let mut sequence = 0_u64;
    for address in addresses {
        for attempt in 1..=request.attempts {
            for chunk in endpoint_ports.chunks(request.limits.batch_size) {
                let probes = chunk
                    .iter()
                    .map(|port| {
                        let probe = ScanProbe {
                            sequence,
                            address: *address,
                            transport: request.transport,
                            port: *port,
                            attempt,
                        };
                        sequence = sequence.checked_add(1).ok_or(ScanError::InvalidLimit {
                            field: "probes",
                            value: u64::MAX,
                            reason: "probe sequence overflowed".to_owned(),
                        })?;
                        Ok(probe)
                    })
                    .collect::<Result<Vec<_>, ScanError>>()?;
                batches.push(ScanBatch {
                    probes,
                    timeout: request.timeout,
                });
            }
        }
    }
    Ok(batches)
}

pub(super) fn worst_case_duration(
    request: &ScanRequest,
    address_count: usize,
    endpoints_per_address: usize,
) -> Result<Duration, ScanError> {
    let batches_per_attempt = endpoints_per_address.div_ceil(request.limits.batch_size);
    let batch_count = address_count
        .checked_mul(request.attempts as usize)
        .and_then(|count| count.checked_mul(batches_per_attempt))
        .ok_or(ScanError::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })?;
    let batch_count_u32 = u32::try_from(batch_count).map_err(|_| ScanError::DurationLimit {
        actual: Duration::MAX,
        limit: request.limits.max_duration,
    })?;
    let exchange_time =
        request
            .timeout
            .checked_mul(batch_count_u32)
            .ok_or(ScanError::DurationLimit {
                actual: Duration::MAX,
                limit: request.limits.max_duration,
            })?;
    let final_batch_size = endpoints_per_address % request.limits.batch_size;
    let delay =
        (0..batch_count.saturating_sub(1)).try_fold(Duration::ZERO, |total, batch_index| {
            let position = batch_index % batches_per_attempt;
            let probes = if position + 1 == batches_per_attempt && final_batch_size != 0 {
                final_batch_size
            } else {
                request.limits.batch_size
            };
            total
                .checked_add(rate_delay(probes, request.probes_per_second)?)
                .ok_or(ScanError::DurationLimit {
                    actual: Duration::MAX,
                    limit: request.limits.max_duration,
                })
        })?;
    exchange_time
        .checked_add(delay)
        .ok_or(ScanError::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })
}

fn rate_delay(probes: usize, rate: Option<u32>) -> Result<Duration, ScanError> {
    crate::clock::rate_delay(probes, rate).ok_or(ScanError::InvalidLimit {
        field: "probes_per_second",
        value: u64::from(rate.unwrap_or_default()),
        reason: "rate-delay arithmetic overflowed".to_owned(),
    })
}
