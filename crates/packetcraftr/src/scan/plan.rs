// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded scan batch and duration planning before live execution.

use std::net::IpAddr;
use std::time::Duration;

use super::WORKFLOW;
use super::model::{Batch, Probe, ProbeEndpoint, Request};
use crate::probe::{Error, ErrorKind};

pub(super) fn build_batches(
    request: &Request,
    addresses: &[IpAddr],
    endpoints: &[ProbeEndpoint],
) -> Result<Vec<Batch>, Error> {
    let batch_size = checked_batch_size(request)?;
    let mut batches = Vec::new();
    let mut sequence = 0_u64;
    for address in addresses {
        for attempt in 1..=request.attempts {
            for chunk in endpoints.chunks(batch_size) {
                let batch_sequence = sequence;
                let probes = chunk
                    .iter()
                    .map(|endpoint| {
                        let probe = Probe {
                            sequence,
                            address: *address,
                            endpoint: *endpoint,
                            attempt,
                        };
                        sequence = sequence.checked_add(1).ok_or(Error::new(
                            WORKFLOW,
                            ErrorKind::InvalidLimit {
                                field: "probes",
                                value: u64::MAX,
                                reason: "probe sequence overflowed".to_owned(),
                            },
                        ))?;
                        Ok(probe)
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                batches.push(Batch {
                    probes,
                    timeout: request.timeout,
                    permit: crate::evidence::ExecutionPermit::new(),
                    sequence: batch_sequence,
                });
            }
        }
    }
    Ok(batches)
}

pub(super) fn worst_case_duration(
    request: &Request,
    address_count: usize,
    endpoints_per_address: usize,
) -> Result<Duration, Error> {
    let batch_size = checked_batch_size(request)?;
    let batches_per_attempt = endpoints_per_address.div_ceil(batch_size);
    let batch_count = address_count
        .checked_mul(usize::try_from(request.attempts).unwrap_or(usize::MAX))
        .and_then(|count| count.checked_mul(batches_per_attempt))
        .ok_or(Error::new(
            WORKFLOW,
            ErrorKind::DurationLimit {
                actual: Duration::MAX,
                limit: request.limits.max_duration,
            },
        ))?;
    let batch_count_u32 = u32::try_from(batch_count).map_err(|_| {
        Error::new(
            WORKFLOW,
            ErrorKind::DurationLimit {
                actual: Duration::MAX,
                limit: request.limits.max_duration,
            },
        )
    })?;
    let exchange_time = request
        .timeout
        .checked_mul(batch_count_u32)
        .ok_or(Error::new(
            WORKFLOW,
            ErrorKind::DurationLimit {
                actual: Duration::MAX,
                limit: request.limits.max_duration,
            },
        ))?;
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "checked_batch_size returned a non-zero divisor"
    )]
    let final_batch_size = endpoints_per_address % batch_size;
    let delay =
        (0..batch_count.saturating_sub(1)).try_fold(Duration::ZERO, |total, batch_index| {
            #[expect(
                clippy::arithmetic_side_effects,
                reason = "`batch_count` is a multiple of `batches_per_attempt`, so this range is \
                          empty when `batches_per_attempt` is zero; `position` is below it and \
                          therefore below usize::MAX"
            )]
            let position = batch_index % batches_per_attempt;
            #[expect(
                clippy::arithmetic_side_effects,
                reason = "`position` is a remainder modulo `batches_per_attempt`, so it is below \
                          usize::MAX and the increment cannot overflow"
            )]
            let is_final_batch = position + 1 == batches_per_attempt;
            let probes = if is_final_batch && final_batch_size != 0 {
                final_batch_size
            } else {
                batch_size
            };
            total
                .checked_add(rate_delay(probes, request.probes_per_second)?)
                .ok_or(Error::new(
                    WORKFLOW,
                    ErrorKind::DurationLimit {
                        actual: Duration::MAX,
                        limit: request.limits.max_duration,
                    },
                ))
        })?;
    exchange_time.checked_add(delay).ok_or(Error::new(
        WORKFLOW,
        ErrorKind::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        },
    ))
}

fn checked_batch_size(request: &Request) -> Result<usize, Error> {
    if request.limits.batch_size == 0 {
        return Err(Error::new(
            WORKFLOW,
            ErrorKind::InvalidLimit {
                field: "batch_size",
                value: 0,
                reason: "must be non-zero".to_owned(),
            },
        ));
    }
    Ok(request.limits.batch_size)
}

fn rate_delay(probes: usize, rate: Option<u32>) -> Result<Duration, Error> {
    crate::clock::rate_delay(probes, rate).ok_or(Error::new(
        WORKFLOW,
        ErrorKind::InvalidLimit {
            field: "probes_per_second",
            value: u64::from(rate.unwrap_or_default()),
            reason: "rate-delay arithmetic overflowed".to_owned(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use crate::target::{Family, Target};

    use super::*;

    #[test]
    fn zero_batch_size_is_rejected_inside_planning() {
        let address = "192.0.2.1".parse().expect("documentation address");
        let request = Request {
            target: Target::Address(address),
            transport: crate::scan::model::Transport::Tcp,
            address_family: Family::Any,
            ports: vec![80],
            attempts: 1,
            timeout: Duration::from_millis(1),
            probes_per_second: None,
            limits: crate::scan::model::Limits {
                batch_size: 0,
                ..crate::scan::model::Limits::default()
            },
        };
        assert!(matches!(
            build_batches(&request, &[address], &[ProbeEndpoint::Tcp { port: 80 }]),
            Err(Error {
                kind: ErrorKind::InvalidLimit {
                    field: "batch_size",
                    value: 0,
                    ..
                },
                ..
            })
        ));
        assert!(matches!(
            worst_case_duration(&request, 1, 1),
            Err(Error {
                kind: ErrorKind::InvalidLimit {
                    field: "batch_size",
                    value: 0,
                    ..
                },
                ..
            })
        ));
    }
}
