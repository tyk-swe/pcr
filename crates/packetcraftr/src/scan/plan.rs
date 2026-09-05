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
    check_batch_size(request)?;
    let mut batches = Vec::new();
    let mut sequence = 0_u64;
    for address in addresses {
        for attempt in 1..=request.attempts {
            // Each exchange materializes its own correlated sequence and IP identifiers.
            for endpoint in endpoints {
                batches.push(Batch {
                    probes: vec![Probe {
                        sequence,
                        address: *address,
                        endpoint: *endpoint,
                        attempt,
                    }],
                    timeout: request.timeout,
                    permit: crate::evidence::ExecutionPermit::new(),
                    sequence,
                });
                sequence = sequence.checked_add(1).ok_or(Error::new(
                    WORKFLOW,
                    ErrorKind::InvalidLimit {
                        field: "probes",
                        value: u64::MAX,
                        reason: "probe sequence overflowed".to_owned(),
                    },
                ))?;
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
    check_batch_size(request)?;
    let overflow = || {
        Error::new(
            WORKFLOW,
            ErrorKind::DurationLimit {
                actual: Duration::MAX,
                limit: request.limits.max_duration,
            },
        )
    };
    let batch_count = address_count
        .checked_mul(usize::try_from(request.attempts).unwrap_or(usize::MAX))
        .and_then(|count| count.checked_mul(endpoints_per_address))
        .ok_or_else(&overflow)?;
    let batch_count_u32 = u32::try_from(batch_count).map_err(|_| overflow())?;
    let exchange_time = request
        .timeout
        .checked_mul(batch_count_u32)
        .ok_or_else(&overflow)?;
    let delay_count = batch_count_u32.saturating_sub(1);
    let delay = if delay_count == 0 {
        Duration::ZERO
    } else {
        rate_delay(request.probes_per_second)?
            .checked_mul(delay_count)
            .ok_or_else(&overflow)?
    };
    exchange_time.checked_add(delay).ok_or_else(overflow)
}

fn check_batch_size(request: &Request) -> Result<(), Error> {
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
    Ok(())
}

fn rate_delay(rate: Option<u32>) -> Result<Duration, Error> {
    crate::clock::rate_delay(1, rate).ok_or(Error::new(
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

    #[test]
    fn duration_planning_preserves_per_gap_rounding_empty_plans_and_overflow() {
        let mut request = Request {
            target: Target::Address("192.0.2.1".parse().expect("documentation address")),
            transport: crate::scan::model::Transport::Tcp,
            address_family: Family::Any,
            ports: vec![80],
            attempts: 1,
            timeout: Duration::from_millis(1),
            probes_per_second: Some(3),
            limits: crate::scan::model::Limits::default(),
        };
        for (addresses, endpoints, expected) in [
            (0, 1, Duration::ZERO),
            (1, 0, Duration::ZERO),
            (1, 1, request.timeout),
            (1, 3, Duration::from_nanos(669_666_668)),
        ] {
            assert_eq!(
                worst_case_duration(&request, addresses, endpoints).expect("bounded duration"),
                expected
            );
        }

        request.probes_per_second = Some(0);
        assert_eq!(worst_case_duration(&request, 0, 1).unwrap(), Duration::ZERO);
        assert_eq!(
            worst_case_duration(&request, 1, 1).unwrap(),
            request.timeout
        );
        assert!(matches!(
            worst_case_duration(&request, 1, 2),
            Err(Error {
                kind: ErrorKind::InvalidLimit {
                    field: "probes_per_second",
                    ..
                },
                ..
            })
        ));

        request.timeout = Duration::MAX;
        for (addresses, endpoints) in [(usize::MAX, 2), (1, 2)] {
            assert!(matches!(
                worst_case_duration(&request, addresses, endpoints),
                Err(Error {
                    kind: ErrorKind::DurationLimit {
                        actual: Duration::MAX,
                        ..
                    },
                    ..
                })
            ));
        }
    }
}
