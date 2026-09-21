// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded scan batch and duration planning before live execution.

use std::net::IpAddr;
use std::time::Duration;

use super::WORKFLOW;
use super::{Batch, Probe, Request};
use super::{IPV4_PROBE_BYTES, IPV6_PROBE_BYTES};
use crate::policy::Authorizer;
use crate::probe::evidence::{check_probe_count, check_probe_duration};
use crate::probe::{Error, ErrorKind, ProbeEndpoint, Transport};
use crate::target::{approve_operation, budgeted};
use packetcraftr_core::budget::Deadline;

pub(super) fn build_batches<'a>(
    request: &'a Request,
    addresses: &'a [IpAddr],
    endpoints: &'a [ProbeEndpoint],
) -> Result<impl Iterator<Item = Batch> + 'a, Error> {
    // Validate the complete sequence space before yielding any external effect.
    addresses
        .len()
        .checked_mul(request.attempts as usize)
        .and_then(|count| count.checked_mul(endpoints.len()))
        .and_then(|count| u64::try_from(count).ok())
        .ok_or(Error::new(
            WORKFLOW,
            ErrorKind::InvalidLimit {
                field: "probes",
                value: u64::MAX,
                reason: "probe sequence overflowed".to_owned(),
            },
        ))?;
    Ok(addresses
        .iter()
        .flat_map(move |address| {
            (1..=request.attempts).flat_map(move |attempt| {
                endpoints
                    .iter()
                    .map(move |endpoint| (*address, attempt, *endpoint))
            })
        })
        .zip(0u64..)
        .map(move |((address, attempt, endpoint), sequence)| Batch {
            probe: Probe {
                sequence,
                address,
                endpoint,
                attempt,
                udp_profile: endpoint
                    .port()
                    .and_then(|port| request.udp_profiles.get(&port))
                    .cloned(),
                udp_payload: endpoint
                    .port()
                    .and_then(|port| request.udp_profiles.get(&port))
                    .map_or_else(
                        || request.udp_payload.clone(),
                        |profile| profile.payload(sequence),
                    ),
            },
            timeout: request.timeout,
            permit: crate::evidence::ExecutionPermit::new(),
        }))
}

pub(super) fn worst_case_duration(
    request: &Request,
    address_count: usize,
    endpoints_per_address: usize,
) -> Result<Duration, Error> {
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
    let windows = if request.max_in_flight == 1 {
        batch_count_u32
    } else {
        batch_count_u32.div_ceil(request.max_in_flight as u32)
    };
    let exchange_time = request.timeout.checked_mul(windows).ok_or_else(&overflow)?;
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

pub(super) struct ApprovedScan {
    pub(super) planned_duration: std::time::Duration,
    pub(super) declared_target: String,
    pub(super) addresses: Vec<IpAddr>,
    pub(super) endpoints: Vec<ProbeEndpoint>,
}

pub(super) fn approve_scan<A: Authorizer>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
) -> Result<ApprovedScan, Error> {
    let ports = request.selected_ports()?;
    // Implementations must authorize the declared target before DNS and every
    // answer before anything below constructs a probe.
    let addresses = super::targets::resolve(request, authorizer, deadline)?;
    if addresses.is_empty() {
        return Err(Error::new(
            WORKFLOW,
            ErrorKind::Family {
                family: request.address_family.label(),
            },
        ));
    }

    let endpoints_per_address = if request.transport == Transport::Icmp {
        1
    } else {
        ports.len()
    };
    let total_probes = probe_count(addresses.len(), endpoints_per_address, request.attempts)?;
    check_probe_count(WORKFLOW, total_probes, request.limits.max_probes)?;
    let maximum_bytes = maximum_wire_bytes(&addresses, &ports, request)?;
    let worst_case = worst_case_duration(request, addresses.len(), endpoints_per_address)?;
    check_probe_duration(WORKFLOW, worst_case, request.limits.max_duration)?;
    approve_operation(
        authorizer,
        budgeted(
            u64::try_from(total_probes).unwrap_or(u64::MAX),
            maximum_bytes,
        ),
        deadline,
        &WORKFLOW,
    )?;

    let endpoints = probe_endpoints(request.transport, ports);
    Ok(ApprovedScan {
        planned_duration: worst_case,
        declared_target: request.targets.to_string(),
        addresses,
        endpoints,
    })
}

/// Expands the authorized port selection into probe endpoints for `transport`.
fn probe_endpoints(transport: Transport, ports: Vec<u16>) -> Vec<ProbeEndpoint> {
    match transport {
        Transport::Icmp => vec![ProbeEndpoint::Icmp],
        Transport::Tcp => ports
            .into_iter()
            .map(|port| ProbeEndpoint::Tcp { port })
            .collect(),
        Transport::Udp => ports
            .into_iter()
            .map(|port| ProbeEndpoint::Udp { port })
            .collect(),
    }
}

fn probe_count(
    address_count: usize,
    endpoints_per_address: usize,
    attempts: u32,
) -> Result<usize, Error> {
    address_count
        .checked_mul(endpoints_per_address)
        .and_then(|value| value.checked_mul(usize::try_from(attempts).unwrap_or(usize::MAX)))
        .ok_or(Error::new(
            WORKFLOW,
            ErrorKind::InvalidLimit {
                field: "probes",
                value: u64::MAX,
                reason: "probe-count arithmetic overflowed".to_owned(),
            },
        ))
}

fn maximum_wire_bytes(
    addresses: &[IpAddr],
    ports: &[u16],
    request: &Request,
) -> Result<u64, Error> {
    let overflow = || {
        Error::new(
            WORKFLOW,
            ErrorKind::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "scan payload accounting overflowed".to_owned(),
            },
        )
    };
    let endpoints = if request.transport == Transport::Icmp {
        1
    } else {
        ports.len() as u64
    };
    let payload = if request.transport == Transport::Udp {
        ports.iter().try_fold(0u64, |total, port| {
            total
                .checked_add(
                    request
                        .udp_profiles
                        .get(port)
                        .map_or(request.udp_payload.len(), |profile| {
                            profile.payload_length()
                        }) as u64,
                )
                .ok_or_else(overflow)
        })?
    } else {
        0
    };
    addresses.iter().try_fold(0u64, |total, address| {
        let header = if address.is_ipv4() {
            IPV4_PROBE_BYTES
        } else {
            IPV6_PROBE_BYTES
        };
        let bytes = header
            .checked_mul(endpoints)
            .and_then(|bytes| bytes.checked_add(payload))
            .and_then(|bytes| bytes.checked_mul(u64::from(request.attempts)))
            .ok_or_else(overflow)?;
        total.checked_add(bytes).ok_or_else(overflow)
    })
}

#[cfg(test)]
mod tests {
    use crate::target::{Family, Target};

    use super::*;

    #[test]
    fn duration_planning_preserves_per_gap_rounding_empty_plans_and_overflow() {
        let mut request = Request {
            max_in_flight: 1,
            targets: Target::Address("192.0.2.1".parse().expect("documentation address")).into(),
            transport: crate::probe::Transport::Tcp,
            address_family: Family::Any,
            ports: vec![80],
            attempts: 1,
            timeout: Duration::from_millis(1),
            probes_per_second: Some(3),
            udp_payload: bytes::Bytes::new(),
            udp_profiles: Default::default(),
            limits: crate::scan::Limits::default(),
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
