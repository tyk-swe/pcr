// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded traceroute hop-batch and duration planning.

use std::net::IpAddr;
use std::time::Duration;

use super::WORKFLOW;
use super::model::{Batch, Probe, ProbeTarget, Request, Strategy};
use crate::probe::{Error, ErrorKind};

pub(super) fn build_batches(request: &Request, destination: IpAddr) -> Result<Vec<Batch>, Error> {
    let mut batches = Vec::with_capacity(request.hop_count());
    let mut sequence = 0_u64;
    for hop_limit in request.first_hop..=request.max_hops {
        let batch_sequence = sequence;
        let probe_capacity = usize::try_from(request.probes_per_hop).map_err(|_| {
            Error::new(
                WORKFLOW,
                ErrorKind::InvalidLimit {
                    field: "probes_per_hop",
                    value: u64::from(request.probes_per_hop),
                    reason: "probes per hop exceeds addressable memory".to_owned(),
                },
            )
        })?;
        let mut probes = Vec::with_capacity(probe_capacity);
        for attempt in 1..=request.probes_per_hop {
            let target = probe_target(request, sequence)?;
            probes.push(Probe {
                sequence,
                address: destination,
                target,
                hop_limit,
                attempt,
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
        batches.push(Batch {
            probes,
            timeout: request.timeout,
            permit: crate::evidence::ExecutionPermit::new(),
            sequence: batch_sequence,
        });
    }
    Ok(batches)
}

/// Resolves the request's strategy and declared port into the target the probe
/// at `sequence` addresses. UDP walks one unique destination port per probe,
/// so the guard that keeps that walk inside `u16` lives here beside the
/// arithmetic it protects.
fn probe_target(request: &Request, sequence: u64) -> Result<ProbeTarget, Error> {
    let declared_port = || {
        request.destination_port.ok_or_else(|| {
            Error::new(
                WORKFLOW,
                ErrorKind::InvalidPort {
                    message: format!(
                        "{} traceroute requires a destination port",
                        request.strategy
                    ),
                },
            )
        })
    };
    match request.strategy {
        Strategy::Udp => {
            let base = declared_port()?;
            let port = u16::try_from(sequence)
                .ok()
                .and_then(|offset| base.checked_add(offset))
                .ok_or_else(|| {
                    Error::new(
                        WORKFLOW,
                        ErrorKind::InvalidPort {
                            message: format!(
                                "base UDP port {base} plus probe {sequence} exceeds {}",
                                u16::MAX
                            ),
                        },
                    )
                })?;
            Ok(ProbeTarget::Udp { port })
        }
        Strategy::Tcp => Ok(ProbeTarget::Tcp {
            port: declared_port()?,
        }),
        Strategy::Icmp => Ok(ProbeTarget::Icmp),
    }
}

pub(super) fn worst_case_duration(request: &Request) -> Result<Duration, Error> {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "hop_count is usize::from(max_hops - first_hop) + 1 with both bounds u8, so it \
                  never exceeds 256"
    )]
    let hops = request.hop_count() as u32;
    let exchange = request.timeout.checked_mul(hops).ok_or(Error::new(
        WORKFLOW,
        ErrorKind::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        },
    ))?;
    let delay = rate_delay(
        usize::try_from(request.probes_per_hop).unwrap_or(usize::MAX),
        request.probes_per_second,
    )?
    .checked_mul(hops.saturating_sub(1))
    .ok_or(Error::new(
        WORKFLOW,
        ErrorKind::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        },
    ))?;
    exchange.checked_add(delay).ok_or(Error::new(
        WORKFLOW,
        ErrorKind::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        },
    ))
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
