// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod packet;

use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_core::packet::Packet;

use super::Error;
use super::Request;
use super::error::Probes;
use crate::execution::rate_delay;
use crate::probe::{Batch, ProbeEndpoint, Transport};

/// One planned traceroute probe: the destination, the endpoint it addresses,
/// and the hop limit and attempt it belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    pub sequence: u64,
    pub address: IpAddr,
    pub target: ProbeEndpoint,
    pub hop_limit: u8,
    pub attempt: u32,
    pub source_port: u16,
}

impl Probe {
    /// Builds the portable IPv4/IPv6 UDP, TCP, or ICMP probe represented by
    /// this already-authorized hop plan.
    #[must_use]
    pub fn packet(&self) -> Packet {
        packet::probe_packet(self)
    }
}

impl crate::probe::runner::Sequenced for Probe {
    fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Plans one batch per hop, each holding that hop's probes.
pub(super) fn build_batches(
    request: &Request,
    destination: IpAddr,
) -> Result<Vec<Batch<Probe>>, Error> {
    let mut batches = Vec::with_capacity(request.hop_count());
    let source_port = request.source_port.unwrap_or(super::SOURCE_PORT);
    let mut sequence = 0_u64;
    for hop_limit in request.first_hop..=request.max_hops {
        let batch_sequence = sequence;
        let probe_capacity =
            usize::try_from(request.probes_per_hop).map_err(|_| Error::InvalidLimit {
                field: "probes_per_hop",
                value: u64::from(request.probes_per_hop),
                reason: "probes per hop exceeds addressable memory".to_owned(),
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
                source_port,
            });
            sequence = sequence.checked_add(1).ok_or(Error::InvalidLimit {
                field: "probes",
                value: u64::MAX,
                reason: "probe sequence overflowed".to_owned(),
            })?;
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
/// at `sequence` addresses. UDP walks one unique destination port per probe, so
/// the walk is guarded to stay inside `u16`.
fn probe_target(request: &Request, sequence: u64) -> Result<ProbeEndpoint, Error> {
    let declared_port = || {
        request.destination_port.ok_or_else(|| Error::InvalidPort {
            message: format!(
                "{} traceroute requires a destination port",
                request.strategy
            ),
        })
    };
    match request.strategy {
        Transport::Udp => {
            let base = declared_port()?;
            let port = u16::try_from(sequence)
                .ok()
                .and_then(|offset| base.checked_add(offset))
                .ok_or_else(|| Error::InvalidPort {
                    message: format!(
                        "base UDP port {base} plus probe {sequence} exceeds {}",
                        u16::MAX
                    ),
                })?;
            Ok(ProbeEndpoint::Udp { port })
        }
        Transport::Tcp => Ok(ProbeEndpoint::Tcp {
            port: declared_port()?,
        }),
        Transport::Icmp => Ok(ProbeEndpoint::Icmp),
    }
}

pub(super) fn worst_case_duration(request: &Request) -> Result<Duration, Error> {
    // hop_count is usize::from(max_hops - first_hop) + 1 with both bounds u8, so it never exceeds
    // 256
    let hops = request.hop_count() as u32;
    let overflow = || Error::DurationLimit {
        actual: Duration::MAX,
        limit: request.limits.max_duration,
    };
    let exchange = request.timeout.checked_mul(hops).ok_or_else(&overflow)?;
    let delay = rate_delay(
        &Probes,
        "probes_per_second",
        usize::try_from(request.probes_per_hop).unwrap_or(usize::MAX),
        request.probes_per_second,
    )?
    .checked_mul(hops.saturating_sub(1))
    .ok_or_else(&overflow)?;
    exchange.checked_add(delay).ok_or_else(overflow)
}
