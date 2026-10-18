// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod packet;
mod reply_identity;
pub(super) use reply_identity::{replies_overlap, response_protocol};

use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_core::packet::Packet;

use super::Error;
use super::Request;
use super::error::probe_error;
use crate::execution::rate_delay;
use crate::probe::{self, Batch};
use packetcraftr_core::error::BoundaryError;

/// The workflow stage a probe belongs to. Discovery probes come first and
/// share one sequence space with the scan probes after them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Stage {
    Discovery,
    Scan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub sequence: u64,
    pub stage: Stage,
    pub address: IpAddr,
    pub scope: Option<crate::target::ResolvedZone>,
    pub endpoint: probe::Endpoint,
    pub tcp_scan: super::TcpScan,
    pub sctp_scan: super::SctpScan,
    pub attempt: u32,
    pub udp_payload: bytes::Bytes,
    pub udp_profile: Option<std::sync::Arc<super::profile::UdpProfile>>,
}

impl Probe {
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

impl Batch<Probe> {
    pub(super) fn single(probe: Probe, timeout: Duration) -> Self {
        Self {
            sequence: probe.sequence,
            probes: vec![probe],
            timeout,
            permit: crate::evidence::ExecutionPermit::new(),
        }
    }

    pub(crate) fn probe(&self) -> Result<&Probe, BoundaryError> {
        match self.probes.as_slice() {
            [probe] => Ok(probe),
            _ => Err(super::executor::EXECUTOR_FAULT.invalid(format!(
                "scan batch at probe {} carries {} probes instead of one",
                self.sequence,
                self.probes.len()
            ))),
        }
    }
}

pub(super) fn probe_count(
    address_count: usize,
    endpoints_per_address: usize,
    attempts: u32,
) -> Result<usize, Error> {
    address_count
        .checked_mul(endpoints_per_address)
        .and_then(|value| value.checked_mul(usize::try_from(attempts).unwrap_or(usize::MAX)))
        .ok_or(Error::InvalidLimit {
            field: "probes",
            value: u64::MAX,
            reason: "probe-count arithmetic overflowed".to_owned(),
        })
}

pub(super) fn sequence(
    first: u64,
    attempt: u32,
    endpoint: usize,
    endpoints: usize,
    host: usize,
    hosts: usize,
) -> u64 {
    first.saturating_add(
        ((u64::from(attempt) - 1)
            .saturating_mul(endpoints as u64)
            .saturating_add(endpoint as u64))
        .saturating_mul(hosts as u64)
        .saturating_add(host as u64),
    )
}

/// One batch per probe, ordered target, attempt, then endpoint, numbered
/// from `first_sequence`.
pub(super) fn build_batches<'a>(
    request: &'a Request,
    targets: &'a [crate::target::SelectedAddress],
    endpoints: &'a [probe::Endpoint],
    stage: Stage,
    first_sequence: u64,
) -> impl Iterator<Item = Batch<Probe>> + 'a {
    targets
        .iter()
        .flat_map(move |target| {
            (1..=request.attempts).flat_map(move |attempt| {
                endpoints
                    .iter()
                    .map(move |endpoint| (target, attempt, *endpoint))
            })
        })
        .zip(first_sequence..)
        .map(move |((target, attempt, endpoint), sequence)| {
            Batch::single(
                planned_probe(request, sequence, stage, target, endpoint, attempt),
                request.timeout,
            )
        })
}

pub(super) fn planned_probe(
    request: &Request,
    sequence: u64,
    stage: Stage,
    target: &crate::target::SelectedAddress,
    endpoint: probe::Endpoint,
    attempt: u32,
) -> Probe {
    // Payloads and profiles are UDP-only; a TCP endpoint sharing the
    // port number must not inherit them.
    let (udp_profile, udp_payload) = match endpoint {
        probe::Endpoint::Udp { port } => {
            let profile = request.udp_profiles.get(&port);
            let payload = profile.map_or_else(
                || request.udp_payload.clone(),
                |profile| profile.payload(sequence),
            );
            (profile.cloned(), payload)
        }
        probe::Endpoint::Tcp { .. }
        | probe::Endpoint::TcpAck { .. }
        | probe::Endpoint::Sctp { .. }
        | probe::Endpoint::Icmp
        | probe::Endpoint::IcmpTimestamp
        | probe::Endpoint::IcmpNetmask
        | probe::Endpoint::Ip { .. } => (None, bytes::Bytes::new()),
    };
    let tcp_scan = match (stage, endpoint) {
        (Stage::Scan, probe::Endpoint::Tcp { .. }) => request.tcp_scan,
        (Stage::Discovery, probe::Endpoint::TcpAck { .. }) => super::TcpScan::Ack,
        _ => super::TcpScan::default(),
    };
    let sctp_scan = match (stage, endpoint) {
        (Stage::Scan, probe::Endpoint::Sctp { .. }) => request.sctp_scan,
        _ => super::SctpScan::default(),
    };
    Probe {
        sequence,
        stage,
        address: target.address,
        scope: target.scope.clone(),
        endpoint,
        tcp_scan,
        sctp_scan,
        attempt,
        udp_profile,
        udp_payload,
    }
}

fn overflow(request: &Request) -> Error {
    Error::DurationLimit {
        actual: Duration::MAX,
        limit: request.limits.max_duration,
    }
}

pub(super) fn worst_case_duration(
    request: &Request,
    batch_count: usize,
) -> Result<Duration, Error> {
    let batch_count_u32 = u32::try_from(batch_count).map_err(|_| overflow(request))?;
    let windows = if request.max_in_flight == 1 {
        batch_count_u32
    } else {
        batch_count_u32.div_ceil(request.max_in_flight as u32)
    };
    duration_with_windows(request, batch_count_u32, windows)
}

/// Bound each potentially overlapping send by an additional timeout. Distinct
/// IP protocols and addresses retain the ordinary parallel projection.
pub(super) fn ip_worst_case_duration(
    request: &Request,
    batch_count: usize,
    targets: &[crate::target::SelectedAddress],
    endpoints: &[probe::Endpoint],
) -> Result<Duration, Error> {
    if batch_count == 0 {
        return Ok(Duration::ZERO);
    }
    let count = u32::try_from(batch_count).map_err(|_| overflow(request))?;
    let parallel = batch_count.div_ceil(request.max_in_flight.max(1));
    let extra = reply_identity::overlap_waits(targets, endpoints, request.attempts)
        .ok_or_else(|| overflow(request))?;
    let windows = parallel
        .checked_add(extra)
        .ok_or_else(|| overflow(request))?
        .min(batch_count);
    duration_with_windows(
        request,
        count,
        u32::try_from(windows).map_err(|_| overflow(request))?,
    )
}

fn pacing_delay(request: &Request, delay_count: u32) -> Result<Duration, Error> {
    if delay_count == 0 {
        return Ok(Duration::ZERO);
    }
    rate_delay(
        probe_error,
        "probes_per_second",
        1,
        request.probes_per_second,
    )?
    .checked_mul(delay_count)
    .ok_or_else(|| overflow(request))
}

fn duration_with_windows(
    request: &Request,
    batch_count_u32: u32,
    windows: u32,
) -> Result<Duration, Error> {
    let exchange_time = request
        .timeout
        .checked_mul(windows)
        .ok_or_else(|| overflow(request))?;
    let delay_count = batch_count_u32.saturating_sub(1);
    let delay = pacing_delay(request, delay_count)?;
    exchange_time
        .checked_add(delay)
        .ok_or_else(|| overflow(request))
}

/// Scheduling upper projection for adaptive work. It intentionally assumes a
/// fully serial exchange: every probe can wait out `max_timeout`, plus pacing,
/// per-endpoint retry backoffs, and the worst inferred per-host spacing. It
/// excludes provider overrun and contended worker waits; the operation
/// deadline stays the hard bound regardless.
pub(super) fn adaptive_worst_case_duration(
    request: &Request,
    adaptive: &super::Adaptive,
    batch_count: usize,
) -> Result<Duration, Error> {
    if batch_count == 0 {
        return Ok(Duration::ZERO);
    }
    let batch_count_u32 = u32::try_from(batch_count).map_err(|_| overflow(request))?;
    let exchange_time = adaptive
        .max_timeout
        .checked_mul(batch_count_u32)
        .ok_or_else(|| overflow(request))?;
    let delay_count = batch_count_u32.saturating_sub(1);
    let delay = pacing_delay(request, delay_count)?;
    let distinct = batch_count_u32
        .checked_div(request.attempts.max(1))
        .unwrap_or(1);
    let mut retry_gaps = Duration::ZERO;
    for attempt in 2..=request.attempts.max(1) {
        let gap = adaptive.retry_delay(attempt);
        retry_gaps = retry_gaps
            .checked_add(gap)
            .ok_or_else(|| overflow(request))?;
    }
    let retry_total = retry_gaps
        .checked_mul(distinct)
        .ok_or_else(|| overflow(request))?;
    let spacing = adaptive
        .max_backoff
        .checked_mul(delay_count)
        .ok_or_else(|| overflow(request))?;
    exchange_time
        .checked_add(delay)
        .and_then(|total| total.checked_add(retry_total))
        .and_then(|total| total.checked_add(spacing))
        .ok_or_else(|| overflow(request))
}
