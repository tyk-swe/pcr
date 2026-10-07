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
use crate::probe::{Batch, ProbeEndpoint};
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
    pub endpoint: ProbeEndpoint,
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

/// One batch per probe, ordered target, attempt, then endpoint, numbered
/// from `first_sequence`.
pub(super) fn build_batches<'a>(
    request: &'a Request,
    targets: &'a [crate::target::SelectedAddress],
    endpoints: &'a [ProbeEndpoint],
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
            // Payloads and profiles are UDP-only; a TCP endpoint sharing the
            // port number must not inherit them.
            let (udp_profile, udp_payload) = match endpoint {
                ProbeEndpoint::Udp { port } => {
                    let profile = request.udp_profiles.get(&port);
                    let payload = profile.map_or_else(
                        || request.udp_payload.clone(),
                        |profile| profile.payload(sequence),
                    );
                    (profile.cloned(), payload)
                }
                ProbeEndpoint::Tcp { .. } | ProbeEndpoint::Icmp => (None, bytes::Bytes::new()),
            };
            Batch::single(
                Probe {
                    sequence,
                    stage,
                    address: target.address,
                    scope: target.scope.clone(),
                    endpoint,
                    attempt,
                    udp_profile,
                    udp_payload,
                },
                request.timeout,
            )
        })
}

pub(super) fn worst_case_duration(
    request: &Request,
    batch_count: usize,
) -> Result<Duration, Error> {
    let overflow = || Error::DurationLimit {
        actual: Duration::MAX,
        limit: request.limits.max_duration,
    };
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
        rate_delay(&Probes, "probes_per_second", 1, request.probes_per_second)?
            .checked_mul(delay_count)
            .ok_or_else(&overflow)?
    };
    exchange_time.checked_add(delay).ok_or_else(overflow)
}

#[cfg(test)]
mod tests {
    use crate::target::{Family, Target};

    use super::*;

    #[test]
    fn duration_planning_preserves_per_gap_rounding_empty_plans_and_overflow() {
        let mut request = Request {
            target_sources: Vec::new(),
            max_in_flight: 1,
            targets: Target::Address("192.0.2.1".parse().expect("documentation address")).into(),
            address_family: Family::Any,
            endpoints: vec![crate::probe::ProbeEndpoint::Tcp { port: 80 }],
            discovery: Default::default(),
            attempts: 1,
            timeout: Duration::from_millis(1),
            probes_per_second: Some(3),
            udp_payload: bytes::Bytes::new(),
            udp_profiles: Default::default(),
            limits: crate::scan::Limits::default(),
            route: crate::route::Options::default(),
            collection: crate::exchange::Collection::default(),
        };
        for (batches, expected) in [
            (0, Duration::ZERO),
            (1, request.timeout),
            (3, Duration::from_nanos(669_666_668)),
        ] {
            assert_eq!(
                worst_case_duration(&request, batches).expect("bounded duration"),
                expected
            );
        }

        request.probes_per_second = Some(0);
        assert_eq!(worst_case_duration(&request, 0).unwrap(), Duration::ZERO);
        assert_eq!(worst_case_duration(&request, 1).unwrap(), request.timeout);
        assert!(matches!(
            worst_case_duration(&request, 2),
            Err(Error::InvalidLimit {
                field: "probes_per_second",
                ..
            })
        ));

        request.timeout = Duration::MAX;
        for batches in [usize::MAX, 2] {
            assert!(matches!(
                worst_case_duration(&request, batches),
                Err(Error::DurationLimit {
                    actual: Duration::MAX,
                    ..
                })
            ));
        }
    }
}
