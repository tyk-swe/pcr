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

/// One planned scan probe: an authorized address and endpoint, the attempt
/// it belongs to, and the exact UDP payload it carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub sequence: u64,
    pub address: IpAddr,
    pub endpoint: ProbeEndpoint,
    pub attempt: u32,
    /// Shared exact UDP payload from the validated request.
    pub udp_payload: bytes::Bytes,
    pub udp_profile: Option<std::sync::Arc<super::profile::UdpProfile>>,
}

impl Probe {
    /// Builds the portable IPv4/IPv6 TCP, UDP, or ICMP probe represented by
    /// this already-authorized plan. Route-dependent fields remain unspecified
    /// for the high-level client to materialize.
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

/// Scan executes exactly one correlated probe per batch.
impl Batch<Probe> {
    /// Plans the batch that executes `probe` alone.
    pub(super) fn single(probe: Probe, timeout: Duration) -> Self {
        Self {
            sequence: probe.sequence,
            probes: vec![probe],
            timeout,
            permit: crate::evidence::ExecutionPermit::new(),
        }
    }

    /// The batch's only probe. Scan plans every batch with exactly one, so
    /// only a batch reshaped outside the planner is rejected.
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

pub(super) fn build_batches<'a>(
    request: &'a Request,
    addresses: &'a [IpAddr],
    endpoints: &'a [ProbeEndpoint],
) -> Result<impl Iterator<Item = Batch<Probe>> + 'a, Error> {
    // Validate the complete sequence space before yielding any external effect.
    addresses
        .len()
        .checked_mul(request.attempts as usize)
        .and_then(|count| count.checked_mul(endpoints.len()))
        .and_then(|count| u64::try_from(count).ok())
        .ok_or(Error::InvalidLimit {
            field: "probes",
            value: u64::MAX,
            reason: "probe sequence overflowed".to_owned(),
        })?;
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
        .map(move |((address, attempt, endpoint), sequence)| {
            let profile = endpoint
                .port()
                .and_then(|port| request.udp_profiles.get(&port));
            Batch::single(
                Probe {
                    sequence,
                    address,
                    endpoint,
                    attempt,
                    udp_profile: profile.cloned(),
                    udp_payload: profile.map_or_else(
                        || request.udp_payload.clone(),
                        |profile| profile.payload(sequence),
                    ),
                },
                request.timeout,
            )
        }))
}

pub(super) fn worst_case_duration(
    request: &Request,
    address_count: usize,
    endpoints_per_address: usize,
) -> Result<Duration, Error> {
    let overflow = || Error::DurationLimit {
        actual: Duration::MAX,
        limit: request.limits.max_duration,
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
            route: crate::route::Options::default(),
            collection: crate::exchange::Collection::default(),
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
            Err(Error::InvalidLimit {
                field: "probes_per_second",
                ..
            })
        ));

        request.timeout = Duration::MAX;
        for (addresses, endpoints) in [(usize::MAX, 2), (1, 2)] {
            assert!(matches!(
                worst_case_duration(&request, addresses, endpoints),
                Err(Error::DurationLimit {
                    actual: Duration::MAX,
                    ..
                })
            ));
        }
    }
}
