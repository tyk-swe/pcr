// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! What one DNS operation will do before any side effect: its finite
//! limits, approved up front, and each attempt's authorized [`Probe`].

use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use packetcraftr_core::error::{BoundaryError, Classification, Kind};
use packetcraftr_core::protocol::{
    application::dns::Dns,
    network::{Ipv4, Ipv6},
    transport::Udp,
};
use packetcraftr_core::{layer::Raw, packet::Packet};

use crate::correlation::nonzero_ipv4_identification;
use crate::execution::rate_delay;
use crate::policy::{DnsOperation, LimitOverflow, SocketLimits, WireLimits};

use super::engine::Attempts;
use super::error::Error;
use super::request::QueryType;
use super::{DEFAULT_SERVER_PORT, MAX_PROBE_OVERHEAD, Request, TransportMode};

/// The complete finite cost one DNS operation may incur, approved before any
/// resolver, route, capture, or socket side effect.
pub(super) struct OperationLimits {
    pub(super) packet_count: u64,
    pub(super) maximum_wire_bytes: u64,
    /// The socket cost of direct TCP or a possible continuation, or
    /// [`SocketLimits::none`] for UDP-only queries. DNS always
    /// states the shape, so the same overrun is charged and classified the
    /// same way whether or not fallback is enabled.
    pub(super) tcp: SocketLimits,
    /// Intentional delay between attempts at the requested rate.
    pub(super) delay: Duration,
}

/// Sum every question's worst-case UDP and TCP cost before any batch traffic.
pub(super) fn batch_limits(
    mut operations: impl Iterator<Item = DnsOperation>,
) -> Result<DnsOperation, Error> {
    operations.try_fold(
        DnsOperation::new(WireLimits::new(0, 0), SocketLimits::none())?,
        |total, operation| {
            let udp = total.udp();
            let tcp = total.tcp();
            Ok(DnsOperation::new(
                WireLimits::new(
                    udp.packets()
                        .checked_add(operation.udp().packets())
                        .ok_or(LimitOverflow)?,
                    udp.wire_bytes()
                        .checked_add(operation.udp().wire_bytes())
                        .ok_or(LimitOverflow)?,
                ),
                SocketLimits::new(
                    tcp.connections()
                        .checked_add(operation.tcp().connections())
                        .ok_or(LimitOverflow)?,
                    tcp.messages()
                        .checked_add(operation.tcp().messages())
                        .ok_or(LimitOverflow)?,
                    tcp.application_bytes()
                        .checked_add(operation.tcp().application_bytes())
                        .ok_or(LimitOverflow)?,
                ),
            )?)
        },
    )
}

pub(super) fn operation_limits(
    request: &Request,
    query_bytes: usize,
) -> Result<OperationLimits, Error> {
    let attempts = u64::from(request.attempts);
    let packet_count = if request.transport == TransportMode::Tcp {
        0
    } else {
        attempts
    };
    let query_bytes = u64::try_from(query_bytes).unwrap_or(u64::MAX);
    let udp_probe_bytes = query_bytes.saturating_add(MAX_PROBE_OVERHEAD);
    let maximum_wire_bytes =
        packet_count
            .checked_mul(udp_probe_bytes)
            .ok_or(Error::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            })?;
    let tcp = if request.transport != TransportMode::Udp {
        socket_limits(attempts, query_bytes)?
    } else {
        SocketLimits::none()
    };
    let delay = rate_delay(
        &Attempts,
        "queries_per_second",
        1,
        request.queries_per_second,
    )?;
    let worst_case = worst_case_duration(request, delay)?;
    if worst_case > request.limits.max_duration {
        return Err(Error::DurationLimit {
            actual: worst_case,
            limit: request.limits.max_duration,
        });
    }
    Ok(OperationLimits {
        packet_count,
        maximum_wire_bytes,
        tcp,
        delay,
    })
}

fn socket_limits(packet_count: u64, query_bytes: u64) -> Result<SocketLimits, Error> {
    let framed_query_bytes = query_bytes.checked_add(2).ok_or(Error::InvalidLimit {
        field: "socket_bytes",
        value: u64::MAX,
        reason: "DNS-over-TCP framing accounting overflowed".to_owned(),
    })?;
    let application_bytes =
        packet_count
            .checked_mul(framed_query_bytes)
            .ok_or(Error::InvalidLimit {
                field: "socket_bytes",
                value: u64::MAX,
                reason: "DNS-over-TCP byte accounting overflowed".to_owned(),
            })?;
    Ok(SocketLimits::new(
        packet_count,
        packet_count,
        application_bytes,
    ))
}

fn worst_case_duration(request: &Request, delay: Duration) -> Result<Duration, Error> {
    request
        .timeout
        .checked_mul(request.attempts)
        .and_then(|duration| {
            delay
                .checked_mul(request.attempts.saturating_sub(1))
                .and_then(|delays| duration.checked_add(delays))
        })
        .ok_or(Error::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })
}

/// One attempt's authorized query: the selected server, the rotated source
/// port, and the exact message bytes every transport carries.
/// [`classify_response`](super::classify_response) judges captured frames
/// against it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub attempt: u32,
    pub server_address: IpAddr,
    pub server_port: u16,
    pub source_port: u16,
    pub transaction_id: u16,
    pub query_name: String,
    pub query_type: QueryType,
    pub query: Bytes,
}

impl Probe {
    /// Builds the portable IPv4/IPv6 UDP query this already-authorized attempt
    /// transmits. Route-dependent fields remain unspecified for the client to
    /// materialize.
    #[must_use]
    pub fn packet(&self) -> Packet {
        let mut packet = Packet::new();
        match self.server_address {
            IpAddr::V4(destination) => {
                packet.push(Ipv4 {
                    destination,
                    identification: nonzero_ipv4_identification(u64::from(self.attempt)),
                    ..Ipv4::default()
                });
            }
            IpAddr::V6(destination) => {
                packet.push(Ipv6 {
                    destination,
                    flow_label: u32::from(self.transaction_id),
                    ..Ipv6::default()
                });
            }
        }
        packet.push(Udp {
            source_port: self.source_port,
            destination_port: self.server_port,
            ..Udp::default()
        });
        if self.server_port == DEFAULT_SERVER_PORT || self.source_port == DEFAULT_SERVER_PORT {
            if let Ok(dns) = Dns::try_from(self.query.clone()) {
                packet.push(dns);
            } else {
                packet.push(Raw::new(self.query.clone()));
            }
        } else {
            packet.push(Raw::new(self.query.clone()));
        }
        packet
    }
}

/// Rotates the query source port one step per retry, so a retried query is not
/// a second chance for an off-path spoofer to guess the same tuple.
pub(super) fn rotated_source_port(base: u16, attempt: u32) -> u16 {
    crate::correlation::ephemeral_source_port(base, u64::from(attempt.saturating_sub(1)))
}

/// Draws a DNS transaction ID from the system random source.
/// Entropy failures are returned before a query can be sent. Callers needing
/// reproducible experiments supply a fixed identity in `Request` instead.
pub fn unpredictable_transaction_id() -> Result<u16, BoundaryError> {
    random_u16(getrandom::fill)
}

/// Draws an ephemeral source port from the system random source.
/// Retries retain deterministic rotation from this random base; this is not
/// a claim of independent entropy on each retry.
pub fn unpredictable_source_port() -> Result<u16, BoundaryError> {
    random_u16(getrandom::fill).map(|value| {
        crate::correlation::ephemeral_source_port(
            crate::correlation::EPHEMERAL_SOURCE_PORT_BASE,
            u64::from(value),
        )
    })
}

fn random_u16(
    fill: impl FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
) -> Result<u16, BoundaryError> {
    let mut bytes = [0; 2];
    fill(&mut bytes).map_err(|source| {
        BoundaryError::with_source(
            "could not obtain system randomness for DNS identity",
            Classification::new("io.dns_entropy", Kind::Io, None),
            Vec::new(),
            source,
        )
    })?;
    Ok(u16::from_ne_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::error::Classified;

    #[test]
    fn entropy_failure_is_not_replaced_with_a_predictable_identity() {
        let error = random_u16(|_| Err(getrandom::Error::UNSUPPORTED)).unwrap_err();
        assert_eq!(error.classification().code, "io.dns_entropy");
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn deterministic_entropy_uses_the_exact_supplied_bytes() {
        assert_eq!(
            random_u16(|bytes| {
                bytes.copy_from_slice(&0x1234u16.to_ne_bytes());
                Ok(())
            })
            .unwrap(),
            0x1234
        );
    }

    #[test]
    fn retries_rotate_the_source_port_within_the_dynamic_range() {
        let base = crate::correlation::EPHEMERAL_SOURCE_PORT_BASE;
        assert_eq!(rotated_source_port(base, 1), base);
        assert_eq!(rotated_source_port(base, 2), base.saturating_add(1));
        assert!(rotated_source_port(base, u32::MAX) >= base);
    }
}
