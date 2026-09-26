// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use bytes::Bytes;
use packetcraftr_core::error::{BoundaryError, Classification, Kind};

use packetcraftr_core::protocol::{
    application::dns::Dns,
    network::{Ipv4, Ipv6},
    transport::Udp,
};
use packetcraftr_core::{layer::Raw, packet::Packet};

use crate::correlation::nonzero_ipv4_identification;

use super::DEFAULT_SERVER_PORT;
use super::request::QueryType;

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
