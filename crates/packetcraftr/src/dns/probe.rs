// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact DNS probe construction and ephemeral source-port rotation.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::IpAddr;
use std::time::SystemTime;

use packetcraftr_core::protocol::{
    application::Dns,
    network::{Ipv4, Ipv6},
    transport::Udp,
};
use packetcraftr_core::{Packet, layer::Raw};

use crate::probe::nonzero_ipv4_identification;

use super::DEFAULT_SERVER_PORT;
use super::model::Probe;

pub(super) fn probe_packet(probe: &Probe) -> Packet {
    let mut packet = Packet::new();
    match probe.server_address {
        IpAddr::V4(destination) => {
            packet.push(Ipv4 {
                destination,
                identification: nonzero_ipv4_identification(u64::from(probe.attempt)),
                ..Ipv4::default()
            });
        }
        IpAddr::V6(destination) => {
            packet.push(Ipv6 {
                destination,
                flow_label: u32::from(probe.transaction_id),
                ..Ipv6::default()
            });
        }
    }
    packet.push(Udp {
        source_port: probe.source_port,
        destination_port: probe.server_port,
        ..Udp::default()
    });
    if probe.server_port == DEFAULT_SERVER_PORT || probe.source_port == DEFAULT_SERVER_PORT {
        if let Ok(dns) = Dns::from_wire(probe.query.clone()) {
            packet.push(dns);
        } else {
            packet.push(Raw::new(probe.query.clone()));
        }
    } else {
        packet.push(Raw::new(probe.query.clone()));
    }
    packet
}

/// Rotates the query source port one step per retry, so a retried query is not
/// a second chance for an off-path spoofer to guess the same tuple.
pub(super) fn rotated_source_port(base: u16, attempt: u32) -> u16 {
    crate::probe::ephemeral_source_port(base, u64::from(attempt.saturating_sub(1)))
}

/// An unpredictable DNS transaction ID for a new query.
///
/// Query-ID unpredictability is spoofing resistance, not cosmetics: an
/// off-path attacker who can guess the ID (and the source port below) can
/// forge an answer that passes the same transaction and question checks a
/// genuine response passes. Callers that need a fixed ID for reproducibility
/// pass one explicitly instead.
///
/// This is a per-call mix of OS-seeded hasher state, the wall clock, and the
/// process ID. It is deliberately not a cryptographic generator, and nothing
/// in this crate treats it as one.
#[must_use]
pub fn unpredictable_transaction_id() -> u16 {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the transaction ID is the low 16 bits of the mixed entropy; every bit of the \
                  64-bit value is equally unpredictable, so the narrowing loses no unpredictability"
    )]
    {
        entropy() as u16
    }
}

/// An unpredictable ephemeral source port for a new query, inside the IANA
/// dynamic range.
///
/// Source-port unpredictability multiplies with
/// [`unpredictable_transaction_id`] to widen the space an off-path spoofer has
/// to guess. Retries rotate one step from this base rather than re-drawing, so
/// the whole operation stays inside one predictable-to-the-caller range.
#[must_use]
pub fn unpredictable_source_port() -> u16 {
    crate::probe::ephemeral_source_port(crate::EPHEMERAL_SOURCE_PORT_BASE, entropy())
}

fn entropy() -> u64 {
    let time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u128(time);
    hasher.write_u32(std::process::id());
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both values must vary between queries and the port must stay inside
    /// the dynamic range the retry rotation assumes.
    #[test]
    fn unpredictable_query_identity_varies_and_stays_in_the_dynamic_range() {
        let ports: Vec<u16> = (0..64).map(|_| unpredictable_source_port()).collect();
        assert!(
            ports
                .iter()
                .all(|port| *port >= crate::EPHEMERAL_SOURCE_PORT_BASE)
        );
        assert!(
            ports.iter().any(|port| Some(port) != ports.first()),
            "64 draws that all agree would mean the source port is fixed"
        );

        let ids: Vec<u16> = (0..64).map(|_| unpredictable_transaction_id()).collect();
        assert!(
            ids.iter().any(|id| Some(id) != ids.first()),
            "64 draws that all agree would mean the transaction ID is fixed"
        );
    }

    /// Retries walk one step at a time and never leave the dynamic range.
    #[test]
    fn retries_rotate_the_source_port_within_the_dynamic_range() {
        let base = crate::EPHEMERAL_SOURCE_PORT_BASE;
        assert_eq!(rotated_source_port(base, 1), base);
        assert_eq!(rotated_source_port(base, 2), base.saturating_add(1));
        assert!(rotated_source_port(base, u32::MAX) >= base);
    }
}
