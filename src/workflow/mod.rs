// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Bounded, policy-gated network workflows.

mod address_family;
mod boundary_error;
mod bounded_probe;
pub mod clock;
mod deadline;
pub mod dns;
mod evidence;
pub mod fuzz;
mod probe;
pub mod replay;
pub mod scan;
pub mod target;
mod target_adapter;
pub mod traceroute;

/// Maps an operation-local sequence to an IPv4 identification that native
/// raw-socket adapters can preserve exactly. Zero is deliberately excluded.
const fn nonzero_ipv4_identification(sequence: u64) -> u16 {
    ((sequence % u16::MAX as u64) + 1) as u16
}

fn push_diagnostic_once(
    diagnostics: &mut Vec<crate::packet::diagnostic::Diagnostic>,
    diagnostic: crate::packet::diagnostic::Diagnostic,
) {
    if !diagnostics
        .iter()
        .any(|existing| existing.code == diagnostic.code)
    {
        diagnostics.push(diagnostic);
    }
}

pub use crate::client::Stats;
pub use address_family::AddressFamily;
pub use boundary_error::BoundaryError;

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use bytes::Bytes;

    use super::dns::{Probe as DnsProbe, QueryType as DnsQueryType};
    use super::scan::{Probe as ScanProbe, Transport as ScanTransport};
    use super::traceroute::{Probe as TracerouteProbe, Strategy as TracerouteStrategy};

    fn identification(packet: &crate::packet::Packet) -> u64 {
        packet
            .iter()
            .next()
            .and_then(|layer| layer.field("identification"))
            .and_then(|value| value.as_u64())
            .expect("generated IPv4 probe must expose an identification")
    }

    #[test]
    fn generated_live_ipv4_workflows_never_request_kernel_identification_rewrites() {
        let destination = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let scan = ScanProbe {
            sequence: 0,
            address: destination,
            transport: ScanTransport::Udp,
            port: Some(9),
            attempt: 0,
        };
        let traceroute = TracerouteProbe {
            sequence: u64::from(u16::MAX),
            address: destination,
            strategy: TracerouteStrategy::Udp,
            destination_port: Some(33_434),
            hop_limit: 1,
            attempt: 0,
        };
        let dns = DnsProbe {
            attempt: 0,
            server_address: destination,
            server_port: 53,
            source_port: 49_152,
            transaction_id: 1,
            query_name: "example.test".to_owned(),
            query_type: DnsQueryType::A,
            query: Bytes::new(),
        };

        assert_eq!(identification(&scan.packet()), 1);
        assert_eq!(identification(&traceroute.packet()), 1);
        assert_eq!(identification(&dns.packet()), 1);
    }
}
