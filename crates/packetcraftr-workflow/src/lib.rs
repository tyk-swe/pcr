// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Bounded packet workflows with explicit offline and live entry points.
//!
//! [`scan`], [`traceroute`], [`dns`], and [`replay`] are live domains: their
//! public entry points require authorization and finite operation budgets.
//! [`fuzz::run`] is deliberately offline, while [`fuzz::run_live`] makes its
//! resolver, authorization, and executor boundaries explicit. Private kernel
//! modules own only contracts that are genuinely shared across these domains,
//! such as clocks, target authorization, probe lifecycles, and exact evidence
//! accounting; packet generation, validation, and classification remain with
//! their domain.

pub mod dns;
pub mod fuzz;
mod kernel;
pub mod replay;
pub mod scan;
pub mod traceroute;

pub use kernel::address_family::AddressFamily;
pub use kernel::clock;
pub use kernel::target;
pub use packetcraftr_client::Stats;
pub use packetcraftr_core::error::BoundaryError;

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use bytes::Bytes;

    use super::dns::{Probe as DnsProbe, QueryType as DnsQueryType};
    use super::scan::{Probe as ScanProbe, Transport as ScanTransport};
    use super::traceroute::{Probe as TracerouteProbe, Strategy as TracerouteStrategy};

    fn identification(packet: &packetcraftr_packet::Packet) -> u64 {
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
