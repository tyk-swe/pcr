// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_capture::Frame;
use packetcraftr_packet::{Packet, decode::DecodedPacket, diagnostic::Diagnostic};

use crate::Stats;

use super::request::ScanTransport;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanProbe {
    pub sequence: u64,
    pub address: IpAddr,
    pub transport: ScanTransport,
    pub port: Option<u16>,
    pub attempt: u32,
}

impl ScanProbe {
    /// Builds the portable IPv4/IPv6 TCP, UDP, or ICMP probe represented by
    /// this already-authorized plan. Route-dependent fields remain unspecified
    /// for the high-level client to materialize.
    pub fn packet(&self) -> Packet {
        super::super::probe::probe_packet(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanBatch {
    pub probes: Vec<ScanProbe>,
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct ScanMatchedResponse {
    pub request_index: usize,
    pub response: DecodedPacket,
    pub latency: Duration,
}

#[derive(Clone, Debug)]
pub struct ScanBatchExecution {
    pub sent: Vec<Packet>,
    pub sent_evidence: Vec<Frame>,
    pub responses: Vec<ScanMatchedResponse>,
    pub unsolicited: Vec<DecodedPacket>,
    pub undecoded: Vec<Frame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

pub trait ScanExecutor {
    fn execute(
        &mut self,
        batch: &ScanBatch,
    ) -> std::result::Result<ScanBatchExecution, crate::BoundaryError>;
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::super::request::ScanTransport;
    use super::ScanProbe;

    #[test]
    fn udp_retries_use_distinct_source_ports() {
        let mut probe = ScanProbe {
            sequence: 0,
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            transport: ScanTransport::Udp,
            port: Some(53),
            attempt: 1,
        };
        let first = probe
            .packet()
            .get::<packetcraftr_protocol::transport::Udp>()
            .unwrap()
            .source_port;
        probe.sequence = 1;
        probe.attempt = 2;
        let second = probe
            .packet()
            .get::<packetcraftr_protocol::transport::Udp>()
            .unwrap()
            .source_port;

        assert_ne!(first, second);
    }
}
