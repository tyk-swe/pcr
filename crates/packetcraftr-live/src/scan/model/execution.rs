// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_packet::frame::Frame;
use packetcraftr_packet::{Packet, decode::Result as DecodedPacket, diagnostic::Diagnostic};

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
    pub(crate) permit: crate::evidence::ExecutionPermit,
}

#[derive(Clone, Debug)]
pub struct ScanMatchedResponse {
    pub request_index: usize,
    pub response: DecodedPacket,
    pub latency: Duration,
}

#[derive(Clone, Debug)]
pub struct ScanBatchExecution {
    pub(crate) permit: crate::evidence::ExecutionPermit,
    pub(crate) sent: Vec<crate::SentPacket>,
    pub(crate) responses: Vec<ScanMatchedResponse>,
    pub(crate) unsolicited: Vec<DecodedPacket>,
    pub(crate) undecoded: Vec<Frame>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) stats: Stats,
}

pub trait ScanExecutor {
    fn execute(
        &mut self,
        batch: &ScanBatch,
    ) -> std::result::Result<ScanBatchExecution, crate::BoundaryError>;
}
