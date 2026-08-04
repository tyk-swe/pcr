// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_capture::Frame;
use packetcraftr_packet::{Packet, decode::DecodedPacket, diagnostic::Diagnostic};

use crate::Stats;

use super::request::TracerouteStrategy;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TracerouteProbe {
    pub sequence: u64,
    pub address: IpAddr,
    pub strategy: TracerouteStrategy,
    pub destination_port: Option<u16>,
    pub hop_limit: u8,
    pub attempt: u32,
}

impl TracerouteProbe {
    pub fn packet(&self) -> Packet {
        super::super::probe::probe_packet(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TracerouteBatch {
    pub probes: Vec<TracerouteProbe>,
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct TracerouteMatchedResponse {
    pub request_index: usize,
    pub response: DecodedPacket,
    pub latency: Duration,
}

#[derive(Clone, Debug)]
pub struct TracerouteBatchExecution {
    pub sent: Vec<Packet>,
    pub sent_evidence: Vec<Frame>,
    pub responses: Vec<TracerouteMatchedResponse>,
    pub unsolicited: Vec<DecodedPacket>,
    pub undecoded: Vec<Frame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

pub trait TracerouteExecutor {
    fn execute(
        &mut self,
        batch: &TracerouteBatch,
    ) -> std::result::Result<TracerouteBatchExecution, crate::BoundaryError>;
}
