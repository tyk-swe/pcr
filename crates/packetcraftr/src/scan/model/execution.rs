// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;

use packetcraftr_core::Packet;

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

pub type ScanBatch = crate::probe::runner::Batch<ScanProbe>;
pub use crate::exchange::Response as ScanMatchedResponse;
pub use crate::probe::runner::BatchExecution as ScanBatchExecution;

pub trait ScanExecutor {
    fn execute(
        &mut self,
        batch: &ScanBatch,
    ) -> std::result::Result<ScanBatchExecution, crate::BoundaryError>;
}
