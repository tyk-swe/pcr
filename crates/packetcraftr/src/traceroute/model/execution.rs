// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;

use packetcraftr_core::Packet;

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

pub type TracerouteBatch = crate::probe::runner::Batch<TracerouteProbe>;
pub use crate::exchange::Response as TracerouteMatchedResponse;
pub use crate::probe::runner::BatchExecution as TracerouteBatchExecution;

pub trait TracerouteExecutor {
    fn execute(
        &mut self,
        batch: &TracerouteBatch,
    ) -> std::result::Result<TracerouteBatchExecution, crate::BoundaryError>;
}
