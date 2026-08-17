// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;

use packetcraftr_core::Packet;

use super::request::Strategy;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub sequence: u64,
    pub address: IpAddr,
    pub strategy: Strategy,
    pub destination_port: Option<u16>,
    pub hop_limit: u8,
    pub attempt: u32,
}

impl Probe {
    pub fn packet(&self) -> Packet {
        super::super::probe::probe_packet(self)
    }
}

pub type Batch = crate::probe::runner::Batch<Probe>;
pub use crate::probe::runner::Execution;

pub trait Executor {
    fn execute(&mut self, batch: &Batch) -> std::result::Result<Execution, crate::BoundaryError>;
}
