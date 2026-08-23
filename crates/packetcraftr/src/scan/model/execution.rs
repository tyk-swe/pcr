// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;

use packetcraftr_core::Packet;

use super::request::Transport;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub sequence: u64,
    pub address: IpAddr,
    pub transport: Transport,
    pub port: Option<u16>,
    pub attempt: u32,
}

impl Probe {
    /// Builds the portable IPv4/IPv6 TCP, UDP, or ICMP probe represented by
    /// this already-authorized plan. Route-dependent fields remain unspecified
    /// for the high-level client to materialize.
    pub fn packet(&self) -> Packet {
        super::super::probe::probe_packet(self)
    }
}

pub type Batch = crate::probe::engine::Batch<Probe>;
pub use crate::probe::engine::Execution;

pub trait Executor {
    fn execute(&mut self, batch: &Batch) -> std::result::Result<Execution, crate::BoundaryError>;
}
