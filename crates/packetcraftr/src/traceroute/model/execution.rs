// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;

use packetcraftr_core::Packet;

pub use crate::probe::ProbeEndpoint as ProbeTarget;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    pub sequence: u64,
    pub address: IpAddr,
    pub target: ProbeTarget,
    pub hop_limit: u8,
    pub attempt: u32,
}

impl Probe {
    /// Builds the portable IPv4/IPv6 UDP, TCP, or ICMP probe represented by
    /// this already-authorized hop plan.
    #[must_use]
    pub fn packet(&self) -> Packet {
        crate::traceroute::probe::probe_packet(self)
    }
}

impl crate::probe::runner::Sequenced for Probe {
    fn sequence(&self) -> u64 {
        self.sequence
    }
}

pub type Batch = crate::probe::Batch<Probe>;
pub use crate::probe::{Execution, Executor};
