// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;

use packetcraftr_core::packet::Packet;

use crate::probe::ProbeEndpoint;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    pub sequence: u64,
    pub address: IpAddr,
    pub target: ProbeEndpoint,
    pub hop_limit: u8,
    pub attempt: u32,
    pub source_port: u16,
}

impl Probe {
    /// Builds the portable IPv4/IPv6 UDP, TCP, or ICMP probe represented by
    /// this already-authorized hop plan.
    #[must_use]
    pub fn packet(&self) -> Packet {
        crate::traceroute::plan::packet::probe_packet(self)
    }
}

impl crate::probe::runner::Sequenced for Probe {
    fn sequence(&self) -> u64 {
        self.sequence
    }
}

pub type Batch = crate::probe::Batch<Probe>;
