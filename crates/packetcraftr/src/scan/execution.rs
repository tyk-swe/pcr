// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;

use packetcraftr_core::packet::Packet;

pub use crate::probe::ProbeEndpoint;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    pub sequence: u64,
    pub address: IpAddr,
    pub endpoint: ProbeEndpoint,
    pub attempt: u32,
}

impl Probe {
    /// Builds the portable IPv4/IPv6 TCP, UDP, or ICMP probe represented by
    /// this already-authorized plan. Route-dependent fields remain unspecified
    /// for the high-level client to materialize.
    #[must_use]
    pub fn packet(&self) -> Packet {
        crate::scan::probe::probe_packet(self)
    }
}

impl crate::probe::runner::Sequenced for Probe {
    fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// One correlated scan probe and its admitted execution context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub probe: Probe,
    pub timeout: std::time::Duration,
    pub(crate) permit: crate::evidence::ExecutionPermit,
}

impl crate::probe::Request for Batch {
    type Execution = Execution;
}

impl crate::probe::runner::BatchPlan for Batch {
    fn sequence(&self) -> u64 {
        self.probe.sequence
    }
    fn probe_count(&self) -> usize {
        1
    }
    fn timeout_mut(&mut self) -> &mut std::time::Duration {
        &mut self.timeout
    }
}
pub use crate::probe::{Execution, Executor};
