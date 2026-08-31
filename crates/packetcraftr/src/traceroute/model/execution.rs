// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;

use packetcraftr_core::Packet;

use super::request::Strategy;

/// The transport-specific destination one traceroute probe addresses.
///
/// Pairing each strategy with exactly the addressing it needs makes a portless
/// UDP or TCP probe — and a ported ICMP probe — unrepresentable, so
/// [`Probe::packet`] never has to unwrap a port that a different module
/// validated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeTarget {
    Udp { port: u16 },
    Tcp { port: u16 },
    Icmp,
}

impl ProbeTarget {
    /// The strategy this target traces with, as the request names it.
    #[must_use]
    pub const fn strategy(self) -> Strategy {
        match self {
            Self::Udp { .. } => Strategy::Udp,
            Self::Tcp { .. } => Strategy::Tcp,
            Self::Icmp => Strategy::Icmp,
        }
    }

    /// The destination port, absent for the portless ICMP target.
    #[must_use]
    pub const fn port(self) -> Option<u16> {
        match self {
            Self::Udp { port } | Self::Tcp { port } => Some(port),
            Self::Icmp => None,
        }
    }
}

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

pub type Batch = crate::probe::runner::Batch<Probe>;
pub use crate::probe::runner::{Execution, Executor};
