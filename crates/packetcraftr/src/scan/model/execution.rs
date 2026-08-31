// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;

use packetcraftr_core::Packet;

use super::request::Transport;

/// The transport-specific destination one scan probe addresses.
///
/// Pairing each transport with exactly the addressing it needs makes a
/// portless TCP or UDP probe — and a ported ICMP probe — unrepresentable, so
/// [`Probe::packet`] never has to unwrap a port that a different module
/// validated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeEndpoint {
    Tcp { port: u16 },
    Udp { port: u16 },
    Icmp,
}

impl ProbeEndpoint {
    /// The transport this endpoint scans, as the request names it.
    #[must_use]
    pub const fn transport(self) -> Transport {
        match self {
            Self::Tcp { .. } => Transport::Tcp,
            Self::Udp { .. } => Transport::Udp,
            Self::Icmp => Transport::Icmp,
        }
    }

    /// The destination port, absent for the portless ICMP endpoint.
    #[must_use]
    pub const fn port(self) -> Option<u16> {
        match self {
            Self::Tcp { port } | Self::Udp { port } => Some(port),
            Self::Icmp => None,
        }
    }
}

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

pub type Batch = crate::probe::runner::Batch<Probe>;
pub use crate::probe::runner::{Execution, Executor};
