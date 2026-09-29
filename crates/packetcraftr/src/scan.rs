// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::probe::Workflow;

pub const DEFAULT_ATTEMPTS: u32 = 1;
pub const DEFAULT_MAX_PORTS: usize = 1_024;
pub const DEFAULT_MAX_UNDECODED_FRAMES: usize = 64;
pub const MAX_ATTEMPTS: u32 = 32;
pub const MAX_IN_FLIGHT: usize = 1_024;
pub const MAX_PROBES: usize = 100_000;
pub(crate) const MAX_PREPARED_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_RATE: u32 = crate::execution::limits::MAX_RATE;
/// Maximum UDP payload accepted for either IP family, before final MTU checks.
pub const MAX_UDP_PAYLOAD_BYTES: usize =
    packetcraftr_core::document::udp_profiles::MAX_PAYLOAD_BYTES;

// Header allowance for every generated scan probe: Ethernet plus IP and TCP
// without options, with the IPv4 allowance including minimum Ethernet padding.
const IPV4_PROBE_BYTES: u64 = 60;
const IPV6_PROBE_BYTES: u64 = 14 + 40 + 20;
const WORKFLOW: Workflow = Workflow::Scan;

/// Raw TCP scan wire flags and silence interpretation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpMode {
    #[default]
    Syn,
    Ack,
    Fin,
    Null,
    Xmas,
}
impl TcpMode {
    pub const fn flags(self) -> u16 {
        use packetcraftr_core::protocol::transport::Tcp;
        match self {
            Self::Syn => Tcp::SYN,
            Self::Ack => Tcp::ACK,
            Self::Fin => Tcp::FIN,
            Self::Null => 0,
            Self::Xmas => Tcp::FIN | 0x08 | 0x20,
        }
    }
    pub const fn silence(self) -> Classification {
        match self {
            Self::Syn => Classification::Timeout,
            Self::Ack => Classification::Filtered,
            Self::Fin | Self::Null | Self::Xmas => Classification::OpenOrFiltered,
        }
    }
}

pub mod connect;
mod engine;
mod error;
mod evidence;
mod executor;
mod plan;
pub mod profile;
mod report;
mod request;
#[cfg(test)]
mod tests;

pub use error::Error;
pub use evidence::{CorrelatedResponse, classify_response};
pub use executor::{PendingEvidence, PipelineFailure};
pub use plan::Probe;
pub(crate) use report::RttAccumulator;
pub use report::{
    Aggregate, Classification, ClassificationCounts, Collector, Endpoint, Event, ProbeEvidence,
    Report, Rtt, SentProbe,
};
pub use request::{Limits, PortSpec, Request, select_ports};
