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
pub use report::{
    Aggregate, Classification, ClassificationCounts, Collector, Endpoint, Event, ProbeEvidence,
    Report, Rtt, SentProbe,
};
pub use request::{Limits, PortSpec, Request, select_ports};
