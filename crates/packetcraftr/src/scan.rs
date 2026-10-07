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
// Allowance for one ARP request or NDP neighbor solicitation: Ethernet
// padding for ARP, a source link-address option for NDP, and the largest
// VLAN tag stack a route may add to either.
const VLAN_STACK_BYTES: u64 = 4 * crate::neighbor::MAX_VLAN_TAGS as u64;
const IPV4_NEIGHBOR_BYTES: u64 = 60 + VLAN_STACK_BYTES;
const IPV6_NEIGHBOR_BYTES: u64 = 14 + 40 + 32 + VLAN_STACK_BYTES;
const WORKFLOW: Workflow = Workflow::Scan;

pub mod catalog;
pub mod connect;
pub mod discovery;
mod engine;
mod error;
mod evidence;
mod executor;
mod inference;
pub mod method;
mod plan;
pub mod profile;
mod report;
mod request;
mod selection;
#[cfg(test)]
mod tests;

pub use error::{Error, PipelineFailure};
pub use evidence::{CorrelatedResponse, classify_response};
pub use inference::{Inference, Rule, State};
pub use plan::{Probe, Stage};
pub use report::{
    Aggregate, Attribution, Classification, ClassificationCounts, Collector, Endpoint, Event,
    PendingEvidence, ProbeEvidence, Reply, Report, Rtt, SentProbe, Unattributed,
};
pub use request::{Limits, PortSpec, Request, select_ports};
pub use selection::{MAX_PORT_TERMS, PortSelection, Selected, Selector, Term, select_endpoints};

/// A bundled data set a result drew on, named with its own version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataSet {
    pub name: &'static str,
    pub version: &'static str,
}
