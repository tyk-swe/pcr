// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated scanning of authorized targets with finite packet, byte,
//! duration, and evidence budgets.

use std::time::Duration;

use crate::probe::Workflow;

pub const DEFAULT_ATTEMPTS: u32 = 1;
pub const DEFAULT_MAX_PORTS: usize = 1_024;
pub const DEFAULT_MAX_UNDECODED_FRAMES: usize = 64;
pub const MAX_ATTEMPTS: u32 = 32;
pub const MAX_PROBES: usize = 100_000;
pub const MAX_RATE: u32 = 1_000_000;
pub const MAX_DURATION: Duration = packetcraftr_netio::capture::MAX_TIMEOUT;
/// Maximum UDP payload accepted for either IP family, before final MTU checks.
pub const MAX_UDP_PAYLOAD_BYTES: usize = 65_507;

// Header allowance for every generated scan probe: Ethernet plus IP and TCP
// without options, with the IPv4 allowance including minimum Ethernet padding.
// UDP payload bytes are added separately to authorize the complete
// multi-batch byte budget before the first route or send side effect.
const IPV4_PROBE_BYTES: u64 = 60;
const IPV6_PROBE_BYTES: u64 = 14 + 40 + 20;
const WORKFLOW: Workflow = Workflow::Scan;

mod classification;
pub mod connect;
mod engine;
mod execution;
mod executor;
mod pipeline;
mod plan;
pub use pipeline::{Error as PipelineError, PendingEvidence};
mod probe;
pub mod profile;
mod registry;
mod report;
mod request;
mod targets;
#[cfg(test)]
mod tests;

pub use crate::probe::Error;
pub use classification::{ResponseClassification, classify_response};
pub use engine::{run, run_with_events};
pub use execution::{Batch, Execution, Executor, Probe, ProbeEndpoint};
pub use report::{
    Classification, ClassificationCounts, Endpoint, Event, ProbeEvidence, ProbeStatus, Report,
    SentProbe, Summary,
};
pub use request::{Limits, PortSpec, Request, Transport, select_ports};
