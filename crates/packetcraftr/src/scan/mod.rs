// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-gated scanning of authorized targets with finite packet, byte,
//! duration, and evidence budgets.

use std::time::Duration;

use crate::probe::Workflow;

pub const DEFAULT_BATCH_SIZE: usize = 64;
pub const DEFAULT_MAX_PORTS: usize = 1_024;
pub const DEFAULT_MAX_UNDECODED_FRAMES: usize = 64;
pub const MAX_ATTEMPTS: u32 = 32;
pub const MAX_PROBES: usize = 100_000;
pub const MAX_RATE: u32 = 1_000_000;
pub const MAX_DURATION: Duration = packetcraftr_netio::capture::MAX_TIMEOUT;

// Every generated scan probe is at most an Ethernet header plus IPv6 and TCP
// without options. The explicit bound lets the workflow authorize the complete
// multi-batch byte budget before the first route or send side effect.
const IPV4_PROBE_BYTES: u64 = 14 + 20 + 20;
const IPV6_PROBE_BYTES: u64 = 14 + 40 + 20;
const WORKFLOW: Workflow = Workflow::Scan;

mod classification;
mod engine;
mod executor;
mod model;
mod plan;
mod probe;
#[cfg(test)]
mod tests;

pub use crate::probe::Error;
pub use classification::{ResponseClassification, classify_response};
pub use engine::{run, run_with_events};
pub use model::{
    Batch, Classification, Endpoint, Event, Execution, Executor, Limits, PortSpec, Probe,
    ProbeEndpoint, ProbeEvidence, ProbeStatus, Report, Request, Summary, Transport, select_ports,
};
